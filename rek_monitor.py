"""
REK Continuous Monitoring
Runs subdomain enumeration on a schedule, diffs results against previous runs,
and alerts on new assets via configured notification channels.
"""
import asyncio
import json
import os
import time
import subprocess
import signal
import sys
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from termcolor import colored
import logging
import threading

logger = logging.getLogger(__name__)

MONITOR_STATE_DIR = os.path.expanduser('~/.rek_monitor')
MONITOR_PID_FILE = os.path.join(MONITOR_STATE_DIR, 'monitor.pid')
MONITOR_LOG_FILE = os.path.join(MONITOR_STATE_DIR, 'monitor.log')


class MonitorState:
    def __init__(self, domain: str):
        self.domain = domain
        self.state_file = os.path.join(MONITOR_STATE_DIR, f"{domain.replace('.', '_')}_state.json")
        os.makedirs(MONITOR_STATE_DIR, exist_ok=True)
        self.state = self.load()

    def load(self) -> Dict:
        """Load monitoring state from disk."""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file) as f:
                    return json.load(f)
        except Exception:
            pass
        return {
            'domain': self.domain,
            'subdomains': [],
            'last_run': None,
            'run_count': 0,
            'findings_history': [],
        }

    def save(self):
        """Save monitoring state to disk."""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving monitor state: {e}")

    def get_known_subdomains(self) -> Set[str]:
        return set(self.state.get('subdomains', []))

    def update_subdomains(self, new_list: List[str]):
        """Update known subdomain list and return newly discovered ones."""
        known = self.get_known_subdomains()
        new_set = set(new_list)
        new_subs = list(new_set - known)
        removed_subs = list(known - new_set)

        self.state['subdomains'] = list(new_set)
        self.state['last_run'] = datetime.utcnow().isoformat()
        self.state['run_count'] = self.state.get('run_count', 0) + 1

        if new_subs or removed_subs:
            self.state.setdefault('findings_history', []).append({
                'timestamp': datetime.utcnow().isoformat(),
                'new_subdomains': new_subs,
                'removed_subdomains': removed_subs,
            })

        self.save()
        return new_subs, removed_subs


def enumerate_subdomains_quick(domain: str, tools_dir: str = None) -> List[str]:
    """Run quick subdomain enumeration using available tools."""
    subdomains = set()
    path_env = os.environ.copy()
    if tools_dir:
        path_env['PATH'] = f"{tools_dir}:{os.path.expanduser('~/go/bin')}:{path_env.get('PATH', '')}"

    # Try subfinder first
    try:
        result = subprocess.run(
            ['subfinder', '-d', domain, '-silent', '-all'],
            capture_output=True, text=True, timeout=120, env=path_env
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and domain in line:
                    subdomains.add(line)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    # Try assetfinder
    try:
        result = subprocess.run(
            ['assetfinder', '--subs-only', domain],
            capture_output=True, text=True, timeout=60, env=path_env
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and domain in line:
                    subdomains.add(line)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    # Fallback: Python-based enumeration (crt.sh)
    if not subdomains:
        try:
            import httpx
            r = httpx.get(f"https://crt.sh/?q={domain}&output=json", timeout=30)
            if r.status_code == 200:
                for entry in r.json():
                    name = entry.get('name_value', '')
                    for line in name.split('\n'):
                        line = line.strip().lstrip('*.')
                        if line and domain in line:
                            subdomains.add(line)
        except Exception:
            pass

    return list(subdomains)


class ContinuousMonitor:
    def __init__(
        self,
        interval_minutes: int = 60,
        slack_webhook: str = None,
        discord_webhook: str = None,
        tools_dir: str = None,
        silent: bool = False,
    ):
        self.interval_minutes = interval_minutes
        self.tools_dir = tools_dir
        self.silent = silent
        self._stop_event = threading.Event()

        # Import notification module
        try:
            from rek_notify import NotificationManager
            self.notifier = NotificationManager(
                slack_webhook=slack_webhook,
                discord_webhook=discord_webhook,
                silent=silent,
            )
        except ImportError:
            self.notifier = None

    def log(self, message: str, level: str = 'info'):
        """Log to both console and log file."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"

        colors = {'info': 'cyan', 'success': 'green', 'warning': 'yellow', 'error': 'red', 'finding': 'red'}
        if not self.silent:
            print(colored(log_entry, colors.get(level, 'white')))

        try:
            os.makedirs(MONITOR_STATE_DIR, exist_ok=True)
            with open(MONITOR_LOG_FILE, 'a') as f:
                f.write(log_entry + '\n')
        except Exception:
            pass

    def run_check(self, domain: str) -> Dict:
        """Run a single monitoring check for a domain."""
        self.log(f"[*] Running check for {domain}...", 'info')

        state = MonitorState(domain)
        results = {'domain': domain, 'new_subdomains': [], 'removed_subdomains': [], 'status': 'ok'}

        try:
            # Enumerate subdomains
            current_subs = enumerate_subdomains_quick(domain, self.tools_dir)
            self.log(f"[*] Found {len(current_subs)} subdomains for {domain}", 'info')

            # Diff against last known state
            new_subs, removed_subs = state.update_subdomains(current_subs)
            results['new_subdomains'] = new_subs
            results['removed_subdomains'] = removed_subs

            if new_subs:
                self.log(f"[!] {len(new_subs)} NEW subdomains found for {domain}!", 'finding')
                for sub in new_subs[:10]:
                    self.log(f"    NEW: {sub}", 'finding')

                # Send notification
                if self.notifier:
                    self.notifier.notify_new_subdomain(domain, new_subs)

                # Quick takeover check on new subdomains
                try:
                    from rek_takeover import TakeoverDetector
                    detector = TakeoverDetector(timeout=10, silent=True)
                    takeover_findings = detector.run(subdomains=new_subs)
                    for finding in takeover_findings:
                        if finding.get('status') == 'VULNERABLE' and self.notifier:
                            self.notifier.notify_takeover(
                                finding['subdomain'],
                                finding['cname'],
                                finding['service']
                            )
                            self.log(f"[!!!] TAKEOVER: {finding['subdomain']} -> {finding['cname']}", 'finding')
                except ImportError:
                    pass

            if removed_subs:
                self.log(f"[*] {len(removed_subs)} subdomains removed/offline for {domain}", 'warning')

            if not new_subs and not removed_subs:
                self.log(f"[✓] No changes for {domain} (known: {len(current_subs)} subdomains)", 'success')

        except Exception as e:
            self.log(f"[!] Error checking {domain}: {e}", 'error')
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def start(self, domains: List[str], daemon: bool = False):
        """Start continuous monitoring for a list of domains."""
        if not self.silent:
            print(colored(f"\n[+] Starting REK Monitor for {len(domains)} domain(s)", "blue"))
            print(colored(f"    Interval: {self.interval_minutes} minutes", "cyan"))
            print(colored(f"    Domains: {', '.join(domains)}", "cyan"))
            print(colored(f"    Log: {MONITOR_LOG_FILE}", "cyan"))
            print(colored("    Press Ctrl+C to stop\n", "yellow"))

        if daemon:
            self._start_daemon(domains)
        else:
            self._run_loop(domains)

    def _run_loop(self, domains: List[str]):
        """Run monitoring loop in foreground."""
        run_count = 0
        try:
            while not self._stop_event.is_set():
                run_count += 1
                self.log(f"=== Monitor Run #{run_count} ===", 'info')

                for domain in domains:
                    self.run_check(domain)

                next_run = datetime.utcnow() + timedelta(minutes=self.interval_minutes)
                self.log(f"[*] Next check at {next_run.strftime('%Y-%m-%d %H:%M:%S')} UTC", 'info')

                # Sleep in small increments to allow Ctrl+C
                sleep_seconds = self.interval_minutes * 60
                for _ in range(sleep_seconds):
                    if self._stop_event.is_set():
                        break
                    time.sleep(1)

        except KeyboardInterrupt:
            self.log("\n[*] Monitor stopped by user", 'warning')

    def _start_daemon(self, domains: List[str]):
        """Start monitoring as a background daemon."""
        import multiprocessing

        def daemon_worker():
            self._run_loop(domains)

        proc = multiprocessing.Process(target=daemon_worker, daemon=True)
        proc.start()

        # Save PID
        os.makedirs(MONITOR_STATE_DIR, exist_ok=True)
        with open(MONITOR_PID_FILE, 'w') as f:
            json.dump({'pid': proc.pid, 'domains': domains, 'started': datetime.utcnow().isoformat()}, f)

        print(colored(f"[✓] Monitor daemon started (PID: {proc.pid})", "green"))
        print(colored(f"    PID file: {MONITOR_PID_FILE}", "cyan"))
        print(colored(f"    Log: {MONITOR_LOG_FILE}", "cyan"))
        return proc

    def stop_daemon(self):
        """Stop a running monitor daemon."""
        try:
            if os.path.exists(MONITOR_PID_FILE):
                with open(MONITOR_PID_FILE) as f:
                    data = json.load(f)
                pid = data.get('pid')
                if pid:
                    os.kill(pid, signal.SIGTERM)
                    os.remove(MONITOR_PID_FILE)
                    print(colored(f"[✓] Monitor daemon stopped (PID: {pid})", "green"))
                    return True
        except Exception as e:
            print(colored(f"[!] Error stopping daemon: {e}", "red"))
        return False

    def get_status(self) -> Dict:
        """Get current monitoring status."""
        status = {'running': False, 'domains': [], 'pid': None}

        if os.path.exists(MONITOR_PID_FILE):
            try:
                with open(MONITOR_PID_FILE) as f:
                    data = json.load(f)
                pid = data.get('pid')
                # Check if process is actually running
                try:
                    os.kill(pid, 0)
                    status['running'] = True
                    status['pid'] = pid
                    status['domains'] = data.get('domains', [])
                    status['started'] = data.get('started', '')
                except OSError:
                    os.remove(MONITOR_PID_FILE)
            except Exception:
                pass

        # Get state files
        state_info = []
        for f in os.listdir(MONITOR_STATE_DIR) if os.path.exists(MONITOR_STATE_DIR) else []:
            if f.endswith('_state.json'):
                try:
                    with open(os.path.join(MONITOR_STATE_DIR, f)) as sf:
                        state = json.load(sf)
                        state_info.append({
                            'domain': state.get('domain', ''),
                            'last_run': state.get('last_run', 'Never'),
                            'run_count': state.get('run_count', 0),
                            'subdomain_count': len(state.get('subdomains', [])),
                        })
                except Exception:
                    pass
        status['states'] = state_info
        return status


if __name__ == '__main__':
    import sys
    domains = sys.argv[1:] or ['example.com']
    monitor = ContinuousMonitor(interval_minutes=30)
    monitor.start(domains)
