"""
REK Notification System
Sends scan alerts and finding notifications to Slack or Discord webhooks.
Supports: Slack Incoming Webhooks, Discord Webhooks, file-based config.
"""
import json
import os
import requests
import time
from typing import Dict, List, Optional, Any
from termcolor import colored
import logging

logger = logging.getLogger(__name__)

CONFIG_FILE = os.path.expanduser('~/.rek_notify_config.json')

SEVERITY_COLORS = {
    'critical': '#FF0000',
    'high': '#FF6600',
    'medium': '#FFA500',
    'low': '#FFFF00',
    'info': '#00FF00',
}

DISCORD_SEVERITY_COLORS = {
    'critical': 16711680,   # Red
    'high': 16744192,       # Orange
    'medium': 16776960,     # Yellow
    'low': 65535,           # Cyan
    'info': 65280,          # Green
}


class NotificationManager:
    def __init__(self, slack_webhook: str = None, discord_webhook: str = None, silent: bool = False):
        self.silent = silent
        config = self.load_config()
        self.slack_webhook = slack_webhook or config.get('slack_webhook', '')
        self.discord_webhook = discord_webhook or config.get('discord_webhook', '')

    def load_config(self) -> Dict:
        """Load saved notification config."""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE) as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def save_config(self, slack_webhook: str = None, discord_webhook: str = None):
        """Save notification config."""
        config = self.load_config()
        if slack_webhook:
            config['slack_webhook'] = slack_webhook
        if discord_webhook:
            config['discord_webhook'] = discord_webhook
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            os.chmod(CONFIG_FILE, 0o600)
            if not self.silent:
                print(colored(f"[✓] Notification config saved to {CONFIG_FILE}", "green"))
        except Exception as e:
            print(colored(f"[!] Error saving notify config: {e}", "red"))

    def send_slack(self, message: str, title: str = None, severity: str = 'info', fields: List[Dict] = None) -> bool:
        """Send a notification to Slack."""
        if not self.slack_webhook:
            return False

        color = SEVERITY_COLORS.get(severity.lower(), '#00FF00')

        payload = {
            'attachments': [{
                'color': color,
                'title': title or 'REK Notification',
                'text': message,
                'footer': 'REK Reconnaissance Toolkit',
                'ts': int(time.time()),
            }]
        }

        if fields:
            payload['attachments'][0]['fields'] = [
                {'title': f['name'], 'value': f['value'], 'short': f.get('short', True)}
                for f in fields
            ]

        try:
            r = requests.post(self.slack_webhook, json=payload, timeout=10)
            if r.status_code == 200:
                if not self.silent:
                    print(colored(f"[✓] Slack notification sent", "green"))
                return True
            else:
                if not self.silent:
                    print(colored(f"[!] Slack notification failed: HTTP {r.status_code}", "yellow"))
        except Exception as e:
            if not self.silent:
                print(colored(f"[!] Slack notification error: {e}", "red"))
        return False

    def send_discord(self, message: str, title: str = None, severity: str = 'info', fields: List[Dict] = None) -> bool:
        """Send a notification to Discord."""
        if not self.discord_webhook:
            return False

        color = DISCORD_SEVERITY_COLORS.get(severity.lower(), 65280)

        embed = {
            'title': title or 'REK Notification',
            'description': message,
            'color': color,
            'footer': {'text': 'REK Reconnaissance Toolkit'},
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        }

        if fields:
            embed['fields'] = [
                {'name': f['name'], 'value': str(f['value'])[:1024], 'inline': f.get('short', True)}
                for f in fields
            ]

        payload = {'embeds': [embed]}

        try:
            r = requests.post(self.discord_webhook, json=payload, timeout=10)
            if r.status_code in [200, 204]:
                if not self.silent:
                    print(colored(f"[✓] Discord notification sent", "green"))
                return True
            else:
                if not self.silent:
                    print(colored(f"[!] Discord notification failed: HTTP {r.status_code}", "yellow"))
        except Exception as e:
            if not self.silent:
                print(colored(f"[!] Discord notification error: {e}", "red"))
        return False

    def notify(self, message: str, title: str = None, severity: str = 'info', fields: List[Dict] = None) -> bool:
        """Send notification to all configured channels."""
        sent = False
        if self.slack_webhook:
            sent |= self.send_slack(message, title, severity, fields)
        if self.discord_webhook:
            sent |= self.send_discord(message, title, severity, fields)
        if not sent and not self.silent:
            print(colored("[!] No notification channels configured. Use --slack-webhook or --discord-webhook", "yellow"))
        return sent

    def notify_scan_start(self, domain: str, scan_type: str = 'Full Recon'):
        """Notify that a scan has started."""
        self.notify(
            message=f"Starting {scan_type} on `{domain}`",
            title=f"REK Scan Started: {domain}",
            severity='info',
            fields=[
                {'name': 'Target', 'value': domain},
                {'name': 'Scan Type', 'value': scan_type},
                {'name': 'Time', 'value': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())},
            ]
        )

    def notify_scan_complete(self, domain: str, stats: Dict):
        """Notify that a scan has completed with summary stats."""
        fields = [
            {'name': 'Target', 'value': domain},
            {'name': 'Subdomains', 'value': str(stats.get('subdomains', 0))},
            {'name': 'Live Hosts', 'value': str(stats.get('live_hosts', 0))},
            {'name': 'Endpoints', 'value': str(stats.get('endpoints', 0))},
            {'name': 'Vulnerabilities', 'value': str(stats.get('vulnerabilities', 0))},
            {'name': 'Duration', 'value': stats.get('duration', 'N/A')},
        ]
        severity = 'high' if stats.get('vulnerabilities', 0) > 0 else 'info'
        self.notify(
            message=f"Recon completed for `{domain}`. Found {stats.get('vulnerabilities', 0)} potential vulnerabilities.",
            title=f"REK Scan Complete: {domain}",
            severity=severity,
            fields=fields
        )

    def notify_finding(self, finding_type: str, target: str, details: str, severity: str = 'high'):
        """Notify about a critical finding."""
        self.notify(
            message=f"**{finding_type}** found on `{target}`\n\n{details}",
            title=f"[{severity.upper()}] REK Finding: {finding_type}",
            severity=severity,
            fields=[
                {'name': 'Finding Type', 'value': finding_type},
                {'name': 'Target', 'value': target},
                {'name': 'Details', 'value': details[:500]},
                {'name': 'Severity', 'value': severity.upper()},
            ]
        )

    def notify_new_subdomain(self, domain: str, new_subs: List[str]):
        """Notify about newly discovered subdomains (for monitoring mode)."""
        if not new_subs:
            return
        sub_list = '\n'.join(new_subs[:20])
        if len(new_subs) > 20:
            sub_list += f'\n... and {len(new_subs) - 20} more'
        self.notify(
            message=f"**{len(new_subs)} new subdomains** discovered for `{domain}`:\n```\n{sub_list}\n```",
            title=f"New Subdomains: {domain}",
            severity='medium',
            fields=[
                {'name': 'Domain', 'value': domain},
                {'name': 'New Count', 'value': str(len(new_subs))},
                {'name': 'Time', 'value': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())},
            ]
        )

    def notify_takeover(self, subdomain: str, cname: str, service: str):
        """Notify about a subdomain takeover finding."""
        self.notify(
            message=f"**SUBDOMAIN TAKEOVER DETECTED!**\n`{subdomain}` → `{cname}` ({service})",
            title=f"[CRITICAL] Subdomain Takeover: {subdomain}",
            severity='critical',
            fields=[
                {'name': 'Subdomain', 'value': subdomain},
                {'name': 'CNAME', 'value': cname},
                {'name': 'Service', 'value': service},
                {'name': 'Severity', 'value': 'CRITICAL - Immediate action required'},
            ]
        )

    def test_webhooks(self):
        """Test all configured webhooks."""
        print(colored("[*] Testing notification webhooks...", "yellow"))
        sent = self.notify(
            message="This is a test notification from REK.",
            title="REK Webhook Test",
            severity='info',
            fields=[{'name': 'Status', 'value': 'Test successful'}]
        )
        return sent

    def configure_interactive(self):
        """Interactive webhook configuration."""
        print(colored("\n[*] Notification Configuration", "cyan"))
        print(colored("Current config:", "yellow"))
        print(f"  Slack:   {self.slack_webhook or '(not set)'}")
        print(f"  Discord: {self.discord_webhook or '(not set)'}")

        slack = input(colored("Slack webhook URL (press Enter to keep current): ", "yellow")).strip()
        discord = input(colored("Discord webhook URL (press Enter to keep current): ", "yellow")).strip()

        if slack:
            self.slack_webhook = slack
        if discord:
            self.discord_webhook = discord

        if slack or discord:
            self.save_config(
                slack_webhook=self.slack_webhook if slack else None,
                discord_webhook=self.discord_webhook if discord else None,
            )

        test = input(colored("Test webhooks now? (y/n): ", "yellow")).strip().lower()
        if test == 'y':
            self.test_webhooks()


if __name__ == '__main__':
    mgr = NotificationManager()
    mgr.configure_interactive()
