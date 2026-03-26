# ╔═════════════════════════════════════════════════════════════╗
# ║  Streamlined Recon Playbook for Efficient Crawling (v2)     ║
# ║  Focused crawling pipeline using Katana, HTTPX, and Nuclei  ║
# ╚═════════════════════════════════════════════════════════════╝
# Python Cross-Platform Edition by jackb898

import os
import sys
import shutil
import subprocess
import argparse
import time
import random
import urllib.parse
from pathlib import Path
from datetime import datetime

try:
    from termcolor import colored
    import colorama
    colorama.init()
except ImportError:
    def colored(text, *args, **kwargs):
        return text

# ─────────────────────────────────────────────
# Global state
# ─────────────────────────────────────────────
WORKING_DIR = Path(os.environ.get("RECON_TOOLKIT_DIR", Path(__file__).parent))
TOOLS_DIR   = Path(os.environ.get("TOOLS_DIR",         WORKING_DIR / "tools"))
CONFIG_FILE = Path(os.environ.get("CONFIG_PATH",       WORKING_DIR / "config.conf"))

TARGET_URL   = ""
TARGET_DOMAIN = ""
OUTPUT_DIR   = ""
RESULTS_DIR  = Path()
THREADS      = 20
RATE_LIMIT   = 25

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
]


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def command_exists(name: str) -> bool:
    if shutil.which(name):
        return True
    for candidate in [TOOLS_DIR / name, TOOLS_DIR / f"{name}.exe"]:
        if candidate.exists():
            return True
    return False


def run(cmd, cwd=None, check=False):
    """Run a command with tools on PATH. Raises on non-zero if check=True."""
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([
        str(TOOLS_DIR),
        str(Path.home() / "go" / "bin"),
        env.get("PATH", "")
    ])
    result = subprocess.run(cmd, cwd=cwd, env=env)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result


def read_lines(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def count_lines(path) -> int:
    return len(read_lines(path))


# ─────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────
def setup_directories():
    global RESULTS_DIR, TARGET_DOMAIN

    print(colored("[+] Setting up directories...", "blue"))

    WORKING_DIR.mkdir(parents=True, exist_ok=True)
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    parsed = urllib.parse.urlparse(TARGET_URL)
    TARGET_DOMAIN = parsed.netloc or TARGET_URL

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    RESULTS_DIR = WORKING_DIR / "results" / f"{TARGET_DOMAIN}-{timestamp}"

    for subdir in ["urls", "probed", "vulnerabilities"]:
        (RESULTS_DIR / subdir).mkdir(parents=True, exist_ok=True)

    print(colored("[+] Directories set up successfully", "green"))
    print(colored(f"[+] Results will be saved to: {RESULTS_DIR}", "green"))


# ─────────────────────────────────────────────
# Prerequisites
# ─────────────────────────────────────────────
def check_prerequisites():
    print(colored("[+] Checking prerequisites...", "blue"))

    tools = ["katana", "httpx", "nuclei"]

    print(f"{'Tool':<20}{'Status'}")
    print(f"{'--------------------':<20}{'----------'}")

    all_ok = True
    for tool in tools:
        if command_exists(tool):
            print(f"{tool:<20}" + colored("Installed", "green"))
        else:
            print(f"{tool:<20}" + colored("Missing", "red"))
            all_ok = False

    if not all_ok:
        print(colored("\n[!] Some prerequisites are missing. Please run install-script-v2.py", "yellow"))
        sys.exit(1)
    else:
        print(colored("\n[+] All prerequisites are installed", "green"))


# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
def load_config():
    global THREADS, RATE_LIMIT

    if CONFIG_FILE.exists():
        print(colored("[+] Loading configuration...", "blue"))
        for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if '=' not in line:
                continue
            key, _, val = line.partition('=')
            val = val.strip().strip('"')
            if key == "THREADS":
                try: THREADS = int(val)
                except ValueError: pass
            elif key == "RATE_LIMIT":
                try: RATE_LIMIT = int(val)
                except ValueError: pass
        print(colored("[+] Configuration loaded", "green"))
    else:
        print(colored("[!] Configuration file not found. Creating new one...", "yellow"))

        t = input(colored("[?] Default number of threads (default: 20): ", "yellow")).strip()
        if t:
            try: THREADS = int(t)
            except ValueError: pass

        r = input(colored("[?] Default rate limit per second (default: 25): ", "yellow")).strip()
        if r:
            try: RATE_LIMIT = int(r)
            except ValueError: pass

        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(f'THREADS="{THREADS}"\n')
            f.write(f'RATE_LIMIT="{RATE_LIMIT}"\n')

        print(colored("[+] Configuration saved", "green"))


# ─────────────────────────────────────────────
# Target input
# ─────────────────────────────────────────────
def get_target_url():
    global TARGET_URL
    TARGET_URL = input(colored("[?] Enter the target URL (e.g., https://example.com): ", "yellow")).strip()
    if not TARGET_URL:
        print(colored("[!] No URL provided. Exiting.", "red"))
        sys.exit(1)
    print(colored(f"[+] Target URL set to: {TARGET_URL}", "green"))


# ─────────────────────────────────────────────
# Recon pipeline
# ─────────────────────────────────────────────
def recon_pipeline():
    print(colored("\n[+] Starting Recon Pipeline: Katana -> HTTPX -> Nuclei", "blue"))

    user_agent = random.choice(USER_AGENTS)

    # ── Katana ──
    print(colored("[*] Running Katana for URL discovery...", "yellow"))
    katana_out = RESULTS_DIR / "urls" / "katana-output.txt"

    result = run([
        "katana",
        "-u", TARGET_URL,
        "-hl", "-jc", "--no-sandbox",
        "-c", "1", "-p", "1", "-rd", "3", "-rl", "5",
        "-H", f"User-Agent: {user_agent}",
        "-o", str(katana_out)
    ])
    if result.returncode != 0:
        print(colored("[!] Katana failed", "red"))
        sys.exit(1)

    total_urls = count_lines(katana_out)
    print(colored(f"[+] Katana completed. Found {total_urls} URLs", "green"))

    # ── HTTPX ──
    print(colored("[*] Running HTTPX for validation and enrichment...", "yellow"))
    httpx_out = RESULTS_DIR / "probed" / "httpx-output.txt"

    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([str(TOOLS_DIR), str(Path.home() / "go" / "bin"), env.get("PATH", "")])

    katana_lines = read_lines(katana_out)
    p = subprocess.Popen(
        ["httpx", "-silent", "-status-code",
         "-follow-redirects", "-tls-probe", "-random-agent", "-fr",
         "-o", str(httpx_out)],
        stdin=subprocess.PIPE,
        env=env
    )
    p.communicate(input="\n".join(katana_lines).encode())
    if p.returncode != 0:
        print(colored("[!] HTTPX failed", "red"))
        sys.exit(1)

    total_live = count_lines(httpx_out)
    print(colored(f"[+] HTTPX completed. Found {total_live} live URLs", "green"))

    # ── Nuclei ──
    print(colored("[*] Running Nuclei for vulnerability scanning...", "yellow"))
    nuclei_report = RESULTS_DIR / "vulnerabilities" / "report"
    nuclei_report.mkdir(exist_ok=True)

    httpx_lines = read_lines(httpx_out)
    p2 = subprocess.Popen(
        ["nuclei",
         "-headless", "-sresp",
         "-rate-limit", str(RATE_LIMIT),
         "-concurrency", str(THREADS),
         "-severity", "critical,high,medium",
         "-tags", "login,auth,exposure,api",
         "-markdown-export", str(nuclei_report),
         "-H", f"User-Agent: {user_agent}",
         "-tlsi", "-stats"],
        stdin=subprocess.PIPE,
        env=env
    )
    p2.communicate(input="\n".join(httpx_lines).encode())
    if p2.returncode != 0:
        print(colored("[!] Nuclei failed", "red"))
        sys.exit(1)

    print(colored(f"[+] Nuclei completed. Report saved in {nuclei_report}", "green"))


# ─────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────
def generate_report():
    print(colored("\n[+] Generating Summary Report", "blue"))
    report_file = RESULTS_DIR / "recon-report.md"

    lines = [
        f"# Reconnaissance Report for {TARGET_URL}",
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        f"- Target URL: {TARGET_URL}",
    ]

    katana_out = RESULTS_DIR / "urls" / "katana-output.txt"
    if katana_out.exists():
        lines.append(f"- Total URLs discovered: {count_lines(katana_out)}")

    httpx_out = RESULTS_DIR / "probed" / "httpx-output.txt"
    if httpx_out.exists():
        lines.append(f"- Live URLs: {count_lines(httpx_out)}")

    nuclei_report = RESULTS_DIR / "vulnerabilities" / "report"
    if nuclei_report.exists():
        lines.append(f"- Vulnerability report: {nuclei_report}")

    lines += [
        "",
        "## Next Steps",
        "- Review Nuclei markdown report for vulnerabilities",
        "- Manually verify high and critical findings",
        "- Investigate exposed APIs and authentication endpoints",
    ]

    report_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(colored(f"[+] Report generated: {report_file}", "green"))
    return report_file


# ─────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────
def parse_arguments():
    global TARGET_URL, OUTPUT_DIR, THREADS, RATE_LIMIT, CONFIG_FILE

    parser = argparse.ArgumentParser(
        description="Streamlined Recon Playbook (v2): Katana -> HTTPX -> Nuclei"
    )
    parser.add_argument("-d", "--url",        help="Target URL (e.g., https://example.com)")
    parser.add_argument("-o", "--output",     help="Output directory")
    parser.add_argument("-t", "--threads",    type=int, default=20,  help="Concurrency (default: 20)")
    parser.add_argument("-r", "--rate-limit", type=int, default=25,  help="Rate limit per second (default: 25)")
    parser.add_argument("-c", "--config",     help="Config file path")

    args = parser.parse_args()

    if args.url:        TARGET_URL  = args.url
    if args.output:     OUTPUT_DIR  = args.output
    if args.threads:    THREADS     = args.threads
    if args.rate_limit: RATE_LIMIT  = args.rate_limit
    if args.config:     CONFIG_FILE = Path(args.config)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    print(colored("""
-----------------------------------------------------------------------------
|                                                                           |
|   Streamlined Recon Playbook (v2): Efficient Crawling with Katana,        |
|   HTTPX, and Nuclei                                                       |
-----------------------------------------------------------------------------
""", "blue"))

    parse_arguments()

    if not TARGET_URL:
        get_target_url()

    setup_directories()
    check_prerequisites()
    load_config()

    start_time = time.time()

    recon_pipeline()
    report_file = generate_report()

    elapsed = time.time() - start_time
    h = int(elapsed // 3600)
    m = int((elapsed % 3600) // 60)
    s = int(elapsed % 60)

    print(colored(f"\n[+] Reconnaissance completed in {h}h {m}m {s}s", "green"))
    print(colored(f"[+] Results saved to: {RESULTS_DIR}", "green"))
    print(colored(f"[+] Report available at: {report_file}", "green"))


if __name__ == "__main__":
    main()