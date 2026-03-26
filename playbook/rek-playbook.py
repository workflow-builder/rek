# ╔═════════════════════════════════════════════════════════════╗
# ║  Modern Recon Playbook for Bug Bounty Hunters               ║
# ║  Automated reconnaissance pipeline based on Open sources    ║
# ║  methodology                                                ║
# ╚═════════════════════════════════════════════════════════════╝
# Python Cross-Platform Edition by jackb898

import os
import sys
import shutil
import subprocess
import argparse
import glob
import re
import time
import platform
import urllib.request
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
WORKING_DIR   = Path(os.environ.get("RECON_TOOLKIT_DIR", Path(__file__).parent))
TOOLS_DIR     = Path(os.environ.get("TOOLS_DIR",         WORKING_DIR / "tools"))
WORDLISTS_DIR = Path(os.environ.get("WORDLISTS_DIR",     WORKING_DIR / "wordlists"))
CONFIG_FILE   = Path(os.environ.get("CONFIG_PATH",       WORKING_DIR / "config.conf"))
RESOLVERS_FILE = WORKING_DIR / "resolvers.txt"

TARGET_DOMAIN      = ""
OUTPUT_DIR         = ""
RESULTS_DIR        = Path()
THREADS            = 100
CHAOS_API_KEY      = ""
GITHUB_API_TOKEN   = ""
GITLAB_API_TOKEN   = ""
SKIP_INSTALL       = False
SKIP_SUBDOMAIN     = False
SKIP_PERMUTATION   = False
SKIP_FINGERPRINT   = False
SKIP_PORTSCAN      = False
SKIP_SPIDER        = False
SKIP_VULNANALYSIS  = False
SKIP_JSANALYSIS    = False


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def command_exists(name: str) -> bool:
    """Check if a command is on PATH or in TOOLS_DIR."""
    if shutil.which(name):
        return True
    for candidate in [TOOLS_DIR / name, TOOLS_DIR / f"{name}.exe"]:
        if candidate.exists():
            return True
    return False


def go_tool_exists(name: str) -> bool:
    return command_exists(name)

def resolve_tool(cmd):
    """Prefer Go-installed tools over system ones if they exist."""
    if not cmd:
        return cmd

    tool = cmd[0]
    go_path = Path.home() / "go" / "bin" / tool

    # If Go version exists, use it
    if go_path.exists():
        cmd[0] = str(go_path)
        return cmd

    # Otherwise fallback to system PATH
    system_path = shutil.which(tool)
    if system_path:
        cmd[0] = system_path

    return cmd


def run(cmd, cwd=None, env=None, capture=False):
    """Run a command, streaming output unless capture=True."""
    merged_env = os.environ.copy()
    merged_env["PATH"] = os.pathsep.join([
        str(TOOLS_DIR),
        str(Path.home() / "go" / "bin"),
        merged_env.get("PATH", "")
    ])
    if env:
        merged_env.update(env)
    
    cmd = resolve_tool(cmd)

    if capture:
        result = subprocess.run(
            cmd, cwd=cwd, env=merged_env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return result.stdout.strip()
    else:
        subprocess.run(cmd, cwd=cwd, env=merged_env)


def run_piped(cmds, cwd=None):
    """Run a shell pipeline (list of arg-lists) and return stdout as string."""
    merged_env = os.environ.copy()
    merged_env["PATH"] = os.pathsep.join([
        str(TOOLS_DIR),
        str(Path.home() / "go" / "bin"),
        merged_env.get("PATH", "")
    ])
    procs = []
    for i, cmd in enumerate(cmds):
        stdin  = procs[-1].stdout if procs else None
        stdout = subprocess.PIPE
        p = subprocess.Popen(cmd, stdin=stdin, stdout=stdout,
                              stderr=subprocess.DEVNULL, cwd=cwd, env=merged_env)
        if procs:
            procs[-1].stdout.close()
        procs.append(p)
    out, _ = procs[-1].communicate()
    return out.decode(errors="replace")


def write_lines(path, lines):
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_lines(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def count_lines(path) -> int:
    return len(read_lines(path))


def spinner(message: str):
    """Print a simple status message (spinner not needed on Windows without threads)."""
    print(colored(f"[*] {message}", "yellow"))


# ─────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────
def setup_directories():
    global RESULTS_DIR
    print(colored("[+] Setting up directories...", "blue"))

    WORKING_DIR.mkdir(parents=True, exist_ok=True)
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    RESULTS_DIR = WORKING_DIR / "results" / f"{TARGET_DOMAIN}-{timestamp}"

    for subdir in ["subdomains", "endpoints", "js", "vulnerabilities"]:
        (RESULTS_DIR / subdir).mkdir(parents=True, exist_ok=True)

    print(colored("[+] Directories set up successfully", "green"))
    print(colored(f"[+] Results will be saved to: {RESULTS_DIR}", "green"))


# ─────────────────────────────────────────────
# Tool installation
# ─────────────────────────────────────────────
def install_go():
    print(colored("[*] Installing Go...", "yellow"))
    print(colored("[!] Go not found. Download and install from https://go.dev/dl/ then re-run.", "red"))
    sys.exit(1)


def install_tools():
    print(colored("[+] Installing required tools...", "blue"))

    if not command_exists("go"):
        install_go()

    # Python tools
    if command_exists("pip") or command_exists("pip3"):
        print(colored("[*] Installing Python dependencies...", "yellow"))
        subprocess.run([sys.executable, "-m", "pip", "install",
                        "requests", "dnsgen", "tldextract", "dnspython"])

    # Go tools
    go_tools = [
        ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
        ("assetfinder", "github.com/tomnomnom/assetfinder"),
        ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx"),
        ("naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu"),
        ("chaos", "github.com/projectdiscovery/chaos-client/cmd/chaos"),
        ("gospider", "github.com/jaeles-project/gospider"),
        ("katana", "github.com/projectdiscovery/katana/cmd/katana"),
        ("gau", "github.com/lc/gau/v2/cmd/gau"),
        ("getjs", "github.com/003random/getJS"),
        ("cariddi", "github.com/edoardottt/cariddi/cmd/cariddi"),
        ("goaltdns", "github.com/subfinder/goaltdns"),
        ("gotator", "github.com/Josue87/gotator"),
        # ("ripgen", "github.com/resyncgg/ripgen/cmd/ripgen"), Rust tool not Go
        ("puredns", "github.com/d3mondev/puredns/v2/cmd/puredns"),
        ("gf", "github.com/tomnomnom/gf"),
    ]
    for tool, pkg in go_tools:
        if go_tool_exists(tool):
            print(colored(f"[+] {tool} already installed", "green"))
        else:
            print(colored(f"[*] Installing {tool}...", "yellow"))
            run(["go", "install", "-v", pkg])

    # findomain — Windows binary
    # Installation involves download/unzip, easier to keep logic in installer script than port + require extra dependency (zipfile)
    if not command_exists("findomain"):
        print(colored("\n[!] findomain is missing. Please re-run install-script.py", "yellow"))
        sys.exit(1)

    # gf patterns
    if go_tool_exists("gf"):
        gf_dir = Path.home() / ".gf"
        gf_dir.mkdir(exist_ok=True)
        patterns_dir = gf_dir / "Gf-Patterns"
        if patterns_dir.exists():
            print(colored("[*] Updating Gf-Patterns...", "yellow"))
            run(["git", "-C", str(patterns_dir), "pull"])
        else:
            print(colored("[*] Cloning Gf-Patterns...", "yellow"))
            run(["git", "clone", "https://github.com/1ndianl33t/Gf-Patterns", str(patterns_dir)])
        import shutil as _shutil
        for f in patterns_dir.glob("*.json"):
            _shutil.copy(f, gf_dir)

    # github-subdomains / gitlab-subdomains
    for name, url in [
        ("github-subdomains", "https://github.com/gwen001/github-subdomains.git"),
        ("gitlab-subdomains", "https://github.com/gwen001/gitlab-subdomains.git"),
    ]:
        repo_path = TOOLS_DIR / name
        if repo_path.exists():
            print(colored(f"[*] Updating {name}...", "yellow"))
            run(["git", "-C", str(repo_path), "pull"])
        else:
            print(colored(f"[*] Cloning {name}...", "yellow"))
            run(["git", "clone", url, str(repo_path)])
        result = subprocess.run(["go", "build"], cwd=str(repo_path),
                                 capture_output=True, text=True)
        if result.returncode != 0:
            print(colored(f"[!] Failed to build {name}: {result.stderr}", "red"))

    # Resolvers
    if not RESOLVERS_FILE.exists():
        print(colored("[*] Downloading resolvers...", "yellow"))
        urllib.request.urlretrieve(
            "https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt",
            RESOLVERS_FILE
        )

    print(colored("[+] Tools installation completed", "green"))


# ─────────────────────────────────────────────
# Prerequisites check
# ─────────────────────────────────────────────
def check_prerequisites():
    print(colored("[+] Checking prerequisites...", "blue"))

    tools = [
        "subfinder", "assetfinder", "findomain", "chaos",
        "github-subdomains", "gitlab-subdomains",
        "httpx", "naabu", "gospider", "katana",
        "gau", "getjs", "cariddi", "dnsgen",
        "goaltdns", "gotator", "puredns", "gf",
    ]

    print(f"{'Tool':<20}{'Status'}")
    print(f"{'--------------------':<20}{'----------'}")

    all_ok = True
    for tool in tools:
        if command_exists(tool) or go_tool_exists(tool):
            print(f"{tool:<20}" + colored("Installed", "green"))
        else:
            print(f"{tool:<20}" + colored("Missing", "red"))
            all_ok = False

    if RESOLVERS_FILE.exists():
        print(f"{'resolvers.txt':<20}" + colored("Available", "green"))
    else:
        print(f"{'resolvers.txt':<20}" + colored("Missing", "red"))
        all_ok = False

    print("\n[!] Any Missing dependencies might cause execution errors. Install them (y) or continue? (n) ")

    if not all_ok:
        #print("\n[!] Some prerequisites are missing. Install them? (y/n): ", end='', flush=True)
        choice = input().strip().lower()
        if choice == 'y':
            install_tools()
        else:
            print(colored("[!] Missing prerequisites might cause errors during execution", "red"))
    else:
        print(colored("\n[+] All prerequisites are installed", "green"))


# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
def load_config():
    global CHAOS_API_KEY, GITHUB_API_TOKEN, GITLAB_API_TOKEN, THREADS

    if CONFIG_FILE.exists():
        print(colored("[+] Loading configuration...", "blue"))
        for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip().strip('"')
            if '=' in line:
                key, _, val = line.partition('=')
                val = val.strip().strip('"')
                if key == "CHAOS_API_KEY":       CHAOS_API_KEY     = val
                elif key == "GITHUB_API_TOKEN":  GITHUB_API_TOKEN  = val
                elif key == "GITLAB_API_TOKEN":  GITLAB_API_TOKEN  = val
                elif key == "THREADS":
                    try: THREADS = int(val)
                    except ValueError: pass
        print(colored("[+] Configuration loaded", "green"))
    else:
        print(colored("[!] Configuration file not found. Creating new one...", "yellow"))
        CHAOS_API_KEY    = input(colored("[?] Enter your Chaos API key (leave blank if none): ", "yellow")).strip()
        GITHUB_API_TOKEN = input(colored("[?] Enter your GitHub API token (leave blank if none): ", "yellow")).strip()
        GITLAB_API_TOKEN = input(colored("[?] Enter your GitLab API token (leave blank if none): ", "yellow")).strip()
        t = input(colored("[?] Default number of threads (default: 100): ", "yellow")).strip()
        if t:
            try: THREADS = int(t)
            except ValueError: pass

        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(f'CHAOS_API_KEY="{CHAOS_API_KEY}"\n')
            f.write(f'GITHUB_API_TOKEN="{GITHUB_API_TOKEN}"\n')
            f.write(f'GITLAB_API_TOKEN="{GITLAB_API_TOKEN}"\n')
            f.write(f'THREADS="{THREADS}"\n')

        print(colored("[+] Configuration saved", "green"))


# ─────────────────────────────────────────────
# Pipeline save/load
# ─────────────────────────────────────────────
def save_pipeline():
    pipelines_dir = WORKING_DIR / "pipelines"
    pipelines_dir.mkdir(exist_ok=True)
    pipeline_file = pipelines_dir / f"{TARGET_DOMAIN}-pipeline.conf"

    print(colored("[+] Saving pipeline configuration...", "blue"))
    with open(pipeline_file, "w", encoding="utf-8") as f:
        f.write(f'TARGET_DOMAIN="{TARGET_DOMAIN}"\n')
        f.write(f'THREADS="{THREADS}"\n')
        f.write(f'CHAOS_API_KEY="{CHAOS_API_KEY}"\n')
        f.write(f'GITHUB_API_TOKEN="{GITHUB_API_TOKEN}"\n')
        f.write(f'GITLAB_API_TOKEN="{GITLAB_API_TOKEN}"\n')
        f.write(f'SKIP_INSTALL="{SKIP_INSTALL}"\n')
        f.write(f'SKIP_SUBDOMAIN="{SKIP_SUBDOMAIN}"\n')
        f.write(f'SKIP_PERMUTATION="{SKIP_PERMUTATION}"\n')
        f.write(f'SKIP_FINGERPRINT="{SKIP_FINGERPRINT}"\n')
        f.write(f'SKIP_PORTSCAN="{SKIP_PORTSCAN}"\n')
        f.write(f'SKIP_SPIDER="{SKIP_SPIDER}"\n')
        f.write(f'SKIP_VULNANALYSIS="{SKIP_VULNANALYSIS}"\n')
        f.write(f'SKIP_JSANALYSIS="{SKIP_JSANALYSIS}"\n')

    print(colored(f"[+] Pipeline configuration saved: {pipeline_file}", "green"))


def load_pipeline(domain: str) -> bool:
    global TARGET_DOMAIN, THREADS, CHAOS_API_KEY, GITHUB_API_TOKEN, GITLAB_API_TOKEN
    global SKIP_INSTALL, SKIP_SUBDOMAIN, SKIP_PERMUTATION, SKIP_FINGERPRINT
    global SKIP_PORTSCAN, SKIP_SPIDER, SKIP_VULNANALYSIS, SKIP_JSANALYSIS

    pipeline_file = WORKING_DIR / "pipelines" / f"{domain}-pipeline.conf"
    if not pipeline_file.exists():
        print(colored(f"[!] No existing pipeline found for {domain}", "yellow"))
        return False

    print(colored(f"[+] Found existing pipeline for {domain}. Loading...", "blue"))
    bool_map = {"true": True, "false": False}
    for line in pipeline_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if '=' not in line:
            continue
        key, _, val = line.partition('=')
        val = val.strip().strip('"')
        if   key == "TARGET_DOMAIN":    TARGET_DOMAIN    = val
        elif key == "THREADS":
            try: THREADS = int(val)
            except ValueError: pass
        elif key == "CHAOS_API_KEY":    CHAOS_API_KEY    = val
        elif key == "GITHUB_API_TOKEN": GITHUB_API_TOKEN = val
        elif key == "GITLAB_API_TOKEN": GITLAB_API_TOKEN = val
        elif key == "SKIP_INSTALL":     SKIP_INSTALL     = bool_map.get(val.lower(), False)
        elif key == "SKIP_SUBDOMAIN":   SKIP_SUBDOMAIN   = bool_map.get(val.lower(), False)
        elif key == "SKIP_PERMUTATION": SKIP_PERMUTATION = bool_map.get(val.lower(), False)
        elif key == "SKIP_FINGERPRINT": SKIP_FINGERPRINT = bool_map.get(val.lower(), False)
        elif key == "SKIP_PORTSCAN":    SKIP_PORTSCAN    = bool_map.get(val.lower(), False)
        elif key == "SKIP_SPIDER":      SKIP_SPIDER      = bool_map.get(val.lower(), False)
        elif key == "SKIP_VULNANALYSIS":SKIP_VULNANALYSIS= bool_map.get(val.lower(), False)
        elif key == "SKIP_JSANALYSIS":  SKIP_JSANALYSIS  = bool_map.get(val.lower(), False)

    print(colored("[+] Pipeline loaded", "green"))
    return True


def list_pipelines():
    print(colored("[+] Available saved pipelines:", "blue"))
    pipelines_dir = WORKING_DIR / "pipelines"
    if not pipelines_dir.exists():
        print(colored("[!] No saved pipelines found", "yellow"))
        return

    files = list(pipelines_dir.glob("*-pipeline.conf"))
    if not files:
        print(colored("[!] No saved pipelines found", "yellow"))
        return

    for i, f in enumerate(sorted(files), 1):
        domain = f.name.replace("-pipeline.conf", "")
        print(colored(f"[{i}] {domain}", "green"))


def get_target_domain():
    global TARGET_DOMAIN
    TARGET_DOMAIN = input(colored("[?] Enter the target domain (e.g., example.com): ", "yellow")).strip()
    if not TARGET_DOMAIN:
        print(colored("[!] No domain provided. Exiting.", "red"))
        sys.exit(1)
    print(colored(f"[+] Target domain set to: {TARGET_DOMAIN}", "green"))


# ─────────────────────────────────────────────
# Step 1: Subdomain Enumeration
# ─────────────────────────────────────────────
def subdomain_enumeration():
    print(colored("\n[+] Step 1: Subdomain Enumeration", "blue"))
    subs_dir = RESULTS_DIR / "subdomains"

    print(colored("[*] Running subfinder...", "yellow"))
    run(["subfinder", "-d", TARGET_DOMAIN, "-all", "-recursive", "-silent",
         "-o", str(subs_dir / "subfinder.txt")], cwd=str(subs_dir))

    print(colored("[*] Running assetfinder...", "yellow"))
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([str(TOOLS_DIR), str(Path.home() / "go" / "bin"), env.get("PATH", "")])
    p = subprocess.Popen(
        ["assetfinder", "-subs-only"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env=env
    )
    out, _ = p.communicate(input=TARGET_DOMAIN.encode())
    (subs_dir / "assetf.txt").write_bytes(out)

    print(colored("[*] Running findomain...", "yellow"))
    if sys.platform == 'win32':
        run([f"{TOOLS_DIR / 'findomain.exe'}", "-t", TARGET_DOMAIN, "--quiet",
            "-u", str(subs_dir / "findomain.txt")], cwd=str(subs_dir))
    else: # Unix-based
        run([f"{TOOLS_DIR / 'findomain'}", "-t", TARGET_DOMAIN, "--quiet",
            "-u", str(subs_dir / "findomain.txt")], cwd=str(subs_dir))

    if CHAOS_API_KEY:
        print(colored("[*] Running chaos...", "yellow"))
        run(["chaos", "-key", CHAOS_API_KEY, "-d", TARGET_DOMAIN,
             "-o", str(subs_dir / "chaos.txt")], cwd=str(subs_dir))
    else:
        print(colored("[!] Chaos API key not provided, skipping...", "yellow"))

    if GITHUB_API_TOKEN:
        print(colored("[*] Running github-subdomains...", "yellow"))
        run(["github-subdomains", "-d", TARGET_DOMAIN, "-t", GITHUB_API_TOKEN,
             "-o", str(subs_dir / "github-subdomains.txt")], cwd=str(subs_dir))
    else:
        print(colored("[!] GitHub API token not provided, skipping github-subdomains...", "yellow"))

    if GITLAB_API_TOKEN:
        print(colored("[*] Running gitlab-subdomains...", "yellow"))
        run(["gitlab-subdomains", "-d", TARGET_DOMAIN, "-t", GITLAB_API_TOKEN,
             "-o", str(subs_dir / "gitlab-subdomains.txt")], cwd=str(subs_dir))
    else:
        print(colored("[!] GitLab API token not provided, skipping gitlab-subdomains...", "yellow"))

    # Consolidate
    print(colored("[*] Consolidating and deduplicating results...", "yellow"))
    all_subs = set()
    for txt in subs_dir.glob("*.txt"):
        all_subs.update(read_lines(txt))

    sorted_subs = sorted(all_subs)
    write_lines(subs_dir / "sorted-subdomains.txt", sorted_subs)

    print(colored(f"[+] Subdomain enumeration completed. Found {len(sorted_subs)} unique subdomains", "green"))


# ─────────────────────────────────────────────
# Step 2: Subdomain Permutation and Bruteforce
# ─────────────────────────────────────────────
def subdomain_permutation():
    print(colored("\n[+] Step 2: Subdomain Permutation and Bruteforce", "blue"))
    subs_dir = RESULTS_DIR / "subdomains"
    sorted_file = subs_dir / "sorted-subdomains.txt"
    sorted_subs = read_lines(sorted_file)

    # Build perms wordlist (split on dots and hyphens)
    perms = set()
    for sub in sorted_subs:
        for part in re.split(r'[.\-]', sub):
            if part:
                perms.add(part)
    write_lines(subs_dir / "perm", sorted(perms))

    print(colored("[*] Running dnsgen...", "yellow"))
    out = run_piped([
        [sys.executable, "-m", "dnsgen", "-"],
    ])
    # dnsgen reads from stdin so feed it via Popen
    merged_env = os.environ.copy()
    merged_env["PATH"] = os.pathsep.join([str(TOOLS_DIR), str(Path.home() / "go" / "bin"), merged_env.get("PATH","")])
    p = subprocess.Popen(
        [sys.executable, "-m", "dnsgen", "-"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env=merged_env
    )
    dnsgen_out, _ = p.communicate(input="\n".join(sorted_subs).encode())
    (subs_dir / "output-dnsgen.txt").write_bytes(dnsgen_out)

    print(colored("[*] Running goaltdns...", "yellow"))
    if command_exists("goaltdns"):
        run(["goaltdns",
             "-w", str(subs_dir / "perm"),
             "-l", str(sorted_file),
             "-o", str(subs_dir / "output-goaltdns.txt")])
    else:
        print(colored("[!] goaltdns not found, skipping...", "red"))

    print(colored("[*] Running gotator...", "yellow"))

    if command_exists("gotator"):
        merged_env2 = os.environ.copy()
        merged_env2["PATH"] = os.pathsep.join([
            str(TOOLS_DIR),
            str(Path.home() / "go" / "bin"),
            merged_env2.get("PATH", "")
        ])

        output_path = subs_dir / "output-gotator.txt"

        with open(output_path, "w", encoding="utf-8") as f:
            subprocess.run(
                ["gotator",
                "-sub", str(sorted_file),
                "-perm", str(subs_dir / "perm"),
                "-depth", "1",
                "-numbers", "1"],
                stdout=f,
                stderr=subprocess.DEVNULL,
                env=merged_env2,
                timeout=300
            )

    else:
        print(colored("[!] gotator not found, skipping...", "red"))

    print(colored("[*] Running ripgen...", "yellow"))
    if command_exists("ripgen"):
        merged_env3 = os.environ.copy()
        merged_env3["PATH"] = os.pathsep.join([str(TOOLS_DIR), str(Path.home() / "go" / "bin"), merged_env3.get("PATH","")])
        p2 = subprocess.Popen(
            ["ripgen"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=merged_env3
        )
        ripgen_out, _ = p2.communicate(input="\n".join(sorted_subs).encode())
        (subs_dir / "output-ripgen.txt").write_bytes(ripgen_out)
    else:
        print(colored("[!] ripgen not found, skipping...", "red"))

    # Merge permutation outputs
    print(colored("[*] Merging permutation results...", "yellow"))
    merged = set()
    for txt in subs_dir.glob("output*.txt"):
        merged.update(read_lines(txt))
    write_lines(subs_dir / "output.txt", sorted(merged))

    # Resolve with puredns
    print(colored("[*] Resolving permutated subdomains...", "yellow"))
    if command_exists("puredns"):
        merged_env4 = os.environ.copy()
        merged_env4["PATH"] = os.pathsep.join([str(TOOLS_DIR), str(Path.home() / "go" / "bin"), merged_env4.get("PATH","")])
        p3 = subprocess.Popen(
            ["puredns", "resolve", "--resolvers", str(RESOLVERS_FILE),
             "--write", str(subs_dir / "subdomains-permutated.txt")],
            stdin=subprocess.PIPE, stderr=subprocess.DEVNULL, env=merged_env4
        )
        p3.communicate(input="\n".join(sorted(merged)).encode())
    else:
        print(colored("[!] puredns not found, skipping resolution...", "red"))

    # Final merge
    print(colored("[*] Merging all subdomains...", "yellow"))
    final = set(sorted_subs)
    perm_file = subs_dir / "subdomains-permutated.txt"
    if perm_file.exists():
        final.update(read_lines(perm_file))
    write_lines(subs_dir / "final-subdomains.txt", sorted(final))

    print(colored(f"[+] Subdomain permutation completed. Found {len(final)} total unique subdomains", "green"))


# ─────────────────────────────────────────────
# Step 3: Identify Live Subdomains
# ─────────────────────────────────────────────
def identify_live_subdomains():
    print(colored("\n[+] Step 3: Identifying Live Subdomains", "blue"))
    subs_dir = RESULTS_DIR / "subdomains"

    print(colored("[*] Running httpx to identify live subdomains...", "yellow"))
    run(["httpx",
         "-l", str(subs_dir / "final-subdomains.txt"),
         "-threads", str(THREADS),
         "-o", str(subs_dir / "subs-alive.txt")])

    print(colored("[*] Fingerprinting live subdomains...", "yellow"))
    run(["httpx",
         "-l", str(subs_dir / "subs-alive.txt"),
         "-title", "-sc", "-td", "-server", "-fr", "-probe", "-location",
         "-o", str(subs_dir / "httpx-output.txt")])

    total = count_lines(subs_dir / "subs-alive.txt")
    print(colored(f"[+] Live subdomain identification completed. Found {total} live subdomains", "green"))


# ─────────────────────────────────────────────
# Step 4: Port Scanning
# ─────────────────────────────────────────────
def port_scanning():
    print(colored("\n[+] Step 4: Port Scanning", "blue"))
    subs_dir = RESULTS_DIR / "subdomains"

    print(colored("[*] Running naabu for port scanning...", "yellow"))
    run(["naabu",
         "-c", str(THREADS),
         "-l", str(subs_dir / "subs-alive.txt"),
         "-port", "80,443,3000,5000,8080,8000,8081,8888,8443",
         "-o", str(subs_dir / "subs-portscanned.txt")])

    print(colored("[*] Fingerprinting services on open ports...", "yellow"))
    run(["httpx",
         "-l", str(subs_dir / "subs-portscanned.txt"),
         "-title", "-sc", "-td", "-server", "-fr",
         "-o", str(subs_dir / "httpx-naabu.txt")])

    print(colored("[+] Port scanning completed", "green"))


# ─────────────────────────────────────────────
# Step 5: Content Discovery (Spidering)
# ─────────────────────────────────────────────
def content_discovery():
    print(colored("\n[+] Step 5: Content Discovery (Spidering)", "blue"))
    endpoints_dir = RESULTS_DIR / "endpoints"
    subs_alive    = RESULTS_DIR / "subdomains" / "subs-alive.txt"
    gospider_out  = endpoints_dir / "gospider-output"
    gospider_out.mkdir(exist_ok=True)

    print(colored("[*] Running gospider...", "yellow"))
    run(["gospider",
         "-S", str(subs_alive),
         "-a", "-r", "--js", "--sitemap", "--robots",
         "-d", "30", "-c", "10",
         "-o", str(gospider_out)])

    # Merge all gospider output files
    gospider_all = []
    for f in gospider_out.rglob("*"):
        if f.is_file():
            gospider_all.extend(read_lines(f))
    write_lines(endpoints_dir / "gospider-all.txt", gospider_all)

    print(colored("[*] Running katana...", "yellow"))
    run(["katana",
         "-list", str(subs_alive),
         "-kf", "all", "-jc",
         "-d", "30", "-c", "50", "-silent",
         "-o", str(endpoints_dir / "katana-output.txt")])

    # print(colored("[*] Running gau...", "yellow"))
    merged_env = os.environ.copy()
    merged_env["PATH"] = os.pathsep.join([str(TOOLS_DIR), str(Path.home() / "go" / "bin"), merged_env.get("PATH","")])
    alive_lines = read_lines(subs_alive)
    # p = subprocess.Popen(
    #     ["gau", "--threads", "50", "--blacklist", "jpg,jpeg,png,gif,svg,css"],
    #     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    #     stderr=subprocess.DEVNULL, env=merged_env
    # )
    # gau_out, _ = p.communicate(input="\n".join(alive_lines).encode())
    # (endpoints_dir / "gau-output.txt").write_bytes(gau_out)

    p = subprocess.Popen(
        ["gau", "--threads", "50", "--timeout", "30", "--blacklist", "jpg,jpeg,png,gif,svg,css"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env=merged_env
    )
    p.stdin.write("\n".join(alive_lines).encode())
    p.stdin.close()

    results = []
    for line in p.stdout:
        decoded = line.decode(errors='ignore').strip()
        results.append(decoded)
        print(f"\r[*] gau: {len(results)} URLs found...", end='', flush=True)

    print()  # newline after progress
    (endpoints_dir / "gau-output.txt").write_text("\n".join(results))



    # Combine all
    print(colored("[*] Combining all spider results...", "yellow"))
    combined = set()
    for src in ["gospider-all.txt", "katana-output.txt", "gau-output.txt"]:
        combined.update(read_lines(endpoints_dir / src))
    write_lines(endpoints_dir / "spider-output.txt", sorted(combined))

    print(colored(f"[+] Content discovery completed. Found {len(combined)} unique URLs", "green"))


# ─────────────────────────────────────────────
# Step 6: Vulnerability Analysis
# ─────────────────────────────────────────────
def analyze_vulnerabilities():
    print(colored("\n[+] Step 6: Analyzing Spidering Output for Vulnerabilities", "blue"))
    vuln_dir    = RESULTS_DIR / "vulnerabilities"
    spider_file = RESULTS_DIR / "endpoints" / "spider-output.txt"
    gf_dir      = Path.home() / ".gf"

    if not gf_dir.exists():
        print(colored("[!] GF patterns not found. Skipping vulnerability analysis.", "red"))
        return

    print(colored("[*] Filtering for potential vulnerabilities...", "yellow"))
    spider_lines = read_lines(spider_file)

    vuln_types = ["xss", "lfi", "ssrf", "sqli", "rce", "ssti", "idor"]
    merged_env = os.environ.copy()
    merged_env["PATH"] = os.pathsep.join([str(TOOLS_DIR), str(Path.home() / "go" / "bin"), merged_env.get("PATH","")])

    for vuln in vuln_types:
        p = subprocess.Popen(
            ["gf", vuln],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=merged_env
        )
        out, _ = p.communicate(input="\n".join(spider_lines).encode())
        (vuln_dir / f"checkfor-{vuln}.txt").write_bytes(out)

    print(colored("[+] Vulnerability pattern analysis completed", "green"))


# ─────────────────────────────────────────────
# Step 7: Categorize Endpoints
# ─────────────────────────────────────────────
def categorize_endpoints():
    print(colored("\n[+] Step 7: Categorizing Endpoints by File Extension", "blue"))
    endpoints_dir = RESULTS_DIR / "endpoints"
    spider_lines  = read_lines(endpoints_dir / "spider-output.txt")

    print(colored("[*] Extracting endpoints by file extension...", "yellow"))

    categories = {
        "json":   [r"\.json$"],
        "backup": [r"\.bak$", r"\.backup$", r"\.old$", r"\.tmp$"],
        "config": [r"\.conf$", r"\.config$", r"\.env$", r"\.ini$"],
        "pdf":    [r"\.pdf$"],
        "xml":    [r"\.xml$"],
        "sql":    [r"\.sql$"],
        "log":    [r"\.log$"],
    }

    for category, patterns in categories.items():
        combined = re.compile("|".join(patterns), re.IGNORECASE)
        matches = [line for line in spider_lines if combined.search(line)]
        write_lines(endpoints_dir / f"{category}-endpoints.txt", matches)

    print(colored("[+] Endpoint categorization completed", "green"))


# ─────────────────────────────────────────────
# Step 8: JavaScript Analysis
# ─────────────────────────────────────────────
def js_analysis():
    print(colored("\n[+] Step 8: JavaScript Analysis for Secrets", "blue"))
    js_dir      = RESULTS_DIR / "js"
    spider_file = RESULTS_DIR / "endpoints" / "spider-output.txt"
    spider_lines = read_lines(spider_file)

    print(colored("[*] Extracting JavaScript files...", "yellow"))
    if command_exists("getjs"):
        run(["getjs",
             "--input", str(spider_file),
             "--complete", "--resolve",
             "--threads", "50",
             "--output", str(js_dir / "getjs-output.txt")])
    else:
        print(colored("[!] getJS not found. Attempting alternative extraction...", "red"))
        js_lines = [l for l in spider_lines if ".js" in l.lower()]
        write_lines(js_dir / "getjs-output.txt", js_lines)

    print(colored("[*] Scanning JavaScript files for secrets...", "yellow"))
    if command_exists("cariddi"):
        merged_env = os.environ.copy()
        merged_env["PATH"] = os.pathsep.join([str(TOOLS_DIR), str(Path.home() / "go" / "bin"), merged_env.get("PATH","")])
        js_lines = read_lines(js_dir / "getjs-output.txt")
        p = subprocess.Popen(
            ["cariddi", "-headers", "User-Agent: Mozilla/5.0", "-intensive", "-e", "-s"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=merged_env
        )
        out, _ = p.communicate(input="\n".join(js_lines).encode())
        (js_dir / "js-secrets.txt").write_bytes(out)
    else:
        print(colored("[!] cariddi not found. Skipping JavaScript secret analysis.", "red"))

    print(colored("[+] JavaScript analysis completed", "green"))


# ─────────────────────────────────────────────
# Report generation
# ─────────────────────────────────────────────
def generate_report():
    print(colored("\n[+] Generating Summary Report", "blue"))
    report_file = RESULTS_DIR / "recon-report.md"

    lines = [
        f"# Reconnaissance Report for {TARGET_DOMAIN}",
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
    ]

    def add_count(path, label):
        if Path(path).exists():
            lines.append(f"- {label}: {count_lines(path)}")

    add_count(RESULTS_DIR / "subdomains" / "final-subdomains.txt", "Total unique subdomains discovered")
    add_count(RESULTS_DIR / "subdomains" / "subs-alive.txt",       "Live subdomains")
    add_count(RESULTS_DIR / "endpoints"  / "spider-output.txt",    "Total endpoints discovered")

    lines += ["", "## Potential Vulnerabilities"]
    for vuln in ["xss", "lfi", "ssrf", "sqli", "rce", "ssti", "idor"]:
        add_count(RESULTS_DIR / "vulnerabilities" / f"checkfor-{vuln}.txt", f"Potential {vuln}")

    add_count(RESULTS_DIR / "js" / "js-secrets.txt", "JavaScript files with potential secrets")

    lines += ["", "## Interesting Findings"]

    alive_file = RESULTS_DIR / "subdomains" / "subs-alive.txt"
    if alive_file.exists():
        sample = read_lines(alive_file)[:10]
        lines += ["", "### Interesting Subdomains", "```"] + sample + ["```"]

    for vuln in ["xss", "lfi", "ssrf", "sqli", "rce", "ssti", "idor"]:
        vf = RESULTS_DIR / "vulnerabilities" / f"checkfor-{vuln}.txt"
        if vf.exists() and vf.stat().st_size > 0:
            sample = read_lines(vf)[:5]
            lines += [f"", f"### Potential {vuln} vulnerabilities (sample)", "```"] + sample + ["```"]

    for ext in ["json", "backup", "config", "pdf", "xml", "sql", "log"]:
        ef = RESULTS_DIR / "endpoints" / f"{ext}-endpoints.txt"
        if ef.exists() and ef.stat().st_size > 0:
            sample = read_lines(ef)[:5]
            lines += ["", f"### Interesting {ext} files (sample)", "```"] + sample + ["```"]

    lines += [
        "", "## Next Steps",
        "- Manual verification of potential vulnerabilities",
        "- Deeper analysis of JavaScript files for secrets",
        "- Testing discovered endpoints for business logic flaws",
        "- Exploring technologies detected by fingerprinting",
    ]

    report_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(colored(f"[+] Report generated: {report_file}", "green"))


# ─────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────
def cleanup():
    print(colored("\n[+] Cleaning up temporary files...", "blue"))
    for tmp in ["all.txt", "output.txt"]:
        f = RESULTS_DIR / "subdomains" / tmp
        if f.exists():
            f.unlink()
    print(colored("[+] Cleanup completed", "green"))


# ─────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────
def parse_arguments():
    global TARGET_DOMAIN, OUTPUT_DIR, THREADS, CONFIG_FILE
    global CHAOS_API_KEY, GITHUB_API_TOKEN, GITLAB_API_TOKEN
    global SKIP_INSTALL, SKIP_SUBDOMAIN, SKIP_PERMUTATION, SKIP_FINGERPRINT
    global SKIP_PORTSCAN, SKIP_SPIDER, SKIP_VULNANALYSIS, SKIP_JSANALYSIS

    parser = argparse.ArgumentParser(
        description="Modern Recon Playbook for Bug Bounty Hunters",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-d", "--domain",           help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output",           help="Output directory")
    parser.add_argument("-t", "--threads",          type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("-c", "--config",           help="Config file path")
    parser.add_argument("--chaos-key",              help="Chaos API key")
    parser.add_argument("--github-token",           help="GitHub API token")
    parser.add_argument("--gitlab-token",           help="GitLab API token")
    parser.add_argument("--skip-install",           action="store_true")
    parser.add_argument("--skip-subdomain",         action="store_true")
    parser.add_argument("--skip-permutation",       action="store_true")
    parser.add_argument("--skip-fingerprint",       action="store_true")
    parser.add_argument("--skip-portscan",          action="store_true")
    parser.add_argument("--skip-spider",            action="store_true")
    parser.add_argument("--skip-vulnanalysis",      action="store_true")
    parser.add_argument("--skip-jsanalysis",        action="store_true")

    args = parser.parse_args()

    if args.domain:        TARGET_DOMAIN    = args.domain
    if args.output:        OUTPUT_DIR       = args.output
    if args.threads:       THREADS          = args.threads
    if args.config:        CONFIG_FILE      = Path(args.config)
    if args.chaos_key:     CHAOS_API_KEY    = args.chaos_key
    if args.github_token:  GITHUB_API_TOKEN = args.github_token
    if args.gitlab_token:  GITLAB_API_TOKEN = args.gitlab_token

    SKIP_INSTALL      = args.skip_install
    SKIP_SUBDOMAIN    = args.skip_subdomain
    SKIP_PERMUTATION  = args.skip_permutation
    SKIP_FINGERPRINT  = args.skip_fingerprint
    SKIP_PORTSCAN     = args.skip_portscan
    SKIP_SPIDER       = args.skip_spider
    SKIP_VULNANALYSIS = args.skip_vulnanalysis
    SKIP_JSANALYSIS   = args.skip_jsanalysis


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    global TARGET_DOMAIN

    print(colored("""
-----------------------------------------------------------------------------
|                                                                           |
|   From Subdomains to Secrets: A Modern Recon Playbook for Bug Hunters     |
|                                                                           |
-----------------------------------------------------------------------------
""", "blue"))

    parse_arguments()

    if not TARGET_DOMAIN:
        list_pipelines()
        choice = input(colored("[?] Would you like to load an existing pipeline? (y/n): ", "yellow")).strip().lower()
        if choice == 'y':
            domain_input = input(colored("[?] Enter the domain name of the pipeline to load: ", "yellow")).strip()
            if not load_pipeline(domain_input):
                get_target_domain()
            else:
                TARGET_DOMAIN = domain_input
        else:
            get_target_domain()
    else:
        load_pipeline(TARGET_DOMAIN)

    setup_directories()

    if not SKIP_INSTALL:
        check_prerequisites()

    load_config()
    save_pipeline()

    start_time = time.time()

    if not SKIP_SUBDOMAIN:
        subdomain_enumeration()
    else:
        print(colored("[!] Skipping subdomain enumeration", "yellow"))

    if not SKIP_PERMUTATION:
        subdomain_permutation()
    else:
        print(colored("[!] Skipping subdomain permutation", "yellow"))

    if not SKIP_FINGERPRINT:
        identify_live_subdomains()
    else:
        print(colored("[!] Skipping subdomain fingerprinting", "yellow"))

    if not SKIP_PORTSCAN:
        port_scanning()
    else:
        print(colored("[!] Skipping port scanning", "yellow"))

    if not SKIP_SPIDER:
        content_discovery()
    else:
        print(colored("[!] Skipping content discovery", "yellow"))

    if not SKIP_VULNANALYSIS:
        analyze_vulnerabilities()
        categorize_endpoints()
    else:
        print(colored("[!] Skipping vulnerability analysis", "yellow"))

    if not SKIP_JSANALYSIS:
        js_analysis()
    else:
        print(colored("[!] Skipping JavaScript analysis", "yellow"))

    generate_report()
    cleanup()

    elapsed = time.time() - start_time
    h = int(elapsed // 3600)
    m = int((elapsed % 3600) // 60)
    s = int(elapsed % 60)

    print(colored(f"\n[+] Reconnaissance completed in {h}h {m}m {s}s", "green"))
    print(colored(f"[+] Results saved to: {RESULTS_DIR}", "green"))
    print(colored(f"[+] Report available at: {RESULTS_DIR / 'recon-report.md'}", "green"))


if __name__ == "__main__":
    main()