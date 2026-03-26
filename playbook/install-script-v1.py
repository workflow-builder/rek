# ╔═════════════════════════════════════════════════════════════╗
# ║  Recon Toolkit Installation Script (v1)                     ║
# ║  Automates the installation of all prerequisites for the    ║
# ║  Modern Recon Playbook (v1)                                 ║
# ╚═════════════════════════════════════════════════════════════╝
# Python Cross-Platform Edition by jackb898


import os
import subprocess
import shutil
import sys
from pathlib import Path
import urllib.request
import platform

# Variables
TOOLS = [
    "subfinder",
    "assetfinder",
    "httpx",
    "naabu",
    "gau",
    "gf"
]

BASE_DIR = Path(__file__).parent.parent
TOOLS_DIR = BASE_DIR / "tools"
WORDLISTS_DIR = BASE_DIR / "wordlists"
RESOLVERS_FILE = BASE_DIR / "resolvers.txt"
FINDOMAIN_VERSION = "10.0.1"
GO_BIN = Path.home() / "go" / "bin"

# Function to check if a command exists
def command_exists(name):
    return shutil.which(name) is not None

# Function to check if a Go tool is installed
def go_tool_exists(name):
    home = os.path.expanduser("~")
    go_bin = os.path.join(home, "go", "bin")
    
    go_path = GO_BIN / name
    if go_path.exists():
        return True

    if name == "httpx":
        # Ignore system httpx (Python one)
        return False

    if shutil.which(name):
        return True

    possible_paths = [
        TOOLS_DIR / name,
        TOOLS_DIR / f"{name}.exe"
    ]

    return any(p.exists() for p in possible_paths)

# Function to create required directories
def setup_directories():
    TOOLS_DIR.mkdir(exist_ok=True)
    WORDLISTS_DIR.mkdir(exist_ok=True)

# Function to install Python tools
def install_python_tools():
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.run([
        sys.executable, "-m", "pip", "install",
        "requests", "dnsgen", "tldextract", "dnspython"
    ])

# Function to install Go and Go Tools
def install_go_tools():
    if not command_exists("go"):
        print("[!] Go not installed. Install from https://go.dev/dl/")
        return

    for tool, pkg in [
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
        ("gf", "github.com/tomnomnom/gf")
    ]:
        if go_tool_exists(tool):
            print(f"[+] {tool} already installed")
        else:
            print(f"[*] Installing {tool}...")
            subprocess.run(["go", "install", f"{pkg}@latest"])

# Function to install Findomain
def install_findomain():
    if command_exists("findomain"):
        print("[+] findomain already installed")
        return

    import zipfile
    system = platform.system()

    if system == "Windows":
        url = f"https://github.com/Findomain/Findomain/releases/download/{FINDOMAIN_VERSION}/findomain-windows.exe.zip"
        zip_path = TOOLS_DIR / "findomain.zip"
        output = TOOLS_DIR / "findomain.exe"
    elif system == "Darwin":
        print("[*] Installing via brew...")
        subprocess.run(["brew", "install", "findomain"])
        return
    else:
        url = f"https://github.com/Findomain/Findomain/releases/download/{FINDOMAIN_VERSION}/findomain-linux.zip"
        zip_path = TOOLS_DIR / "findomain.zip"
        output = TOOLS_DIR / "findomain"

    print("[*] Downloading findomain...")
    urllib.request.urlretrieve(url, zip_path)

    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(TOOLS_DIR)
    zip_path.unlink()

    if system != "Windows":
        os.chmod(output, 0o755)

    print(f"[+] findomain installed at {output}")

# Function to install GF and patterns
def install_gf_patterns():
    print("[+] Installing GF patterns...")

    # Ensure gf is installed
    if not go_tool_exists("gf"):
        print("[*] Installing gf...")
        subprocess.run(["go", "install", "github.com/tomnomnom/gf@latest"])

    # Set gf patterns directory (cross-platform)
    home = Path.home()
    gf_dir = home / ".gf"
    gf_dir.mkdir(exist_ok=True)

    # --- Clone Gf-Patterns ---
    gf_patterns_repo = gf_dir / "Gf-Patterns"

    if gf_patterns_repo.exists():
        print("[*] Updating Gf-Patterns...")
        subprocess.run(["git", "-C", str(gf_patterns_repo), "pull"])
    else:
        print("[*] Cloning Gf-Patterns...")
        subprocess.run([
            "git", "clone",
            "https://github.com/1ndianl33t/Gf-Patterns",
            str(gf_patterns_repo)
        ])

    # Copy JSON files
    for file in gf_patterns_repo.glob("*.json"):
        shutil.copy(file, gf_dir)

    # --- Clone gf-secrets ---
    gf_secrets_repo = TOOLS_DIR / "gf-secrets"

    if gf_secrets_repo.exists():
        print("[*] Updating gf-secrets...")
        subprocess.run(["git", "-C", str(gf_secrets_repo), "pull"])
    else:
        print("[*] Cloning gf-secrets...")
        subprocess.run([
            "git", "clone",
            "https://github.com/dwisiswant0/gf-secrets",
            str(gf_secrets_repo)
        ])

    # Copy secret patterns
    secrets_gf_dir = gf_secrets_repo / ".gf"
    if secrets_gf_dir.exists():
        for file in secrets_gf_dir.glob("*.json"):
            shutil.copy(file, gf_dir)

    print("[+] GF patterns installed")

# Function to install github-subdomains and gitlab-subdomains
def install_subdomain_tools():
    print("[+] Installing GitHub/GitLab subdomain tools...")

    repos = [
        ("github-subdomains", "https://github.com/gwen001/github-subdomains"),
        ("gitlab-subdomains", "https://github.com/gwen001/gitlab-subdomains"),
    ]

    for name, url in repos:
        repo_path = TOOLS_DIR / name

        if repo_path.exists():
            print(f"[*] Updating {name}...")
            subprocess.run(["git", "-C", str(repo_path), "pull"])
        else:
            print(f"[*] Cloning {name}...")
            subprocess.run(["git", "clone", url, str(repo_path)])

        result = subprocess.run(["go", "install", "./..."], cwd=str(repo_path))
        if result.returncode != 0:
            print(f"[!] Failed to build {name}")

    print("[+] Subdomain tools ready")

# Function to download DNS resolvers and wordlists
def download_wordlists():
    print("[+] Downloading wordlists and DNS resolver...")

    # Always attempt download (v1 behaviour — no skip if exists)
    print("[*] Downloading resolvers.txt...")
    urllib.request.urlretrieve(
        "https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt",
        RESOLVERS_FILE
    )
    if RESOLVERS_FILE.stat().st_size > 0:
        print("[+] DNS resolvers downloaded")
    else:
        print("[!] Failed to download resolvers")

    wordlists = [
        (
            "dns_names.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/namelist.txt"
        ),
        (
            "subdomains-top1million-5000.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
        ),
        (
            "raft-medium-directories.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"
        ),
    ]

    # Always download wordlists (v1 behaviour — no skip if exists)
    for filename, url in wordlists:
        path = WORDLISTS_DIR / filename
        print(f"[*] Downloading {filename}...")
        urllib.request.urlretrieve(url, path)

    print("[+] Wordlists ready")

# Function to create configuration file
def create_config():
    config_path = BASE_DIR / "config.conf"

    if config_path.exists():
        print("[+] Config exists")
        return

    chaos = input("Chaos API key (leave blank if you don't have one): ")
    github = input("GitHub token (leave blank if you don't have one): ")
    gitlab = input("GitLab token (leave blank if you don't have one): ")
    threads = input("Threads (default 100): ") or "100"

    with open(config_path, "w") as f:
        f.write(f"""CHAOS_API_KEY="{chaos}"
GITHUB_API_TOKEN="{github}"
GITLAB_API_TOKEN="{gitlab}"
THREADS="{threads}"
""")

# Function to verify installation
def verify_installation():
    print("[+] Verifying installation...\n")

    tools = [
        "subfinder",
        "assetfinder",
        "findomain",
        "chaos",
        "httpx",
        "naabu",
        "gospider",
        "katana",
        "gau",
        "getjs",
        "cariddi",
        "dnsgen",
        "goaltdns",
        "gotator",
        "puredns",
        "gf",
        "ripgen"
    ]

    # Special tools (handled differently)
    special_tools = {
        "github-subdomains": TOOLS_DIR / "github-subdomains" / "github-subdomains.py",
        "gitlab-subdomains": TOOLS_DIR / "gitlab-subdomains" / "gitlab-subdomains.py",
    }

    print(f"{'Tool':<25}{'Status'}")
    print(f"{'-'*25}{'-'*10}")

    all_ok = True

    # --- Normal tools ---
    for tool in tools:
        if command_exists(tool):
            print(f"{tool:<25}Installed")
        else:
            print(f"{tool:<25}Missing")
            all_ok = False

    # --- Special tools ---
    for name, path in special_tools.items():
        if path.exists():
            print(f"{name:<25}Installed")
        else:
            print(f"{name:<25}Missing")
            all_ok = False

    # --- Files ---
    checks = [
        ("resolvers.txt", RESOLVERS_FILE),
        ("config.conf", BASE_DIR / "config.conf"),
        ("gf patterns", Path.home() / ".gf"),
    ]

    for name, path in checks:
        if path.exists():
            print(f"{name:<25}Available")
        else:
            print(f"{name:<25}Missing")
            all_ok = False

    # --- Final result ---
    print()
    if all_ok:
        print("[+] All components verified successfully")
    else:
        print("[!] Some components are missing")

def main():
    setup_directories()
    install_python_tools()
    install_go_tools()
    install_findomain()
    install_gf_patterns()
    install_subdomain_tools()
    download_wordlists()
    create_config()
    verify_installation()

    print("\n[+] Ready to run the Modern Recon Playbook (v1)")

if __name__ == "__main__":
    main()

