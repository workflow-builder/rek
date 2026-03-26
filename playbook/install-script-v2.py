# ╔═════════════════════════════════════════════════════════════╗
# ║  Recon Toolkit Installation Script (v2)                     ║
# ║  Installs Katana, HTTPX, Nuclei, and dependencies for       ║
# ║  Recon Playbook (v2)                                        ║
# ╚═════════════════════════════════════════════════════════════╝
# Python Cross-Platform Edition by jackb898


import os
import subprocess
import shutil
import sys
from pathlib import Path
import urllib.request
import platform
import tarfile

# Variables
WORKING_DIR = Path(os.environ.get("RECON_TOOLKIT_DIR", Path(__file__).parent))
TOOLS_DIR = Path(os.environ.get("TOOLS_DIR", WORKING_DIR / "tools"))
CONFIG_FILE = Path(os.environ.get("CONFIG_PATH", WORKING_DIR / "config.conf"))

# Function to check if a command exists
def command_exists(name):
    return shutil.which(name) is not None

# Function to check if a Go tool is installed
def go_tool_exists(name):
    if shutil.which(name):
        return True
    return False

# Function to detect system type
def detect_system():
    print("[+] Detecting operating system...")

    system = platform.system()

    if system == "Darwin":
        os_type = "macos"
        print("[+] macOS detected")
    elif system == "Windows":
        os_type = "windows"
        print("[+] Windows detected")
    elif system == "Linux":
        if Path("/etc/debian_version").exists():
            os_type = "debian"
            print("[+] Debian/Ubuntu detected")
        elif Path("/etc/redhat-release").exists():
            os_type = "rhel"
            print("[+] RHEL/CentOS/Fedora detected")
        elif Path("/etc/arch-release").exists():
            os_type = "arch"
            print("[+] Arch Linux detected")
        else:
            os_type = "linux"
            print("[!] Unknown Linux distro. Will attempt generic installation")
    else:
        os_type = "unknown"
        print("[!] Unknown operating system. Will attempt generic installation")

    return os_type

# Function to create required directories
def setup_directories():
    print("[+] Setting up directories...")
    WORKING_DIR.mkdir(parents=True, exist_ok=True)
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    print("[+] Directories set up successfully")

# Function to install basic dependencies
def install_basic_dependencies(os_type):
    print("[+] Installing basic dependencies...")

    if os_type == "macos":
        if not command_exists("brew"):
            print("[*] Installing Homebrew...")
            subprocess.run([
                "/bin/bash", "-c",
                "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            ])
        print("[*] Installing base packages...")
        subprocess.run(["brew", "install", "wget", "curl", "git", "coreutils"])

    elif os_type == "debian":
        print("[*] Updating package lists...")
        subprocess.run(["sudo", "apt", "update"])
        print("[*] Installing base packages...")
        subprocess.run(["sudo", "apt", "install", "-y", "wget", "curl", "git", "coreutils"])

    elif os_type == "rhel":
        print("[*] Installing base packages...")
        subprocess.run(["sudo", "yum", "install", "-y", "wget", "curl", "git", "coreutils"])

    elif os_type == "arch":
        print("[*] Installing base packages...")
        subprocess.run(["sudo", "pacman", "-Sy", "--noconfirm", "wget", "curl", "git", "coreutils"])

    elif os_type == "windows":
        # On Windows, recommend winget or chocolatey for git/curl if missing
        if not command_exists("git"):
            print("[!] git not found. Install from https://git-scm.com/download/win")
        if not command_exists("curl"):
            print("[!] curl not found. Install from https://curl.se/windows/")

    else:
        print("[!] Please install wget, curl, git, and coreutils manually")

    print("[+] Basic dependencies installed")

# Function to install Go
def install_go(os_type):
    print("[+] Installing Go...")

    if command_exists("go"):
        result = subprocess.run(["go", "version"], capture_output=True, text=True)
        version = result.stdout.strip().split()[2].replace("go", "")
        print(f"[+] Go is already installed (version {version})")
    else:
        if os_type == "macos":
            subprocess.run(["brew", "install", "golang"])

        elif os_type == "windows":
            print("[!] Go not installed. Download and install from https://go.dev/dl/")
            print("[!] After installing, re-run this script.")
            sys.exit(1)

        else:
            go_tarball = "go1.22.3.linux-amd64.tar.gz"
            print(f"[*] Downloading {go_tarball}...")
            urllib.request.urlretrieve(f"https://go.dev/dl/{go_tarball}", go_tarball)
            subprocess.run(["sudo", "tar", "-C", "/usr/local", "-xzf", go_tarball])
            Path(go_tarball).unlink()

            bashrc = Path.home() / ".bashrc"
            with open(bashrc, "a") as f:
                f.write("\nexport PATH=$PATH:/usr/local/go/bin\n")
                f.write("export PATH=$PATH:$HOME/go/bin\n")

            os.environ["PATH"] += os.pathsep + "/usr/local/go/bin"

        print("[+] Go installed successfully")

    # Ensure GOPATH is set
    gopath = os.environ.get("GOPATH", str(Path.home() / "go"))
    os.environ["GOPATH"] = gopath
    os.environ["PATH"] += os.pathsep + str(Path(gopath) / "bin")

    for d in ["bin", "pkg", "src"]:
        (Path(gopath) / d).mkdir(parents=True, exist_ok=True)

# Function to install ProjectDiscovery tools
def install_pd_tools():
    print("[+] Installing ProjectDiscovery tools...")

    if not command_exists("go"):
        print("[!] Go is not installed. Please install Go first")
        return

    # Ensure tools dir is on PATH
    os.environ["PATH"] += os.pathsep + str(TOOLS_DIR)

    for tool, pkg in [
        ("katana", "github.com/projectdiscovery/katana/cmd/katana@latest"),
        ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ]:
        if go_tool_exists(tool):
            print(f"[+] {tool} is already installed")
        else:
            print(f"[*] Installing {tool}...")
            result = subprocess.run(["go", "install", "-v", pkg])
            if result.returncode != 0:
                print(f"[!] Failed to install {tool}")

    print("[+] ProjectDiscovery tools installed")

# Function to create configuration file
def create_config():
    print("[+] Creating configuration file...")

    if CONFIG_FILE.exists():
        print("[+] Configuration file already exists")
        return

    threads = input("Default number of threads (default: 20): ") or "20"
    rate_limit = input("Default rate limit per second (default: 25): ") or "25"

    with open(CONFIG_FILE, "w") as f:
        f.write(f'THREADS="{threads}"\n')
        f.write(f'RATE_LIMIT="{rate_limit}"\n')

    print(f"[+] Configuration file created at {CONFIG_FILE}")

# Function to verify installation
def verify_installation(os_type):
    print("[+] Verifying installation...\n")

    tools = ["katana", "httpx", "nuclei"]

    # macOS uses gshuf from coreutils, others use shuf
    if os_type == "macos":
        tools.append("gshuf")
    else:
        tools.append("shuf")

    print(f"{'Tool':<20}{'Status'}")
    print(f"{'-'*20}{'-'*10}")

    all_ok = True

    for tool in tools:
        if command_exists(tool):
            print(f"{tool:<20}Installed")
        else:
            print(f"{tool:<20}Missing")
            all_ok = False

    if CONFIG_FILE.exists():
        print(f"{'config.conf':<20}Available")
    else:
        print(f"{'config.conf':<20}Missing")
        all_ok = False

    print()
    if all_ok:
        print("[+] All components verified successfully")
    else:
        print("[!] Some components are missing. Please review the installation logs")

def main():
    os_type = detect_system()
    setup_directories()
    install_basic_dependencies(os_type)
    install_go(os_type)
    install_pd_tools()
    create_config()
    verify_installation(os_type)

    print("\n[+] Installation completed successfully")
    print(f"[!] Please ensure your PATH includes {TOOLS_DIR} and {Path.home() / 'go' / 'bin'}")
    if os_type != "windows":
        print("[!] You may need to restart your terminal or source ~/.bashrc")
    print("[+] Ready to run the Recon Playbook (v2)")

if __name__ == "__main__":
    main()