#!/bin/bash

# ╔═════════════════════════════════════════════════════════════╗
# ║  Recon Toolkit Installation Script (v3)                     ║
# ║  Installs Shodan CLI and dependencies for Shodan Playbook   ║
# ╚═════════════════════════════════════════════════════════════╝

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                           ║"
echo "║        Recon Toolkit Installer (v3) - Setup for Shodan CLI                ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Variables
WORKING_DIR="${RECON_TOOLKIT_DIR:-$(dirname "$(realpath "$0")")}"
TOOLS_DIR="${TOOLS_DIR:-$WORKING_DIR/tools}"
CONFIG_FILE="${CONFIG_PATH:-$WORKING_DIR/config.conf}"
export PATH="$TOOLS_DIR:$HOME/.local/bin:$PATH"

# Function to detect system type
detect_system() {
    echo -e "${BLUE}[+] Detecting operating system...${NC}"
    
    if [ "$(uname)" == "Darwin" ]; then
        OS="macos"
        echo -e "${GREEN}[✓] macOS detected${NC}"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
        echo -e "${GREEN}[✓] Debian/Ubuntu detected${NC}"
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
        echo -e "${GREEN}[✓] RHEL/CentOS/Fedora detected${NC}"
    elif [ -f /etc/arch-release ]; then
        OS="arch"
        echo -e "${GREEN}[✓] Arch Linux detected${NC}"
    else
        OS="unknown"
        echo -e "${RED}[!] Unknown OS. Exiting.${NC}"
        exit 1
    fi
}

# Function to create required directories
setup_directories() {
    echo -e "${BLUE}[+] Setting up directories...${NC}"
    mkdir -p "$WORKING_DIR" "$TOOLS_DIR"
    echo -e "${GREEN}[✓] Directories set up successfully${NC}"
}

# Function to install basic dependencies
install_basic_dependencies() {
    echo -e "${BLUE}[+] Installing basic dependencies...${NC}"
    
    case $OS in
        macos)
            if ! command -v brew >/dev/null 2>&1; then
                echo -e "${YELLOW}[*] Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
                eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || /usr/local/bin/brew shellenv)"
            fi
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            brew install python3 coreutils || { echo -e "${RED}[!] Failed to install dependencies${NC}"; exit 1; }
            ;;
        debian)
            echo -e "${YELLOW}[*] Updating package lists...${NC}"
            sudo apt update || { echo -e "${RED}[!] Failed to update package lists${NC}"; exit 1; }
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            sudo apt install -y python3 python3-pip coreutils || { echo -e "${RED}[!] Failed to install dependencies${NC}"; exit 1; }
            ;;
        rhel)
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            sudo yum install -y python3 python3-pip coreutils || { echo -e "${RED}[!] Failed to install dependencies${NC}"; exit 1; }
            ;;
        arch)
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            sudo pacman -Sy --noconfirm python python-pip coreutils || { echo -e "${RED}[!] Failed to install dependencies${NC}"; exit 1; }
            ;;
    esac
    
    echo -e "${GREEN}[✓] Basic dependencies installed${NC}"
}

# Function to install Shodan CLI
install_shodan() {
    echo -e "${BLUE}[+] Installing Shodan CLI...${NC}"
    
    if command -v shodan >/dev/null 2>&1; then
        echo -e "${GREEN}[✓] Shodan CLI is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing Shodan CLI via pip...${NC}"
        python3 -m pip install --user shodan || { echo -e "${RED}[!] Failed to install Shodan CLI${NC}"; exit 1; }
        echo -e "${GREEN}[✓] Shodan CLI installed successfully${NC}"
    fi
}

# Function to check if Shodan CLI is initialized
check_shodan_init() {
    shodan info >/dev/null 2>&1
    return $?
}

# Function to prompt for Shodan API key
prompt_for_api_key() {
    echo -e "${YELLOW}[?] Enter your Shodan API key:${NC}"
    read -r SHODAN_API_KEY
    if [ -z "$SHODAN_API_KEY" ]; then
        echo -e "${RED}[!] No API key provided. Exiting.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}[*] Testing Shodan API key...${NC}"
    if ! shodan init "$SHODAN_API_KEY" >/dev/null 2>&1; then
        echo -e "${RED}[!] Invalid Shodan API key. Please try again.${NC}"
        prompt_for_api_key
    fi
    
    echo "SHODAN_API_KEY=\"$SHODAN_API_KEY\"" > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE" 2>/dev/null || echo -e "${YELLOW}[!] Warning: Could not set permissions on $CONFIG_FILE${NC}"
    echo -e "${GREEN}[✓] Configuration saved to $CONFIG_FILE${NC}"
}

# Function to create configuration file
create_config() {
    echo -e "${BLUE}[+] Creating configuration file...${NC}"
    
    if check_shodan_init; then
        echo -e "${GREEN}[✓] Shodan CLI is initialized${NC}"
        return 0
    fi
    
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        if [ -n "$SHODAN_API_KEY" ]; then
            echo -e "${YELLOW}[*] Initializing Shodan CLI with stored key...${NC}"
            if ! shodan init "$SHODAN_API_KEY" >/dev/null 2>&1; then
                echo -e "${YELLOW}[!] Stored API key invalid. Prompting for new key...${NC}"
                prompt_for_api_key
            fi
        else
            echo -e "${YELLOW}[!] Config file exists but SHODAN_API_KEY is empty${NC}"
            prompt_for_api_key
        fi
    else
        prompt_for_api_key
    fi
    
    echo -e "${GREEN}[✓] Configuration created${NC}"
}

# Function to verify installation
verify_installation() {
    echo -e "${BLUE}[+] Verifying installation...${NC}"
    
    local tools=("shodan")
    if [ "$OS" = "macos" ]; then
        tools+=("gshuf")
    else
        tools+=("shuf")
    fi
    
    printf "%-20s %-10s\n" "Tool" "Status"
    printf "%-20s %-10s\n" "--------------------" "----------"
    
    local all_tools_installed=true
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf "%-20s ${GREEN}%-10s${NC}\n" "$tool" "Installed"
        else
            printf "%-20s ${RED}%-10s${NC}\n" "$tool" "Missing"
            all_tools_installed=false
        fi
    done
    
    if check_shodan_init; then
        printf "%-20s ${GREEN}%-10s${NC}\n" "Shodan CLI Init" "Initialized"
    else
        printf "%-20s ${RED}%-10s${NC}\n" "Shodan CLI Init" "Not Init"
        all_tools_installed=false
    fi
    
    if [ -f "$CONFIG_FILE" ]; then
        printf "%-20s ${GREEN}%-10s${NC}\n" "config.conf" "Available"
    else
        printf "%-20s ${RED}%-10s${NC}\n" "config.conf" "Missing"
        all_tools_installed=false
    fi
    
    if [ "$all_tools_installed" = true ]; then
        echo -e "${GREEN}[✓] All components verified successfully${NC}"
    else
        echo -e "${RED}[!] Verification failed. Please re-run the script.${NC}"
        exit 1
    fi
}

# Main function
main() {
    detect_system
    setup_directories
    install_basic_dependencies
    install_shodan
    create_config
    verify_installation
    
    echo -e "\n${GREEN}[✓] Installation completed successfully${NC}"
    echo -e "${BLUE}[+] Ready to run the Shodan Recon Playbook (v3)${NC}"
}

main "$@"