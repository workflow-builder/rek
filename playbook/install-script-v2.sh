#!/bin/bash

# ╔═════════════════════════════════════════════════════════════╗
# ║  Recon Toolkit Installation Script (v2)                     ║
# ║  Installs Katana, HTTPX, Nuclei, and dependencies for       ║
# ║  Recon Playbook (v2)                                       ║
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
echo "║        Recon Toolkit Installer (v2) - Setup for Katana, HTTPX, Nuclei     ║"
echo "║                                                                           ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Variables
WORKING_DIR="${RECON_TOOLKIT_DIR:-$(dirname "$(realpath "$0")")}"
TOOLS_DIR="${TOOLS_DIR:-$WORKING_DIR/tools}"
CONFIG_FILE="${CONFIG_PATH:-$WORKING_DIR/config.conf}"

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
        echo -e "${YELLOW}[!] Unknown operating system. Will attempt generic Linux installation${NC}"
    fi
}

# Function to create required directories
setup_directories() {
    echo -e "${BLUE}[+] Setting up directories...${NC}"
    mkdir -p "$WORKING_DIR"
    mkdir -p "$TOOLS_DIR"
    echo -e "${GREEN}[✓] Directories set up successfully${NC}"
}

# Function to install basic dependencies
install_basic_dependencies() {
    echo -e "${BLUE}[+] Installing basic dependencies...${NC}"
    
    case $OS in
        macos)
            if ! command -v brew &> /dev/null; then
                echo -e "${YELLOW}[*] Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            brew install wget curl git coreutils
            ;;
        debian)
            echo -e "${YELLOW}[*] Updating package lists...${NC}"
            sudo apt update
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            sudo apt install -y wget curl git coreutils
            ;;
        rhel)
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            sudo yum install -y wget curl git coreutils
            ;;
        arch)
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            sudo pacman -Sy --noconfirm wget curl git coreutils
            ;;
        *)
            echo -e "${YELLOW}[!] Please install wget, curl, git, and coreutils manually${NC}"
            ;;
    esac
    
    echo -e "${GREEN}[✓] Basic dependencies installed${NC}"
}

# Function to install Go
install_go() {
    echo -e "${BLUE}[+] Installing Go...${NC}"
    
    if command -v go &> /dev/null; then
        go_version=$(go version | awk '{print $3}' | sed 's/go//')
        echo -e "${GREEN}[✓] Go is already installed (version $go_version)${NC}"
    else
        case $OS in
            macos)
                brew install golang
                ;;
            *)
                wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
                sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
                rm go1.22.3.linux-amd64.tar.gz
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
                echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
                source ~/.bashrc
                ;;
        esac
        echo -e "${GREEN}[✓] Go installed successfully${NC}"
    fi
    
    if [ -z "$GOPATH" ]; then
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin
    fi
    
    mkdir -p $HOME/go/{bin,pkg,src}
}

# Function to install ProjectDiscovery tools
install_pd_tools() {
    echo -e "${BLUE}[+] Installing ProjectDiscovery tools...${NC}"
    
    if ! command -v go &> /dev/null; then
        echo -e "${RED}[!] Go is not installed. Please install Go first${NC}"
        return 1
    fi
    
    export PATH=$PATH:$HOME/go/bin:$TOOLS_DIR
    
    local tools=(
        "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
        "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )
    
    for tool_entry in "${tools[@]}"; do
        IFS=':' read -r tool repo <<< "$tool_entry"
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}[✓] $tool is already installed${NC}"
        else
            echo -e "${YELLOW}[*] Installing $tool...${NC}"
            go install -v "$repo" || echo -e "${RED}[!] Failed to install $tool${NC}"
        fi
    done
    
    echo -e "${GREEN}[✓] ProjectDiscovery tools installed${NC}"
}

# Function to create configuration file
create_config() {
    echo -e "${BLUE}[+] Creating configuration file...${NC}"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}[?] Default number of threads (default: 20):${NC}"
        read -r THREADS
        THREADS=${THREADS:-20}
        
        echo -e "${YELLOW}[?] Default rate limit per second (default: 25):${NC}"
        read -r RATE_LIMIT
        RATE_LIMIT=${RATE_LIMIT:-25}
        
        cat <<EOL > "$CONFIG_FILE"
THREADS="$THREADS"
RATE_LIMIT="$RATE_LIMIT"
EOL
        
        echo -e "${GREEN}[✓] Configuration file created at $CONFIG_FILE${NC}"
    else
        echo -e "${GREEN}[✓] Configuration file already exists${NC}"
    fi
}

# Function to verify installation
verify_installation() {
    echo -e "${BLUE}[+] Verifying installation...${NC}"
    
    local tools=("katana" "httpx" "nuclei")
    if [ "$OS" = "macos" ]; then
        tools+=("gshuf")
    else
        tools+=("shuf")
    fi
    
    printf "%-20s %-10s\n" "Tool" "Status"
    printf "%-20s %-10s\n" "--------------------" "----------"
    
    local all_tools_installed=true
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            printf "%-20s ${GREEN}%-10s${NC}\n" "$tool" "Installed"
        else
            printf "%-20s ${RED}%-10s${NC}\n" "$tool" "Missing"
            all_tools_installed=false
        fi
    done
    
    if [ -f "$CONFIG_FILE" ]; then
        printf "%-20s ${GREEN}%-10s${NC}\n" "config.conf" "Available"
    else
        printf "%-20s ${RED}%-10s${NC}\n" "config.conf" "Missing"
        all_tools_installed=false
    fi
    
    if [ "$all_tools_installed" = true ]; then
        echo -e "${GREEN}[✓] All components verified successfully${NC}"
    else
        echo -e "${RED}[!] Some components are missing. Please review the installation logs${NC}"
    fi
}

# Main function
main() {
    detect_system
    setup_directories
    install_basic_dependencies
    install_go
    install_pd_tools
    create_config
    verify_installation
    
    echo -e "\n${GREEN}[✓] Installation completed successfully${NC}"
    echo -e "${YELLOW}[!] Please ensure your PATH includes $TOOLS_DIR and $HOME/go/bin${NC}"
    echo -e "${YELLOW}[!] You may need to restart your terminal or source ~/.bashrc${NC}"
    echo -e "${BLUE}[+] Ready to run the Recon Playbook (v2)${NC}"
}

main "$@"