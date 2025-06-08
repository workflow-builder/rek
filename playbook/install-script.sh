#!/bin/bash

# ╔═════════════════════════════════════════════════════════════╗
# ║  Recon Toolkit Installation Script                          ║
# ║  Automates the installation of all prerequisites for the    ║
# ║  Modern Recon Playbook                                      ║
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
echo "║        Recon Toolkit Installer - Setup your bug bounty environment        ║"
echo "║                                                                           ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Variables
WORKING_DIR="$HOME/recon-toolkit"
TOOLS_DIR="$WORKING_DIR/tools"
WORDLISTS_DIR="$WORKING_DIR/wordlists"
CONFIG_FILE="$WORKING_DIR/config.conf"
RESOLVERS_FILE="$WORKING_DIR/resolvers.txt"
GF_PATTERNS_DIR="$HOME/.gf"

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
    mkdir -p "$WORDLISTS_DIR"
    echo -e "${GREEN}[✓] Directories set up successfully${NC}"
}

# Function to install basic dependencies based on OS
install_basic_dependencies() {
    echo -e "${BLUE}[+] Installing basic dependencies...${NC}"
    
    case $OS in
        macos)
            echo -e "${YELLOW}[*] Installing Homebrew if not installed...${NC}"
            if ! command -v brew &> /dev/null; then
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            brew install wget curl git python3 make gcc jq
            ;;
        debian)
            echo -e "${YELLOW}[*] Updating package lists...${NC}"
            sudo apt update
            
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            sudo apt install -y wget curl git python3 python3-pip build-essential jq
            ;;
        rhel)
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            sudo yum install -y wget curl git python3 python3-pip gcc make jq
            ;;
        arch)
            echo -e "${YELLOW}[*] Installing base packages...${NC}"
            sudo pacman -Sy --noconfirm wget curl git python python-pip base-devel jq
            ;;
        *)
            echo -e "${YELLOW}[*] Attempting to install base packages...${NC}"
            echo -e "${YELLOW}[!] You may need to manually install: wget, curl, git, python3, pip3, gcc, make, jq${NC}"
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
            debian)
                wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
                sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
                rm go1.21.0.linux-amd64.tar.gz
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
                echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.profile
                source ~/.profile
                ;;
            rhel)
                wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
                sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
                rm go1.21.0.linux-amd64.tar.gz
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
                echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
                source ~/.bashrc
                ;;
            arch)
                sudo pacman -S --noconfirm go
                ;;
            *)
                wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
                sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
                rm go1.21.0.linux-amd64.tar.gz
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
                echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
                source ~/.bashrc
                ;;
        esac
        echo -e "${GREEN}[✓] Go installed successfully${NC}"
        echo -e "${YELLOW}[!] Please ensure Go binaries are in your PATH${NC}"
        echo -e "${YELLOW}[!] You may need to restart your terminal or run: source ~/.bashrc (or ~/.profile)${NC}"
    fi
    
    # Setup Go environment variables if not set
    if [ -z "$GOPATH" ]; then
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin
        echo -e "${YELLOW}[*] Go environment variables set. You may need to restart your terminal${NC}"
    fi
    
    # Create go directory structure
    mkdir -p $HOME/go/{bin,pkg,src}
}

# Function to install Python tools
install_python_tools() {
    echo -e "${BLUE}[+] Installing Python tools and dependencies...${NC}"
    
    # Ensure pip is available
    if ! command -v pip3 &> /dev/null; then
        case $OS in
            macos)
                brew install python3
                ;;
            debian)
                sudo apt install -y python3-pip
                ;;
            rhel)
                sudo yum install -y python3-pip
                ;;
            arch)
                sudo pacman -S --noconfirm python-pip
                ;;
            *)
                echo -e "${YELLOW}[!] Please install pip3 manually${NC}"
                ;;
        esac
    fi
    
    # Install Python packages
    pip3 install --upgrade pip
    pip3 install requests dnsgen tldextract dnspython
    
    echo -e "${GREEN}[✓] Python tools installed${NC}"
}

# Function to install Go tools
install_go_tools() {
    echo -e "${BLUE}[+] Installing Go tools...${NC}"
    
    # Make sure go is installed
    if ! command -v go &> /dev/null; then
        echo -e "${RED}[!] Go is not installed. Please install Go first${NC}"
        return 1
    fi
    
    # Make sure GOPATH/bin is in PATH
    export PATH=$PATH:$HOME/go/bin
    
    # Install tools
    echo -e "${YELLOW}[*] Installing subfinder...${NC}"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    
    echo -e "${YELLOW}[*] Installing assetfinder...${NC}"
    go install -v github.com/tomnomnom/assetfinder@latest
    
    echo -e "${YELLOW}[*] Installing httpx...${NC}"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    
    echo -e "${YELLOW}[*] Installing naabu...${NC}"
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    
    echo -e "${YELLOW}[*] Installing chaos client...${NC}"
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
    
    echo -e "${YELLOW}[*] Installing gospider...${NC}"
    go install -v github.com/jaeles-project/gospider@latest
    
    echo -e "${YELLOW}[*] Installing katana...${NC}"
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    
    echo -e "${YELLOW}[*] Installing gau...${NC}"
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    
    echo -e "${YELLOW}[*] Installing getJS...${NC}"
    go install -v github.com/003random/getJS@latest
    
    echo -e "${YELLOW}[*] Installing cariddi...${NC}"
    go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest
    
    echo -e "${YELLOW}[*] Installing goaltdns...${NC}"
    go install -v github.com/subfinder/goaltdns@latest
    
    echo -e "${YELLOW}[*] Installing gotator...${NC}"
    go install -v github.com/Josue87/gotator@latest
    
    echo -e "${YELLOW}[*] Installing ripgen...${NC}"
    go install -v github.com/resyncgg/ripgen/cmd/ripgen@latest
    
    echo -e "${YELLOW}[*] Installing puredns...${NC}"
    go install -v github.com/d3mondev/puredns/v2@latest
    
    echo -e "${YELLOW}[*] Installing gf...${NC}"
    go install -v github.com/tomnomnom/gf@latest
    
    echo -e "${GREEN}[✓] Go tools installed successfully${NC}"
}

# Function to install Findomain
install_findomain() {
    echo -e "${BLUE}[+] Installing Findomain...${NC}"
    
    if command -v findomain &> /dev/null; then
        echo -e "${GREEN}[✓] Findomain is already installed${NC}"
    else
        case $OS in
            macos)
                brew install findomain
                ;;
            *)
                curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux
                chmod +x findomain-linux
                sudo mv findomain-linux /usr/local/bin/findomain
                ;;
        esac
        echo -e "${GREEN}[✓] Findomain installed${NC}"
    fi
}

# Function to install GF and patterns
install_gf_patterns() {
    echo -e "${BLUE}[+] Installing GF patterns...${NC}"
    
    # Check if gf is installed
    if ! command -v gf &> /dev/null; then
        echo -e "${YELLOW}[!] GF not found. Installing...${NC}"
        go install -v github.com/tomnomnom/gf@latest
    fi
    
    # Create .gf directory if it doesn't exist
    mkdir -p "$GF_PATTERNS_DIR"
    
    # Clone GF patterns repositories
    echo -e "${YELLOW}[*] Downloading GF patterns...${NC}"
    git clone https://github.com/1ndianl33t/Gf-Patterns "$GF_PATTERNS_DIR/Gf-Patterns"
    
    # Copy pattern files to .gf directory
    if [ -d "$GF_PATTERNS_DIR/Gf-Patterns" ]; then
        cp "$GF_PATTERNS_DIR/Gf-Patterns"/*.json "$GF_PATTERNS_DIR/"
    fi
    
    # Clone and install additional patterns
    git clone https://github.com/dwisiswant0/gf-secrets "$TOOLS_DIR/gf-secrets"
    if [ -d "$TOOLS_DIR/gf-secrets/.gf" ]; then
        cp "$TOOLS_DIR/gf-secrets/.gf"/*.json "$GF_PATTERNS_DIR/"
    fi
    
    echo -e "${GREEN}[✓] GF patterns installed${NC}"
}

# Function to install github-subdomains and gitlab-subdomains
install_code_platform_tools() {
    echo -e "${BLUE}[+] Installing GitHub and GitLab subdomain tools...${NC}"
    
    # Install github-subdomains
    echo -e "${YELLOW}[*] Installing github-subdomains...${NC}"
    if ! command -v github-subdomains &> /dev/null; then
        git clone https://github.com/gwen001/github-subdomains.git "$TOOLS_DIR/github-subdomains"
        cd "$TOOLS_DIR/github-subdomains"
        go build
        cp github-subdomains $HOME/go/bin/
        cd - > /dev/null
    fi
    
    # Install gitlab-subdomains
    echo -e "${YELLOW}[*] Installing gitlab-subdomains...${NC}"
    if ! command -v gitlab-subdomains &> /dev/null; then
        git clone https://github.com/gwen001/gitlab-subdomains.git "$TOOLS_DIR/gitlab-subdomains"
        cd "$TOOLS_DIR/gitlab-subdomains"
        go build
        cp gitlab-subdomains $HOME/go/bin/
        cd - > /dev/null
    fi
    
    echo -e "${GREEN}[✓] GitHub and GitLab tools installed${NC}"
}

# Function to download DNS resolvers
download_resolvers() {
    echo -e "${BLUE}[+] Downloading DNS resolvers...${NC}"
    
    curl -s https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -o "$RESOLVERS_FILE"
    echo -e "${GREEN}[✓] Resolvers downloaded to $RESOLVERS_FILE${NC}"
    
    # Also download trusted resolvers for better accuracy
    curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt -o "$WORKING_DIR/resolvers-trusted.txt"
    echo -e "${GREEN}[✓] Trusted resolvers downloaded to $WORKING_DIR/resolvers-trusted.txt${NC}"
}

# Function to download useful wordlists
download_wordlists() {
    echo -e "${BLUE}[+] Downloading wordlists...${NC}"
    
    # Create wordlists directory if it doesn't exist
    mkdir -p "$WORDLISTS_DIR"
    
    # Download SecLists DNS subdomain lists
    echo -e "${YELLOW}[*] Downloading subdomain wordlists...${NC}"
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -o "$WORDLISTS_DIR/subdomains-top5000.txt"
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -o "$WORDLISTS_DIR/prefixes-top50000.txt"
    
    # Download path discovery wordlists
    echo -e "${YELLOW}[*] Downloading content discovery wordlists...${NC}"
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o "$WORDLISTS_DIR/common-paths.txt"
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api-endpoints.txt -o "$WORDLISTS_DIR/api-endpoints.txt"
    
    echo -e "${GREEN}[✓] Wordlists downloaded to $WORDLISTS_DIR${NC}"
}

# Function to setup configuration file
setup_config() {
    echo -e "${BLUE}[+] Setting up configuration file...${NC}"
    
    # Create a blank config if it doesn't exist
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}[*] Creating configuration file...${NC}"
        echo "# Recon Toolkit Configuration" > "$CONFIG_FILE"
        echo "# Created on $(date)" >> "$CONFIG_FILE"
        echo "CHAOS_API_KEY=\"\"" >> "$CONFIG_FILE"
        echo "GITHUB_API_TOKEN=\"\"" >> "$CONFIG_FILE"
        echo "GITLAB_API_TOKEN=\"\"" >> "$CONFIG_FILE"
        echo "THREADS=\"100\"" >> "$CONFIG_FILE"
    fi
    
    # Ask for API keys
    echo -e "${YELLOW}[?] Would you like to configure API keys now? (y/n)${NC}"
    read -r configure_keys
    
    if [[ "$configure_keys" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}[?] Enter your Chaos API key (leave blank to skip):${NC}"
        read -r chaos_key
        
        echo -e "${YELLOW}[?] Enter your GitHub API token (leave blank to skip):${NC}"
        read -r github_token
        
        echo -e "${YELLOW}[?] Enter your GitLab API token (leave blank to skip):${NC}"
        read -r gitlab_token
        
        # Update config file
        if [ -n "$chaos_key" ]; then
            sed -i.bak "s/CHAOS_API_KEY=\"\"/CHAOS_API_KEY=\"$chaos_key\"/" "$CONFIG_FILE"
        fi
        
        if [ -n "$github_token" ]; then
            sed -i.bak "s/GITHUB_API_TOKEN=\"\"/GITHUB_API_TOKEN=\"$github_token\"/" "$CONFIG_FILE"
        fi
        
        if [ -n "$gitlab_token" ]; then
            sed -i.bak "s/GITLAB_API_TOKEN=\"\"/GITLAB_API_TOKEN=\"$gitlab_token\"/" "$CONFIG_FILE"
        fi
        
        # Remove backup file
        rm -f "$CONFIG_FILE.bak"
    fi
    
    echo -e "${GREEN}[✓] Configuration setup complete${NC}"
}

# Function to download the recon playbook script
download_recon_playbook() {
    echo -e "${BLUE}[+] Downloading recon-playbook.sh...${NC}"
    
    curl -s https://raw.githubusercontent.com/yourusername/recon-playbook/main/recon-playbook.sh -o "$WORKING_DIR/recon-playbook.sh"
    chmod +x "$WORKING_DIR/recon-playbook.sh"
    
    echo -e "${GREEN}[✓] Recon playbook downloaded to $WORKING_DIR/recon-playbook.sh${NC}"
}

# Function to verify installation
verify_installation() {
    echo -e "${BLUE}[+] Verifying installation...${NC}"
    
    # Check if essential directories exist
    if [ -d "$WORKING_DIR" ] && [ -d "$TOOLS_DIR" ] && [ -d "$WORDLISTS_DIR" ]; then
        echo -e "${GREEN}[✓] Directory structure verified${NC}"
    else
        echo -e "${RED}[!] Directory structure is incomplete${NC}"
    fi
    
    # Check if configuration file exists
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "${GREEN}[✓] Configuration file verified${NC}"
    else
        echo -e "${RED}[!] Configuration file is missing${NC}"
    fi
    
    # Check if resolvers file exists
    if [ -f "$RESOLVERS_FILE" ]; then
        echo -e "${GREEN}[✓] Resolvers file verified${NC}"
    else
        echo -e "${RED}[!] Resolvers file is missing${NC}"
    fi
    
    # Check if Go is in PATH
    if command -v go &> /dev/null; then
        echo -e "${GREEN}[✓] Go installation verified${NC}"
    else
        echo -e "${RED}[!] Go is not installed or not in PATH${NC}"
    fi
    
    # Check if key tools are installed
    tools_missing=0
    for tool in subfinder assetfinder httpx naabu gospider katana gau getJS puredns gf; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}[!] Tool '$tool' is not installed or not in PATH${NC}"
            tools_missing=$((tools_missing + 1))
        fi
    done
    
    if [ $tools_missing -eq 0 ]; then
        echo -e "${GREEN}[✓] All core tools verified${NC}"
    else
        echo -e "${RED}[!] $tools_missing core tools are missing${NC}"
    fi
    
    # Overall verification
    if [ -d "$WORKING_DIR" ] && [ -f "$CONFIG_FILE" ] && [ -f "$RESOLVERS_FILE" ] && command -v go &> /dev/null && [ $tools_missing -eq 0 ]; then
        echo -e "\n${GREEN}[✓] Installation verified successfully!${NC}"
    else
        echo -e "\n${YELLOW}[!] Installation has issues that need to be addressed${NC}"
    fi
}

# Function to create convenient tool symlinks
create_symlinks() {
    echo -e "${BLUE}[+] Creating convenient symlinks...${NC}"
    
    # Check if user has sudo privileges
    if [ "$(id -u)" -eq 0 ] || command -v sudo &> /dev/null; then
        # Create symlink to recon-playbook.sh
        if [ -f "$WORKING_DIR/recon-playbook.sh" ]; then
            if command -v sudo &> /dev/null; then
                sudo ln -sf "$WORKING_DIR/recon-playbook.sh" /usr/local/bin/recon-playbook
            else
                ln -sf "$WORKING_DIR/recon-playbook.sh" /usr/local/bin/recon-playbook
            fi
            echo -e "${GREEN}[✓] Symlink created: you can now run 'recon-playbook' from anywhere${NC}"
        else
            echo -e "${RED}[!] recon-playbook.sh not found, skipping symlink creation${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Cannot create symlinks without sudo privileges${NC}"
    fi
}

# Function to display summary
display_summary() {
    echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                        Installation Summary                               ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${GREEN}✓ Recon toolkit installed successfully!${NC}"
    echo -e "\n${YELLOW}Key locations:${NC}"
    echo -e "  • Working directory: $WORKING_DIR"
    echo -e "  • Tools directory: $TOOLS_DIR"
    echo -e "  • Wordlists: $WORDLISTS_DIR"
    echo -e "  • Configuration: $CONFIG_FILE"
    
    echo -e "\n${YELLOW}Usage:${NC}"
    echo -e "  • Run the recon playbook: $WORKING_DIR/recon-playbook.sh"
    if [ -f "/usr/local/bin/recon-playbook" ]; then
        echo -e "  • Or simply type: recon-playbook"
    fi
    
    echo -e "\n${YELLOW}Next steps:${NC}"
    echo -e "  1. Ensure all API keys are configured in $CONFIG_FILE"
    
    if [ "$(id -u)" -ne 0 ] && ! command -v sudo &> /dev/null; then
        echo -e "  2. Consider running parts of this script with sudo to create system-wide symlinks"
    fi
    
    echo -e "  3. Run your first recon: $WORKING_DIR/recon-playbook.sh -d example.com"
    
    echo -e "\n${BLUE}Happy hunting!${NC}"
}

# Main installation function
main() {
    detect_system
    setup_directories
    install_basic_dependencies
    install_go
    install_python_tools
    install_go_tools
    install_findomain
    install_gf_patterns
    install_code_platform_tools
    download_resolvers
    download_wordlists
    setup_config
    # download_recon_playbook  # Uncomment if you want to download the script
    verify_installation
    create_symlinks
    display_summary
}

# Run the main function
main
