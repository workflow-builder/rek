
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
echo "║        Recon Toolkit Installer - Setup your bug bounty environment       ║"
echo "║                                                                           ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Variables
WORKING_DIR="${RECON_TOOLKIT_DIR:-$(dirname "$(realpath "$0")")}"
TOOLS_DIR="${TOOLS_DIR:-$WORKING_DIR/tools}"
WORDLISTS_DIR="${WORDLISTS_DIR:-$WORKING_DIR/wordlists}"
CONFIG_FILE="${CONFIG_PATH:-$WORKING_DIR/config.conf}"
RESOLVERS_FILE="$WORKING_DIR/resolvers.txt"
GF_PATTERNS_DIR="$HOME/.gf"

# Function to check if a tool is installed
tool_installed() {
    command -v "$1" >/dev/null 2>&1
}

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
            if ! tool_installed "brew"; then
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
    
    if tool_installed "go"; then
        go_version=$(go version | awk '{print $3}' | sed 's/go//')
        echo -e "${GREEN}[✓] Go is already installed (version $go_version)${NC}"
    else
        case $OS in
            macos)
                brew install golang
                ;;
            debian)
                wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
                sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
                rm go1.22.3.linux-amd64.tar.gz
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
                echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.profile
                source ~/.profile
                ;;
            rhel)
                wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
                sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
                rm go1.22.3.linux-amd64.tar.gz
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
                echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
                source ~/.bashrc
                ;;
            arch)
                sudo pacman -S --noconfirm go
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
        echo -e "${YELLOW}[!] Please ensure Go binaries are in your PATH${NC}"
        echo -e "${YELLOW}[!] You may need to restart your terminal or run: source ~/.bashrc (or ~/.profile)${NC}"
    fi
    
    if [ -z "$GOPATH" ]; then
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin
        echo -e "${YELLOW}[*] Go environment variables set. You may need to restart your terminal${NC}"
    fi
    
    mkdir -p $HOME/go/{bin,pkg,src}
}

# Function to install Python tools
install_python_tools() {
    echo -e "${BLUE}[+] Installing Python tools and dependencies...${NC}"
    
    if ! tool_installed "pip3"; then
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
    
    pip3 install --upgrade pip
    pip3 install requests dnsgen tldextract dnspython
    
    echo -e "${GREEN}[✓] Python tools installed${NC}"
}

# Function to install Go tools
install_go_tools() {
    echo -e "${BLUE}[+] Installing Go tools...${NC}"
    
    if ! tool_installed "go"; then
        echo -e "${RED}[!] Go is not installed. Please install Go first${NC}"
        return 1
    fi
    
    export PATH=$PATH:$HOME/go/bin:$TOOLS_DIR
    
    if tool_installed "subfinder"; then
        echo -e "${GREEN}[✓] subfinder is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing subfinder...${NC}"
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    fi
    
    if tool_installed "assetfinder"; then
        echo -e "${GREEN}[✓] assetfinder is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing assetfinder...${NC}"
        go install -v github.com/tomnomnom/assetfinder@latest
    fi
    
    if tool_installed "httpx"; then
        echo -e "${GREEN}[✓] httpx is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing httpx...${NC}"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    fi
    
    if tool_installed "naabu"; then
        echo -e "${GREEN}[✓] naabu is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing naabu...${NC}"
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    fi
    
    if tool_installed "chaos"; then
        echo -e "${GREEN}[✓] chaos client is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing chaos client...${NC}"
        go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
    fi
    
    if tool_installed "gospider"; then
        echo -e "${GREEN}[✓] gospider is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing gospider...${NC}"
        go install -v github.com/jaeles-project/gospider@latest
    fi
    
    if tool_installed "katana"; then
        echo -e "${GREEN}[✓] katana is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing katana...${NC}"
        go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    fi
    
    if tool_installed "gau"; then
        echo -e "${GREEN}[✓] gau is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing gau...${NC}"
        go install -v github.com/lc/gau/v2/cmd/gau@latest
    fi
    
    if tool_installed "getjs"; then
        echo -e "${GREEN}[✓] getJS is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing getJS...${NC}"
        go install -v github.com/003random/getJS@latest
    fi
    
    if tool_installed "cariddi"; then
        echo -e "${GREEN}[✓] cariddi is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing cariddi...${NC}"
        go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest
    fi
    
    if tool_installed "goaltdns"; then
        echo -e "${GREEN}[✓] goaltdns is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing goaltdns...${NC}"
        go install -v github.com/subfinder/goaltdns@latest
    fi
    
    if tool_installed "gotator"; then
        echo -e "${GREEN}[✓] gotator is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing gotator...${NC}"
        go install -v github.com/Josue87/gotator@latest
    fi
    
    if tool_installed "ripgen"; then
        echo -e "${GREEN}[✓] ripgen is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing ripgen...${NC}"
        go install -v github.com/resyncgg/ripgen@latest
    fi
    
    if tool_installed "puredns"; then
        echo -e "${GREEN}[✓] puredns is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing puredns...${NC}"
        go install -v github.com/d3mondev/puredns/v2@latest
    fi
    
    if tool_installed "gf"; then
        echo -e "${GREEN}[✓] gf is already installed${NC}"
    else
        echo -e "${YELLOW}[*] Installing gf...${NC}"
        go install -v github.com/tomnomnom/gf@latest
    fi
    
    echo -e "${GREEN}[✓] Go tools installed successfully${NC}"
}

# Function to install Findomain
install_findomain() {
    echo -e "${BLUE}[+] Installing Findomain...${NC}"
    
    if tool_installed "findomain"; then
        echo -e "${GREEN}[✓] Findomain is already installed${NC}"
    else
        case $OS in
            macos)
                brew install findomain
                ;;
            *)
                curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux
                chmod +x findomain-linux
                mv findomain-linux "$TOOLS_DIR/findomain"
                ;;
        esac
        echo -e "${GREEN}[✓] Findomain installed${NC}"
    fi
}

# Function to install GF and patterns
install_gf_patterns() {
    echo -e "${BLUE}[+] Installing GF patterns...${NC}"
    
    if ! tool_installed "gf"; then
        echo -e "${YELLOW}[!] GF not found. Installing...${NC}"
        go install -v github.com/tomnomnom/gf@latest
    fi
    
    echo -e "${YELLOW}[*] Downloading GF patterns...${NC}"
    if [ -d "$GF_PATTERNS_DIR/Gf-Patterns" ]; then
        echo -e "${YELLOW}[!] $GF_PATTERNS_DIR/Gf-Patterns already exists. Updating...${NC}"
        git -C "$GF_PATTERNS_DIR/Gf-Patterns" pull
    else
        mkdir -p "$GF_PATTERNS_DIR"
        git clone https://github.com/1ndianl33t/Gf-Patterns "$GF_PATTERNS_DIR/Gf-Patterns"
    fi
    
    if [ -d "$GF_PATTERNS_DIR/Gf-Patterns" ]; then
        cp "$GF_PATTERNS_DIR/Gf-Patterns"/*.json "$GF_PATTERNS_DIR/"
    fi
    
    if [ -d "$TOOLS_DIR/gf-secrets" ]; then
        echo -e "${YELLOW}[!] $TOOLS_DIR/gf-secrets already exists. Updating...${NC}"
        git -C "$TOOLS_DIR/gf-secrets" pull
    else
        git clone https://github.com/dwisiswant0/gf-secrets "$TOOLS_DIR/gf-secrets"
    fi
    if [ -d "$TOOLS_DIR/gf-secrets/.gf" ]; then
        cp "$TOOLS_DIR/gf-secrets/.gf"/*.json "$GF_PATTERNS_DIR/"
    fi
    
    echo -e "${GREEN}[✓] GF patterns installed${NC}"
}

# Function to install github-subdomains and gitlab-subdomains
install_code_platform_tools() {
    echo -e "${BLUE}[+] Installing GitHub and GitLab subdomain tools...${NC}"
    
    echo -e "${YELLOW}[*] Installing github-subdomains...${NC}"
    if ! tool_installed "github-subdomains"; then
        if [ -d "$TOOLS_DIR/github-subdomains" ]; then
            echo -e "${YELLOW}[!] $TOOLS_DIR/github-subdomains already exists. Updating...${NC}"
            git -C "$TOOLS_DIR/github-subdomains" pull
        else
            git clone https://github.com/gwen001/github-subdomains.git "$TOOLS_DIR/github-subdomains"
        fi
        cd "$TOOLS_DIR/github-subdomains"
        go build
        mv github-subdomains "$TOOLS_DIR/"
        cd - > /dev/null
    else
        echo -e "${GREEN}[✓] github-subdomains is already installed${NC}"
    fi
    
    echo -e "${YELLOW}[*] Installing gitlab-subdomains...${NC}"
    if ! tool_installed "gitlab-subdomains"; then
        if [ -d "$TOOLS_DIR/gitlab-subdomains" ]; then
            echo -e "${YELLOW}[!] $TOOLS_DIR/gitlab-subdomains already exists. Updating...${NC}"
            git -C "$TOOLS_DIR/gitlab-subdomains" pull
        else
            git clone https://github.com/gwen001/gitlab-subdomains.git "$TOOLS_DIR/gitlab-subdomains"
        fi
        cd "$TOOLS_DIR/gitlab-subdomains"
        go build
        mv gitlab-subdomains "$TOOLS_DIR/"
        cd - > /dev/null
    else
        echo -e "${GREEN}[✓] gitlab-subdomains is already installed${NC}"
    fi
    
    echo -e "${GREEN}[✓] GitHub and GitLab tools installed${NC}"
}

# Function to download DNS resolvers
download_resolvers() {
    echo -e "${BLUE}[+] Downloading DNS resolvers...${NC}"
    
    if [ -f "$RESOLVERS_FILE" ]; then
        echo -e "${GREEN}[✓] DNS resolvers file already exists${NC}"
    else
        curl -s https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -o "$RESOLVERS_FILE"
        if [ -s "$RESOLVERS_FILE" ]; then
            echo -e "${GREEN}[✓] DNS resolvers downloaded${NC}"
        else
            echo -e "${RED}[!] Failed to download resolvers${NC}"
        fi
    fi
}

# Function to download wordlists
download_wordlists() {
    echo -e "${BLUE}[+] Downloading wordlists...${NC}"
    
    if [ ! -f "$WORDLISTS_DIR/dns_names.txt" ]; then
        echo -e "${YELLOW}[*] Downloading dns_names.txt...${NC}"
        curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns_names.txt -o "$WORDLISTS_DIR/dns_names.txt"
    else
        echo -e "${GREEN}[✓] dns_names.txt already exists${NC}"
    fi
    
    if [ ! -f "$WORDLISTS_DIR/subdomains-top1million-5000.txt" ]; then
        echo -e "${YELLOW}[*] Downloading subdomains-top1million-5000.txt...${NC}"
        curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -o "$WORDLISTS_DIR/subdomains-top1million-5000.txt"
    else
        echo -e "${GREEN}[✓] subdomains-top1million-5000.txt already exists${NC}"
    fi
    
    if [ ! -f "$WORDLISTS_DIR/raft-medium-directories.txt" ]; then
        echo -e "${YELLOW}[*] Downloading raft-medium-directories.txt...${NC}"
        curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt -o "$WORDLISTS_DIR/raft-medium-directories.txt"
    else
        echo -e "${GREEN}[✓] raft-medium-directories.txt already exists${NC}"
    fi
    
    echo -e "${GREEN}[✓] Wordlists downloaded${NC}"
}

# Function to create configuration file
create_config() {
    echo -e "${BLUE}[+] Creating configuration file...${NC}"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}[?] Enter your Chaos API key (leave blank if you don't have one):${NC}"
        read -r CHAOS_API_KEY
        
        echo -e "${YELLOW}[?] Enter your GitHub API token (leave blank if you don't have one):${NC}"
        read -r GITHUB_API_TOKEN
        
        echo -e "${YELLOW}[?] Enter your GitLab API token (leave blank if you don't have one):${NC}"
        read -r GITLAB_API_TOKEN
        
        echo -e "${YELLOW}[?] Default number of threads to use (default: 100):${NC}"
        read -r THREADS
        THREADS=${THREADS:-100}
        
        cat <<EOL > "$CONFIG_FILE"
CHAOS_API_KEY="$CHAOS_API_KEY"
GITHUB_API_TOKEN="$GITHUB_API_TOKEN"
GITLAB_API_TOKEN="$GITLAB_API_TOKEN"
THREADS="$THREADS"
EOL
        
        echo -e "${GREEN}[✓] Configuration file created at $CONFIG_FILE${NC}"
    else
        echo -e "${GREEN}[✓] Configuration file already exists${NC}"
    fi
}

# Function to verify installation
verify_installation() {
    echo -e "${BLUE}[+] Verifying installation...${NC}"
    
    local tools=(
        "subfinder"
        "assetfinder"
        "findomain"
        "chaos"
        "github-subdomains"
        "gitlab-subdomains"
        "httpx"
        "naabu"
        "gospider"
        "katana"
        "gau"
        "getjs"
        "cariddi"
        "dnsgen"
        "goaltdns"
        "gotator"
        "puredns"
        "gf"
        "ripgen"
    )
    
    printf "%-20s %-10s\n" "Tool" "Status"
    printf "%-20s %-10s\n" "--------------------" "----------"
    
    local all_tools_installed=true
    
    for tool in "${tools[@]}"; do
        if tool_installed "$tool"; then
            printf "%-20s ${GREEN}%-10s${NC}\n" "$tool" "Installed"
        else
            printf "%-20s ${RED}%-10s${NC}\n" "$tool" "Missing"
            all_tools_installed=false
        fi
    done
    
    if [ -f "$RESOLVERS_FILE" ]; then
        printf "%-20s ${GREEN}%-10s${NC}\n" "resolvers.txt" "Available"
    else
        printf "%-20s ${RED}%-10s${NC}\n" "resolvers.txt" "Missing"
        all_tools_installed=false
    fi
    
    if [ -d "$GF_PATTERNS_DIR" ]; then
        printf "%-20s ${GREEN}%-10s${NC}\n" "gf patterns" "Available"
    else
        printf "%-20s ${RED}%-10s${NC}\n" "gf patterns" "Missing"
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
        echo -e "${RED}[!] Some components are missing. Please review the installation logs${NC}"
    fi
}

# Main function
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
    create_config
    verify_installation
    
    echo -e "\n${GREEN}[✓] Installation completed successfully${NC}"
    echo -e "${YELLOW}[!] Please ensure your PATH includes $TOOLS_DIR and $HOME/go/bin${NC}"
    echo -e "${YELLOW}[!] You may need to restart your terminal or source your shell configuration${NC}"
    echo -e "${BLUE}[+] Ready to run the Modern Recon Playbook${NC}"
}

main "$@"
