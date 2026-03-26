#!/bin/bash

# ╔═════════════════════════════════════════════════════════════╗
# ║  Modern Recon Playbook for Bug Bounty Hunters (v1)          ║
# ║  Automated reconnaissance pipeline based on Open sources    ║
# ║  methodology                                                ║
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
echo "║   From Subdomains to Secrets: A Modern Recon Playbook for Bug Hunters (v1)║"
echo "║                                                                           ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Variables
WORKING_DIR="${RECON_TOOLKIT_DIR:-$(dirname "$(realpath "$0")")}"
TOOLS_DIR="${TOOLS_DIR:-$WORKING_DIR/tools}"
OUTPUT_DIR=""
TARGET_DOMAIN=""
CONFIG_FILE="${CONFIG_PATH:-$WORKING_DIR/config.conf}"
API_KEYS=()
RESOLVERS_FILE="$WORKING_DIR/resolvers.txt"
THREADS=250
WORDLISTS_DIR="${WORDLISTS_DIR:-$WORKING_DIR/wordlists}"
RESULTS_DIR=""
export PATH="$TOOLS_DIR:$HOME/go/bin:$PATH"

# Create required directories
setup_directories() {
    echo -e "${BLUE}[+] Setting up directories...${NC}"
    mkdir -p "$WORKING_DIR"
    mkdir -p "$TOOLS_DIR"
    mkdir -p "$WORDLISTS_DIR"
    
    timestamp=$(date +"%Y%m%d-%H%M%S")
    RESULTS_DIR="$WORKING_DIR/results/$TARGET_DOMAIN-$timestamp"
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$RESULTS_DIR/subdomains"
    mkdir -p "$RESULTS_DIR/endpoints"
    mkdir -p "$RESULTS_DIR/js"
    mkdir -p "$RESULTS_DIR/vulnerabilities"
    
    echo -e "${GREEN}[✓] Directories set up successfully${NC}"
    echo -e "${GREEN}[✓] Results will be saved to: $RESULTS_DIR${NC}"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a Go tool is installed
go_tool_exists() {
    if command_exists go; then
        if [ -x "$(command -v "$1")" ]; then
            return 0
        fi
    fi
    return 1
}

# Function to install Go
install_go() {
    echo -e "${YELLOW}[*] Installing Go...${NC}"
    if [ "$(uname)" == "Darwin" ]; then
        brew install golang
    elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
        wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
        rm go1.22.3.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.profile
        source ~/.profile
    fi
    echo -e "${GREEN}[✓] Go installed successfully${NC}"
}

# Function to install required tools
install_tools() {
    echo -e "${BLUE}[+] Installing required tools...${NC}"
    
    if ! command_exists go; then
        install_go
    fi
    
    if command_exists pip3; then
        echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
        pip3 install requests dnsgen tldextract dnspython
    fi
    
    if command_exists go; then
        for tool in subfinder assetfinder findomain chaos httpx naabu gospider katana gau getjs cariddi goaltdns gotator puredns gf ripgen; do
            if ! go_tool_exists "$tool"; then
                echo -e "${YELLOW}[*] Installing $tool...${NC}"
                case $tool in
                    subfinder) go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ;;
                    assetfinder) go install -v github.com/tomnomnom/assetfinder@latest ;;
                    findomain)
                        if [ "$(uname)" == "Darwin" ]; then
                            brew install findomain
                        else
                            curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux
                            chmod +x findomain-linux
                            mv findomain-linux "$TOOLS_DIR/findomain"
                        fi
                        ;;
                    chaos) go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest ;;
                    httpx) go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest ;;
                    naabu) go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest ;;
                    gospider) go install -v github.com/jaeles-project/gospider@latest ;;
                    katana) go install -v github.com/projectdiscovery/katana/cmd/katana@latest ;;
                    gau) go install -v github.com/lc/gau/v2/cmd/gau@latest ;;
                    getjs) go install -v github.com/003random/getJS@latest ;;
                    cariddi) go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest ;;
                    goaltdns) go install -v github.com/subfinder/goaltdns@latest ;;
                    gotator) go install -v github.com/Josue87/gotator@latest ;;
                    puredns) go install -v github.com/d3mondev/puredns/v2@latest ;;
                    gf) go install -v github.com/tomnomnom/gf@latest ;;
                    ripgen) go install -v github.com/resyncgg/ripgen@latest ;;
                    nuclei) go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest ;;
                    subzy) go install -v github.com/PentestPad/subzy@latest ;;
                    waybackurls) go install -v github.com/tomnomnom/waybackurls@latest ;;
                    asnmap) go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest ;;
                    arjun) pip3 install arjun 2>/dev/null || true ;;
                esac
            fi
        done
        
        if ! command_exists github-subdomains; then
            echo -e "${YELLOW}[*] Installing github-subdomains...${NC}"
            if [ -d "$TOOLS_DIR/github-subdomains" ]; then
                git -C "$TOOLS_DIR/github-subdomains" pull
            else
                git clone https://github.com/gwen001/github-subdomains.git "$TOOLS_DIR/github-subdomains"
            fi
            cd "$TOOLS_DIR/github-subdomains"
            go build
            mv github-subdomains "$TOOLS_DIR/"
            cd - > /dev/null
        fi
        
        if ! command_exists gitlab-subdomains; then
            echo -e "${YELLOW}[*] Installing gitlab-subdomains...${NC}"
            if [ -d "$TOOLS_DIR/gitlab-subdomains" ]; then
                git -C "$TOOLS_DIR/gitlab-subdomains" pull
            else
                git clone https://github.com/gwen001/gitlab-subdomains.git "$TOOLS_DIR/gitlab-subdomains"
            fi
            cd "$TOOLS_DIR/gitlab-subdomains"
            go build
            mv gitlab-subdomains "$TOOLS_DIR/"
            cd - > /dev/null
        fi
    fi
    
    if [ ! -f "$RESOLVERS_FILE" ]; then
        echo -e "${YELLOW}[*] Downloading resolvers...${NC}"
        curl -s https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -o "$RESOLVERS_FILE"
    fi
    
    echo -e "${GREEN}[✓] Tools installation completed${NC}"
}

# Function to check prerequisites and display status
check_prerequisites() {
    echo -e "${BLUE}[+] Checking prerequisites...${NC}"
    
    printf "%-20s %-10s\n" "Tool" "Status"
    printf "%-20s %-10s\n" "--------------------" "----------"
    
    local all_tools_installed=true
    
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
        "nuclei"
        "subzy"
        "waybackurls"
        "asnmap"
        "arjun"
    )
    
    for tool in "${tools[@]}"; do
        if command_exists "$tool" || go_tool_exists "$tool"; then
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
    
    if [ -d "$HOME/.gf" ]; then
        printf "%-20s ${GREEN}%-10s${NC}\n" "gf patterns" "Available"
    else
        printf "%-20s ${RED}%-10s${NC}\n" "gf patterns" "Missing"
        all_tools_installed=false
    fi
    
    if [ "$all_tools_installed" = false ]; then
        echo -e "\n${YELLOW}[!] Some prerequisites are missing. Would you like to install them? (y/n)${NC}"
        read -r install_choice
        if [[ "$install_choice" =~ ^[Yy]$ ]]; then
            install_tools
        else
            echo -e "${RED}[!] Missing prerequisites might cause errors during execution${NC}"
        fi
    else
        echo -e "\n${GREEN}[✓] All prerequisites are installed${NC}"
    fi
}

# Function to load configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "${BLUE}[+] Loading configuration...${NC}"
        source "$CONFIG_FILE"
        echo -e "${GREEN}[✓] Configuration loaded${NC}"
    else
        echo -e "${YELLOW}[!] Configuration file not found. Creating new one...${NC}"
        
        echo -e "${YELLOW}[?] Enter your Chaos API key (leave blank if you don't have one):${NC}"
        read -r CHAOS_API_KEY
        
        echo -e "${YELLOW}[?] Enter your GitHub API token (leave blank if you don't have one):${NC}"
        read -r GITHUB_API_TOKEN
        
        echo -e "${YELLOW}[?] Enter your GitLab API token (leave blank if you don't have one):${NC}"
        read -r GITLAB_API_TOKEN
        
        echo -e "${YELLOW}[?] Default number of threads to use (default: 250):${NC}"
        read -r input_threads
        
        if [ -n "$input_threads" ]; then
            THREADS="$input_threads"
        fi
        
        echo "CHAOS_API_KEY=\"$CHAOS_API_KEY\"" > "$CONFIG_FILE"
        echo "GITHUB_API_TOKEN=\"$GITHUB_API_TOKEN\"" >> "$CONFIG_FILE"
        echo "GITLAB_API_TOKEN=\"$GITLAB_API_TOKEN\"" >> "$CONFIG_FILE"
        echo "THREADS=\"$THREADS\"" >> "$CONFIG_FILE"
        
        echo -e "${GREEN}[✓] Configuration saved${NC}"
    fi
}

# Function to get target domain from user
get_target_domain() {
    echo -e "${YELLOW}[?] Enter the target domain (e.g., example.com):${NC}"
    read -r TARGET_DOMAIN
    
    if [ -z "$TARGET_DOMAIN" ]; then
        echo -e "${RED}[!] No domain provided. Exiting.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[✓] Target domain set to: $TARGET_DOMAIN${NC}"
}

# Function to refresh resolvers
refresh_resolvers() {
    echo -e "${YELLOW}[*] Refreshing DNS resolvers...${NC}"
    curl -s https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -o "$RESOLVERS_FILE"
    if [ -s "$RESOLVERS_FILE" ]; then
        echo -e "${GREEN}[✓] Resolvers refreshed${NC}"
    else
        echo -e "${RED}[!] Failed to refresh resolvers${NC}"
    fi
}

# Phase 0: Cloud Asset Discovery
cloud_asset_discovery() {
    echo -e "\n${BLUE}[+] Phase 0: Cloud Asset Discovery (S3/Azure/GCP)${NC}"
    mkdir -p "$RESULTS_DIR/cloud"
    cd "$RESULTS_DIR/cloud"

    echo -e "${YELLOW}[*] Running cloud bucket enumeration via Python module...${NC}"
    python3 -c "
import sys, os
sys.path.insert(0, '$WORKING_DIR')
try:
    from rek_cloud_recon import CloudRecon
    recon = CloudRecon(timeout=10, concurrency=50, silent=False)
    recon.run('$TARGET_DOMAIN', 'cloud_assets.csv')
except ImportError:
    print('[!] rek_cloud_recon.py not available, skipping cloud recon')
except Exception as e:
    print(f'[!] Cloud recon error: {e}')
" 2>&1 || echo -e "${YELLOW}[!] Cloud recon skipped${NC}"

    echo -e "${GREEN}[✓] Cloud asset discovery completed${NC}"
    cd "$RESULTS_DIR"
}

# Step 1: Subdomain Enumeration
subdomain_enumeration() {
    echo -e "\n${BLUE}[+] Step 1: Subdomain Enumeration${NC}"
    cd "$RESULTS_DIR/subdomains"
    
    echo -e "${YELLOW}[*] Running subfinder...${NC}"
    subfinder -d "$TARGET_DOMAIN" -all -recursive -silent -o subPrecursive.txt || echo -e "${RED}[!] subfinder failed${NC}"
    
    echo -e "${YELLOW}[*] Running assetfinder...${NC}"
    echo "$TARGET_DOMAIN" | assetfinder -subs-only | tee assetf.txt || echo -e "${RED}[!] assetfinder failed${NC}"
    
    echo -e "${YELLOW}[*] Running findomain...${NC}"
    findomain -t "$TARGET_DOMAIN" --quiet | tee findomain.txt || echo -e "${RED}[!] findomain failed${NC}"
    
    if [ -n "$CHAOS_API_KEY" ]; then
        echo -e "${YELLOW}[*] Running chaos...${NC}"
        chaos -key "$CHAOS_API_KEY" -d "$TARGET_DOMAIN" -o chaos.txt || echo -e "${RED}[!] chaos failed${NC}"
    else
        echo -e "${YELLOW}[!] Chaos API key not provided, skipping...${NC}"
    fi
    
    if [ -n "$GITHUB_API_TOKEN" ]; then
        echo -e "${YELLOW}[*] Running github-subdomains...${NC}"
        github-subdomains -d "$TARGET_DOMAIN" -t "$GITHUB_API_TOKEN" > github-subs.txt || echo -e "${RED}[!] github-subdomains failed${NC}"
    else
        echo -e "${YELLOW}[!] GitHub API token not provided, skipping github-subdomains...${NC}"
    fi
    
    if [ -n "$GITLAB_API_TOKEN" ]; then
        echo -e "${YELLOW}[*] Running gitlab-subdomains...${NC}"
        gitlab-subdomains -d "$TARGET_DOMAIN" -t "$GITLAB_API_TOKEN" > gitlab-subs.txt || echo -e "${RED}[!] gitlab-subdomains failed${NC}"
    else
        echo -e "${YELLOW}[!] GitLab API token not provided, skipping gitlab-subdomains...${NC}"
    fi
    
    echo -e "${YELLOW}[*] Consolidating and deduplicating results...${NC}"
    cat *.txt 2>/dev/null | sort -u | tee sorted-subdomains.txt
    
    total_subdomains=$(wc -l < sorted-subdomains.txt)
    echo -e "${GREEN}[✓] Subdomain enumeration completed. Found $total_subdomains unique subdomains${NC}"
}

# Step 2: Subdomain Permutation and Bruteforce
subdomain_permutation() {
    echo -e "\n${BLUE}[+] Step 2: Subdomain Permutation and Bruteforce${NC}"
    cd "$RESULTS_DIR/subdomains"
    
    echo -e "${YELLOW}[*] Generating permutation wordlist...${NC}"
    cat sorted-subdomains.txt | tr . '\n' | sort -n | uniq > perm
    cat sorted-subdomains.txt | sed 's/[.]/-/g' | awk -F '-' '{for(i=1;i<=NF;i++){print $i}}' | sort -u >> perm
    
    echo -e "${YELLOW}[*] Running dnsgen...${NC}"
    cat sorted-subdomains.txt | dnsgen - > output-dnsgen.txt || echo -e "${RED}[!] dnsgen failed${NC}"
    
    echo -e "${YELLOW}[*] Running goaltdns...${NC}"
    if command_exists goaltdns; then
        goaltdns -w perm -l sorted-subdomains.txt -o output-goaltdns.txt || echo -e "${RED}[!] goaltdns failed${NC}"
    else
        echo -e "${RED}[!] goaltdns not found, skipping...${NC}"
    fi
    
    echo -e "${YELLOW}[*] Running gotator...${NC}"
    if command_exists gotator; then
        gotator -sub sorted-subdomains.txt -perm perm -depth 1 -numbers 1 > output-gotator.txt || echo -e "${RED}[!] gotator failed${NC}"
    else
        echo -e "${RED}[!] gotator not found, skipping...${NC}"
    fi
    
    echo -e "${YELLOW}[*] Running ripgen...${NC}"
    if command_exists ripgen; then
        cat sorted-subdomains.txt | ripgen > output-ripgen.txt || echo -e "${RED}[!] ripgen failed${NC}"
    else
        echo -e "${RED}[!] ripgen not found, skipping...${NC}"
    fi
    
    echo -e "${YELLOW}[*] Merging permutation results...${NC}"
    cat output*.txt 2>/dev/null | sort -u > output.txt
    
    echo -e "${YELLOW}[*] Refreshing resolvers...${NC}"
    refresh_resolvers
    
    echo -e "${YELLOW}[*] Resolving permutated subdomains...${NC}"
    if command_exists puredns; then
        cat output.txt | puredns resolve --resolvers "$RESOLVERS_FILE" > subdomains-permutated.txt || echo -e "${RED}[!] puredns failed${NC}"
    else
        echo -e "${RED}[!] puredns not found, skipping resolution...${NC}"
    fi
    
    echo -e "${YELLOW}[*] Merging all subdomains...${NC}"
    if [ -f "subdomains-permutated.txt" ]; then
        cat sorted-subdomains.txt subdomains-permutated.txt | sort -u | tee sorted-subs.txt
    else
        cp sorted-subdomains.txt sorted-subs.txt
    fi
    
    total_subdomains=$(wc -l < sorted-subs.txt)
    echo -e "${GREEN}[✓] Subdomain permutation completed. Found $total_subdomains total unique subdomains${NC}"
}

# Phase 2.5: ASN / IP Range Expansion
asn_expansion() {
    echo -e "\n${BLUE}[+] Phase 2.5: ASN / IP Range Expansion${NC}"
    cd "$RESULTS_DIR/subdomains"

    if command_exists asnmap; then
        echo -e "${YELLOW}[*] Running asnmap for ASN enumeration...${NC}"
        asnmap -d "$TARGET_DOMAIN" -silent -o asnmap_cidrs.txt 2>/dev/null || echo -e "${RED}[!] asnmap failed${NC}"
        if [ -s asnmap_cidrs.txt ]; then
            echo -e "${GREEN}[✓] ASN CIDRs saved: $(wc -l < asnmap_cidrs.txt) ranges${NC}"
        fi
    else
        echo -e "${YELLOW}[*] asnmap not found, using Python ASN module...${NC}"
        python3 -c "
import sys
sys.path.insert(0, '$WORKING_DIR')
try:
    from rek_asn import ASNRecon
    recon = ASNRecon(timeout=15, silent=False)
    results = recon.run('$TARGET_DOMAIN', 'asn_$TARGET_DOMAIN.csv')
except ImportError:
    print('[!] rek_asn.py not available')
except Exception as e:
    print(f'[!] ASN recon error: {e}')
" 2>&1 || true
    fi

    echo -e "${GREEN}[✓] ASN expansion completed${NC}"
    cd "$RESULTS_DIR"
}

# Step 3: Identify Live Subdomains and Fingerprint Applications
identify_live_subdomains() {
    echo -e "\n${BLUE}[+] Step 3: Identifying Live Subdomains${NC}"
    cd "$RESULTS_DIR/subdomains"
    
    echo -e "${YELLOW}[*] Running httpx to identify live subdomains...${NC}"
    httpx -l sorted-subs.txt -threads 250 -o subs-alive.txt || echo -e "${RED}[!] httpx failed${NC}"
    
    echo -e "${YELLOW}[*] Fingerprinting live subdomains...${NC}"
    httpx -l subs-alive.txt -title -sc -td -server -fr -probe -location -o httpx-output.txt || echo -e "${RED}[!] httpx failed${NC}"
    
    total_live=$(wc -l < subs-alive.txt)
    echo -e "${GREEN}[✓] Live subdomain identification completed. Found $total_live live subdomains${NC}"
}

# Phase 3.5: Subdomain Takeover Detection
takeover_detection() {
    echo -e "\n${BLUE}[+] Phase 3.5: Subdomain Takeover Detection${NC}"
    cd "$RESULTS_DIR/subdomains"

    if command_exists subzy; then
        echo -e "${YELLOW}[*] Running subzy for takeover detection...${NC}"
        subzy run --targets subs-alive.txt --output "$RESULTS_DIR/vulnerabilities/takeover-subzy.json" 2>/dev/null \
            || echo -e "${RED}[!] subzy failed${NC}"
    fi

    echo -e "${YELLOW}[*] Running Python takeover checker...${NC}"
    python3 -c "
import sys
sys.path.insert(0, '$WORKING_DIR')
try:
    from rek_takeover import TakeoverDetector
    detector = TakeoverDetector(timeout=10, concurrency=50, silent=False)
    detector.run(input_file='subs-alive.txt', output_file='$RESULTS_DIR/vulnerabilities/takeover.csv')
except ImportError:
    print('[!] rek_takeover.py not available')
except Exception as e:
    print(f'[!] Takeover detection error: {e}')
" 2>&1 || true

    echo -e "${GREEN}[✓] Takeover detection completed${NC}"
    cd "$RESULTS_DIR"
}

# Phase 3.6: Favicon Fingerprinting
favicon_fingerprinting() {
    echo -e "\n${BLUE}[+] Phase 3.6: Favicon Fingerprinting${NC}"
    cd "$RESULTS_DIR"

    python3 -c "
import sys
sys.path.insert(0, '$WORKING_DIR')
try:
    from rek_favicon import FaviconScanner
    scanner = FaviconScanner(timeout=10, concurrency=30, silent=False)
    scanner.run(input_file='subdomains/subs-alive.txt', output_file='vulnerabilities/favicon_hashes.csv')
except ImportError:
    print('[!] rek_favicon.py not available')
except Exception as e:
    print(f'[!] Favicon scan error: {e}')
" 2>&1 || true

    echo -e "${GREEN}[✓] Favicon fingerprinting completed${NC}"
}

# Phase 3.7: CORS / Security Headers Audit
headers_audit() {
    echo -e "\n${BLUE}[+] Phase 3.7: CORS / Security Headers Audit${NC}"
    cd "$RESULTS_DIR"

    python3 -c "
import sys, re
sys.path.insert(0, '$WORKING_DIR')
sys.modules.setdefault('re', re)
try:
    from rek_headers_audit import HeadersAuditor
    auditor = HeadersAuditor(timeout=10, concurrency=30, silent=False)
    auditor.run(input_file='subdomains/subs-alive.txt', output_file='vulnerabilities/headers_audit.csv')
except ImportError:
    print('[!] rek_headers_audit.py not available')
except Exception as e:
    print(f'[!] Headers audit error: {e}')
" 2>&1 || true

    echo -e "${GREEN}[✓] Headers audit completed${NC}"
}

# Step 4: Port Scanning
port_scanning() {
    echo -e "\n${BLUE}[+] Step 4: Port Scanning${NC}"
    cd "$RESULTS_DIR/subdomains"
    
    echo -e "${YELLOW}[*] Running naabu for port scanning...${NC}"
    if [ "$(id -u)" -eq 0 ] || command -v sudo &> /dev/null; then
        sudo naabu -c 250 -l subs-alive.txt -port 3000,5000,8080,8000,8081,8888,8069,8009,8001,8070,8088,8002,8060,8091,8086,8010,8050,8085,8089,8040,8020,8051,8087,8071,8011,8030,8061,8072,8100,8083,8073,8099,8092,8074,8043,8035,8055,8021,8093,8022,8075,8044,8062,8023,8094,8012,8033,8063,8045,7000,9000,7070,9001,7001,10000,9002,7002,9003,7003,10001,80,443,4443 -o subs-portscanned.txt || {
            echo -e "${YELLOW}[*] Falling back to connect scanning...${NC}"
            naabu -c 250 -l subs-alive.txt -port 3000,5000,8080,8000,8081,8888,8069,8009,8001,8070,8088,8002,8060,8091,8086,8010,8050,8085,8089,8040,8020,8051,8087,8071,8011,8030,8061,8072,8100,8083,8073,8099,8092,8074,8043,8035,8055,8021,8093,8022,8075,8044,8062,8023,8094,8012,8033,8063,8045,7000,9000,7070,9001,7001,10000,9002,7002,9003,7003,10001,80,443,4443 -s connect -o subs-portscanned.txt || echo -e "${RED}[!] naabu failed${NC}"
        }
    else
        echo -e "${YELLOW}[*] Running naabu with connect scanning (no sudo)...${NC}"
        naabu -c 250 -l subs-alive.txt -port 3000,5000,8080,8000,8081,8888,8069,8009,8001,8070,8088,8002,8060,8091,8086,8010,8050,8085,8089,8040,8020,8051,8087,8071,8011,8030,8061,8072,8100,8083,8073,8099,8092,8074,8043,8035,8055,8021,8093,8022,8075,8044,8062,8023,8094,8012,8033,8063,8045,7000,9000,7070,9001,7001,10000,9002,7002,9003,7003,10001,80,443,4443 -s connect -o subs-portscanned.txt || echo -e "${RED}[!] naabu failed${NC}"
    fi
    
    echo -e "${YELLOW}[*] Fingerprinting services on open ports...${NC}"
    httpx -l subs-portscanned.txt -title -sc -td -server -fr -o httpx-naabu.txt || echo -e "${RED}[!] httpx failed${NC}"
    
    echo -e "${GREEN}[✓] Port scanning completed${NC}"
}

# Phase 4.5: Wayback Machine / Passive URL Mining
wayback_mining() {
    echo -e "\n${BLUE}[+] Phase 4.5: Wayback Machine / Passive URL Mining${NC}"
    cd "$RESULTS_DIR/endpoints"

    if command_exists waybackurls; then
        echo -e "${YELLOW}[*] Running waybackurls...${NC}"
        cat "$RESULTS_DIR/subdomains/subs-alive.txt" | waybackurls 2>/dev/null | sort -u > wayback-output.txt \
            || echo -e "${RED}[!] waybackurls failed${NC}"
        total_wayback=$(wc -l < wayback-output.txt 2>/dev/null || echo 0)
        echo -e "${GREEN}[✓] waybackurls found $total_wayback URLs${NC}"
    else
        echo -e "${YELLOW}[!] waybackurls not found, using gau fallback...${NC}"
        cat "$RESULTS_DIR/subdomains/subs-alive.txt" | gau --threads 20 \
            --blacklist jpg,jpeg,png,gif,svg,css,ttf,woff,woff2,ico 2>/dev/null \
            | sort -u > wayback-output.txt || true
    fi

    echo -e "${GREEN}[✓] Wayback mining completed${NC}"
    cd "$RESULTS_DIR"
}

# Step 5: Content Discovery (Spidering)
content_discovery() {
    echo -e "\n${BLUE}[+] Step 5: Content Discovery (Spidering)${NC}"
    cd "$RESULTS_DIR/endpoints"
    
    echo -e "${YELLOW}[*] Running gospider...${NC}"
    gospider -S "$RESULTS_DIR/subdomains/subs-alive.txt" -a -r --js --sitemap --robots -d 30 -c 10 -t 20 -K 10 -q --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico)" -o gospider-output || echo -e "${RED}[!] gospider failed${NC}"
    cat gospider-output/* > gospider-all.txt 2>/dev/null || echo -e "${RED}[!] gospider output aggregation failed${NC}"
    
    echo -e "${YELLOW}[*] Running katana...${NC}"
    katana -list "$RESULTS_DIR/subdomains/subs-alive.txt" -kf all -jc -d 30 -c 50 -silent | tee katana-output.txt -a || echo -e "${RED}[!] katana failed${NC}"
    
    echo -e "${YELLOW}[*] Running gau...${NC}"
    cat "$RESULTS_DIR/subdomains/subs-alive.txt" | gau --threads 50 --blacklist jpg,jpeg,png,gif,svg,css,ttf,woff,woff2,ico,tif,tiff,webp | tee gau-output.txt -a || echo -e "${RED}[!] gau failed${NC}"
    
    echo -e "${YELLOW}[*] Combining all spider results...${NC}"
    cat gospider-all.txt katana-output.txt gau-output.txt 2>/dev/null | sort -u > spider-output.txt
    
    total_urls=$(wc -l < spider-output.txt)
    echo -e "${GREEN}[✓] Content discovery completed. Found $total_urls unique URLs${NC}"
}

# Step 6: Analyze Spidering Output for Vulnerabilities
analyze_vulnerabilities() {
    echo -e "\n${BLUE}[+] Step 6: Analyzing Spidering Output for Vulnerabilities${NC}"
    cd "$RESULTS_DIR/vulnerabilities"
    
    if [ -d "$HOME/.gf" ]; then
        echo -e "${YELLOW}[*] Filtering for potential vulnerabilities...${NC}"
        vuln_types=("xss" "lfi" "ssrf" "sqli" "rce" "ssti" "idor")
        for vuln in "${vuln_types[@]}"; do
            if [ -f "$HOME/.gf/$vuln.json" ]; then
                cat "$RESULTS_DIR/endpoints/spider-output.txt" | gf "$vuln" > "checkfor-$vuln.txt" || echo -e "${RED}[!] gf $vuln failed${NC}"
            else
                echo -e "${YELLOW}[!] GF pattern for $vuln not found, skipping...${NC}"
            fi
        done
        echo -e "${GREEN}[✓] Vulnerability pattern analysis completed${NC}"
    else
        echo -e "${RED}[!] GF patterns not found. Skipping vulnerability analysis.${NC}"
    fi
}

# Step 7: Categorize Endpoints by File Extension
categorize_endpoints() {
    echo -e "\n${BLUE}[+] Step 7: Categorizing Endpoints by File Extension${NC}"
    cd "$RESULTS_DIR/endpoints"
    
    echo -e "${YELLOW}[*] Extracting endpoints by file extension...${NC}"
    grep -i -e '\.json$' spider-output.txt | tee json-endpd
    grep -i -e '\.bak$' spider-output.txt | tee bak-endpd
    grep -i -e '\.pdf$' spider-output.txt | tee pdf-endpd
    
    echo -e "${GREEN}[✓] Endpoint categorization completed${NC}"
}

# Phase 7.5: Parameter Discovery
parameter_discovery() {
    echo -e "\n${BLUE}[+] Phase 7.5: Parameter Discovery${NC}"
    cd "$RESULTS_DIR"

    # Use arjun if available
    if command_exists arjun && [ -f "endpoints/spider-output.txt" ]; then
        echo -e "${YELLOW}[*] Running arjun parameter discovery (sample of 50 endpoints)...${NC}"
        # Sample first 50 live endpoints to avoid excessive runtime
        head -50 endpoints/spider-output.txt > /tmp/arjun_targets.txt 2>/dev/null || true
        arjun -i /tmp/arjun_targets.txt -oT endpoints/arjun-params.txt -q 2>/dev/null \
            || echo -e "${RED}[!] arjun failed${NC}"
        rm -f /tmp/arjun_targets.txt
    fi

    echo -e "${YELLOW}[*] Running Python param discovery...${NC}"
    python3 -c "
import sys
sys.path.insert(0, '$WORKING_DIR')
try:
    from rek_param_discovery import ParamDiscovery
    disco = ParamDiscovery(timeout=10, concurrency=15, silent=False)
    disco.run(input_file='endpoints/spider-output.txt', output_file='endpoints/params_discovered.csv')
except ImportError:
    print('[!] rek_param_discovery.py not available')
except Exception as e:
    print(f'[!] Param discovery error: {e}')
" 2>&1 || true

    echo -e "${GREEN}[✓] Parameter discovery completed${NC}"
}

# Phase 7.6: Nuclei Vulnerability Scanning
nuclei_scan() {
    echo -e "\n${BLUE}[+] Phase 7.6: Nuclei Vulnerability Scanning${NC}"
    cd "$RESULTS_DIR"

    if ! command_exists nuclei; then
        echo -e "${RED}[!] nuclei not found, skipping...${NC}"
        return
    fi

    mkdir -p vulnerabilities

    echo -e "${YELLOW}[*] Updating Nuclei templates...${NC}"
    nuclei -update-templates -silent 2>/dev/null || true

    echo -e "${YELLOW}[*] Running Nuclei on live hosts (critical/high/medium severity)...${NC}"
    nuclei -l subdomains/subs-alive.txt \
        -severity critical,high,medium \
        -o vulnerabilities/nuclei-findings.txt \
        -stats \
        -c 25 \
        -rate-limit 50 \
        -timeout 5 \
        -silent 2>/dev/null || echo -e "${RED}[!] Nuclei scan failed${NC}"

    # Also run technology-specific templates based on httpx fingerprinting
    if [ -f "subdomains/httpx-output.txt" ]; then
        echo -e "${YELLOW}[*] Running Nuclei exposure/takeover templates...${NC}"
        nuclei -l subdomains/subs-alive.txt \
            -tags exposure,takeover,misconfig \
            -o vulnerabilities/nuclei-exposure.txt \
            -c 25 \
            -rate-limit 30 \
            -timeout 5 \
            -silent 2>/dev/null || true
    fi

    if [ -f "vulnerabilities/nuclei-findings.txt" ]; then
        nuclei_count=$(wc -l < vulnerabilities/nuclei-findings.txt)
        echo -e "${GREEN}[✓] Nuclei found $nuclei_count potential issues${NC}"
    fi
    echo -e "${GREEN}[✓] Nuclei scan completed${NC}"
}

# Phase 7.7: GitHub Dorking
github_dorking() {
    echo -e "\n${BLUE}[+] Phase 7.7: GitHub Dorking & Secret Scan${NC}"
    cd "$RESULTS_DIR"

    if [ -z "$GITHUB_API_TOKEN" ]; then
        echo -e "${YELLOW}[!] GitHub API token not provided, skipping GitHub dorking...${NC}"
        return
    fi

    python3 -c "
import sys
sys.path.insert(0, '$WORKING_DIR')
try:
    from rek_github_dorking import GitHubDorker
    dorker = GitHubDorker(token='$GITHUB_API_TOKEN', timeout=15, silent=False)
    dorker.run('$TARGET_DOMAIN', 'vulnerabilities/github_dorks.csv')
except ImportError:
    print('[!] rek_github_dorking.py not available')
except Exception as e:
    print(f'[!] GitHub dorking error: {e}')
" 2>&1 || true

    echo -e "${GREEN}[✓] GitHub dorking completed${NC}"
}

# Step 8: JavaScript Analysis for Secrets
js_analysis() {
    echo -e "\n${BLUE}[+] Step 8: JavaScript Analysis for Secrets${NC}"
    cd "$RESULTS_DIR/js"
    
    echo -e "${YELLOW}[*] Extracting JavaScript files...${NC}"
    if command_exists getjs; then
        getjs --input "$RESULTS_DIR/endpoints/spider-output.txt" --complete --resolve --threads 50 --output getjs-output.txt || echo -e "${RED}[!] getjs failed${NC}"
    else
        echo -e "${RED}[!] getJS not found. Attempting alternative extraction...${NC}"
        grep -i '\.js$' "$RESULTS_DIR/endpoints/spider-output.txt" | tee getjs-output.txt
    fi
    
    echo -e "${YELLOW}[*] Scanning JavaScript files for secrets...${NC}"
    if command_exists cariddi; then
        cariddi -headers "User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10/15_7) AppleWebKit/537.36(KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36" -intensive -e -s < getjs-output.txt | tee js-secrets.txt || echo -e "${RED}[!] cariddi failed${NC}"
    else
        echo -e "${RED}[!] cariddi not found. Skipping JavaScript secret analysis.${NC}"
    fi
    
    echo -e "${GREEN}[✓] JavaScript analysis completed${NC}"
}

# Function to generate a summary report
generate_report() {
    echo -e "\n${BLUE}[+] Generating Summary Report${NC}"
    
    REPORT_FILE="$RESULTS_DIR/recon-report.md"
    
    echo "# Reconnaissance Report for $TARGET_DOMAIN" > "$REPORT_FILE"
    echo "Generated on: $(date)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    echo "## Summary" >> "$REPORT_FILE"
    
    if [ -f "$RESULTS_DIR/subdomains/sorted-subs.txt" ]; then
        total_subdomains=$(wc -l < "$RESULTS_DIR/subdomains/sorted-subs.txt")
        echo "- Total unique subdomains discovered: $total_subdomains" >> "$REPORT_FILE"
    fi
    
    if [ -f "$RESULTS_DIR/subdomains/subs-alive.txt" ]; then
        live_subdomains=$(wc -l < "$RESULTS_DIR/subdomains/subs-alive.txt")
        echo "- Live subdomains: $live_subdomains" >> "$REPORT_FILE"
    fi
    
    if [ -f "$RESULTS_DIR/endpoints/spider-output.txt" ]; then
        total_endpoints=$(wc -l < "$RESULTS_DIR/endpoints/spider-output.txt")
        echo "- Total endpoints discovered: $total_endpoints" >> "$REPORT_FILE"
    fi
    
    echo "" >> "$REPORT_FILE"
    echo "## Potential Vulnerabilities" >> "$REPORT_FILE"
    
    vuln_types=("xss" "lfi" "ssrf" "sqli" "rce" "ssti" "idor")
    for vuln in "${vuln_types[@]}"; do
        if [ -f "$RESULTS_DIR/vulnerabilities/checkfor-$vuln.txt" ]; then
            count=$(wc -l < "$RESULTS_DIR/vulnerabilities/checkfor-$vuln.txt")
            echo "- Potential $vuln: $count endpoints" >> "$REPORT_FILE"
        fi
    done
    
    if [ -f "$RESULTS_DIR/js/js-secrets.txt" ]; then
        secrets=$(wc -l < "$RESULTS_DIR/js/js-secrets.txt")
        echo "- JavaScript files with potential secrets: $secrets" >> "$REPORT_FILE"
    fi
    
    echo "" >> "$REPORT_FILE"
    echo "## Interesting Findings" >> "$REPORT_FILE"
    
    if [ -f "$RESULTS_DIR/subdomains/subs-alive.txt" ]; then
        echo "" >> "$REPORT_FILE"
        echo "### Interesting Subdomains" >> "$REPORT_FILE"
        echo "```" >> "$REPORT_FILE"
        head -10 "$RESULTS_DIR/subdomains/subs-alive.txt" >> "$REPORT_FILE"
        echo "```" >> "$REPORT_FILE"
    fi
    
    for vuln in "${vuln_types[@]}"; do
        if [ -f "$RESULTS_DIR/vulnerabilities/checkfor-$vuln.txt" ] && [ -s "$RESULTS_DIR/vulnerabilities/checkfor-$vuln.txt" ]; then
            echo "" >> "$REPORT_FILE"
            echo "### Potential $vuln vulnerabilities (sample)" >> "$REPORT_FILE"
            echo "```" >> "$REPORT_FILE"
            head -5 "$RESULTS_DIR/vulnerabilities/checkfor-$vuln.txt" >> "$REPORT_FILE"
            echo "```" >> "$REPORT_FILE"
        fi
    done
    
    for ext in "json" "bak" "pdf"; do
        if [ -f "$RESULTS_DIR/endpoints/$ext-endpd" ] && [ -s "$RESULTS_DIR/endpoints/$ext-endpd" ]; then
            echo "" >> "$REPORT_FILE"
            echo "### Interesting $ext files (sample)" >> "$REPORT_FILE"
            echo "```" >> "$REPORT_FILE"
            head -5 "$RESULTS_DIR/endpoints/$ext-endpd" >> "$REPORT_FILE"
            echo "```" >> "$REPORT_FILE"
        fi
    done
    
    # Nuclei findings
    if [ -f "$RESULTS_DIR/vulnerabilities/nuclei-findings.txt" ]; then
        nuclei_count=$(wc -l < "$RESULTS_DIR/vulnerabilities/nuclei-findings.txt")
        echo "- Nuclei findings: $nuclei_count" >> "$REPORT_FILE"
    fi

    # Takeover findings
    if [ -f "$RESULTS_DIR/vulnerabilities/takeover.csv" ]; then
        takeover_count=$(tail -n +2 "$RESULTS_DIR/vulnerabilities/takeover.csv" | wc -l)
        echo "- Potential takeovers: $takeover_count" >> "$REPORT_FILE"
    fi

    # Cloud assets
    if [ -f "$RESULTS_DIR/cloud/cloud_assets.csv" ]; then
        cloud_count=$(tail -n +2 "$RESULTS_DIR/cloud/cloud_assets.csv" | wc -l)
        echo "- Cloud assets discovered: $cloud_count" >> "$REPORT_FILE"
    fi

    # Parameter discovery
    if [ -f "$RESULTS_DIR/endpoints/params_discovered.csv" ]; then
        params_count=$(tail -n +2 "$RESULTS_DIR/endpoints/params_discovered.csv" | wc -l)
        echo "- Endpoints with discovered parameters: $params_count" >> "$REPORT_FILE"
    fi

    # Headers audit high/medium
    if [ -f "$RESULTS_DIR/vulnerabilities/headers_audit.csv" ]; then
        headers_high=$(grep -c ",High," "$RESULTS_DIR/vulnerabilities/headers_audit.csv" 2>/dev/null || echo 0)
        echo "- Headers/CORS high-severity issues: $headers_high" >> "$REPORT_FILE"
    fi

    # GitHub dorking secrets
    if [ -f "$RESULTS_DIR/vulnerabilities/github_dorks.csv" ]; then
        dork_count=$(tail -n +2 "$RESULTS_DIR/vulnerabilities/github_dorks.csv" | wc -l)
        echo "- GitHub dork matches (potential secrets): $dork_count" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"
    echo "## Next Steps" >> "$REPORT_FILE"
    echo "- Manual verification of potential vulnerabilities" >> "$REPORT_FILE"
    echo "- Review Nuclei findings in vulnerabilities/nuclei-findings.txt" >> "$REPORT_FILE"
    echo "- Confirm subdomain takeover candidates in vulnerabilities/takeover.csv" >> "$REPORT_FILE"
    echo "- Test endpoints with discovered parameters (endpoints/params_discovered.csv)" >> "$REPORT_FILE"
    echo "- Review CORS/headers issues in vulnerabilities/headers_audit.csv" >> "$REPORT_FILE"
    echo "- Investigate GitHub dork matches in vulnerabilities/github_dorks.csv" >> "$REPORT_FILE"
    echo "- Check favicon hash Shodan queries for related infrastructure" >> "$REPORT_FILE"
    echo "- Deeper analysis of JavaScript files for secrets" >> "$REPORT_FILE"
    echo "- Testing discovered endpoints for business logic flaws" >> "$REPORT_FILE"
    echo "- Explore ASN IP ranges for additional attack surface" >> "$REPORT_FILE"

    echo -e "${GREEN}[✓] Report generated: $REPORT_FILE${NC}"
}

# Function to clean up temporary files
cleanup() {
    echo -e "\n${BLUE}[+] Cleaning up temporary files...${NC}"
    
    if [ -f "$RESULTS_DIR/subdomains/output.txt" ]; then
        rm "$RESULTS_DIR/subdomains/output.txt"
    fi
    
    echo -e "${GREEN}[✓] Cleanup completed${NC}"
}

# Function to display program help
display_help() {
    echo -e "${BLUE}Usage:${NC}"
    echo -e "  ./rek-playbook-v1.sh [OPTIONS]"
    echo ""
    echo -e "${BLUE}Options:${NC}"
    echo -e "  -h, --help                 Display this help message"
    echo -e "  -d, --domain DOMAIN        Specify target domain"
    echo -e "  -o, --output DIR           Specify output directory"
    echo -e "  -t, --threads NUMBER       Specify number of threads (default: 250)"
    echo -e "  -c, --config FILE          Specify config file"
    echo -e "  --chaos-key KEY            Specify Chaos API key"
    echo -e "  --github-token TOKEN       Specify GitHub API token"
    echo -e "  --gitlab-token TOKEN       Specify GitLab API token"
    echo -e "  --skip-install             Skip tool installation"
    echo -e "  --skip-subdomain           Skip subdomain enumeration"
    echo -e "  --skip-permutation         Skip subdomain permutation"
    echo -e "  --skip-fingerprint         Skip subdomain fingerprinting"
    echo -e "  --skip-portscan            Skip port scanning"
    echo -e "  --skip-spider              Skip content discovery"
    echo -e "  --skip-vulnanalysis        Skip vulnerability analysis"
    echo -e "  --skip-jsanalysis          Skip JavaScript analysis"
    echo -e "  --skip-cloudrecon          Skip cloud asset discovery"
    echo -e "  --skip-takeover            Skip subdomain takeover detection"
    echo -e "  --skip-params              Skip parameter discovery"
    echo -e "  --skip-headers             Skip CORS/headers audit"
    echo -e "  --skip-nuclei              Skip Nuclei scanning"
    echo -e "  --skip-asn                 Skip ASN expansion"
    echo -e "  --skip-wayback             Skip Wayback URL mining"
    echo -e "  --skip-githubdork          Skip GitHub dorking"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  ./rek-playbook-v1.sh -d example.com"
    echo -e "  ./rek-playbook-v1.sh -d example.com -t 200 --skip-portscan"
    echo -e "  ./rek-playbook-v1.sh -d example.com --chaos-key YOUR_KEY --github-token YOUR_TOKEN"
}

# Parse command line arguments
parse_arguments() {
    SKIP_INSTALL=false
    SKIP_SUBDOMAIN=false
    SKIP_PERMUTATION=false
    SKIP_FINGERPRINT=false
    SKIP_PORTSCAN=false
    SKIP_SPIDER=false
    SKIP_VULNANALYSIS=false
    SKIP_JSANALYSIS=false
    SKIP_CLOUDRECON=false
    SKIP_TAKEOVER=false
    SKIP_PARAMS=false
    SKIP_HEADERS=false
    SKIP_NUCLEI=false
    SKIP_ASN=false
    SKIP_WAYBACK=false
    SKIP_GITHUBDORK=false
    
    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            -h|--help)
                display_help
                exit 0
                ;;
            -d|--domain)
                TARGET_DOMAIN="$2"
                shift
                shift
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift
                shift
                ;;
            -t|--threads)
                THREADS="$2"
                shift
                shift
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift
                shift
                ;;
            --chaos-key)
                CHAOS_API_KEY="$2"
                shift
                shift
                ;;
            --github-token)
                GITHUB_API_TOKEN="$2"
                shift
                shift
                ;;
            --gitlab-token)
                GITLAB_API_TOKEN="$2"
                shift
                shift
                ;;
            --skip-install)
                SKIP_INSTALL=true
                shift
                ;;
            --skip-subdomain)
                SKIP_SUBDOMAIN=true
                shift
                ;;
            --skip-permutation)
                SKIP_PERMUTATION=true
                shift
                ;;
            --skip-fingerprint)
                SKIP_FINGERPRINT=true
                shift
                ;;
            --skip-portscan)
                SKIP_PORTSCAN=true
                shift
                ;;
            --skip-spider)
                SKIP_SPIDER=true
                shift
                ;;
            --skip-vulnanalysis)
                SKIP_VULNANALYSIS=true
                shift
                ;;
            --skip-jsanalysis)
                SKIP_JSANALYSIS=true
                shift
                ;;
            --skip-cloudrecon)
                SKIP_CLOUDRECON=true
                shift
                ;;
            --skip-takeover)
                SKIP_TAKEOVER=true
                shift
                ;;
            --skip-params)
                SKIP_PARAMS=true
                shift
                ;;
            --skip-headers)
                SKIP_HEADERS=true
                shift
                ;;
            --skip-nuclei)
                SKIP_NUCLEI=true
                shift
                ;;
            --skip-asn)
                SKIP_ASN=true
                shift
                ;;
            --skip-wayback)
                SKIP_WAYBACK=true
                shift
                ;;
            --skip-githubdork)
                SKIP_GITHUBDORK=true
                shift
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $key${NC}"
                display_help
                exit 1
                ;;
        esac
    done
}

# Function to save current configuration to a pipeline file
save_pipeline() {
    PIPELINE_FILE="$WORKING_DIR/pipelines/$TARGET_DOMAIN-pipeline.conf"
    mkdir -p "$WORKING_DIR/pipelines"
    
    echo -e "${BLUE}[+] Saving pipeline configuration...${NC}"
    
    echo "TARGET_DOMAIN=\"$TARGET_DOMAIN\"" > "$PIPELINE_FILE"
    echo "THREADS=\"$THREADS\"" >> "$PIPELINE_FILE"
    echo "CHAOS_API_KEY=\"$CHAOS_API_KEY\"" >> "$PIPELINE_FILE"
    echo "GITHUB_API_TOKEN=\"$GITHUB_API_TOKEN\"" >> "$PIPELINE_FILE"
    echo "GITLAB_API_TOKEN=\"$GITLAB_API_TOKEN\"" >> "$PIPELINE_FILE"
    echo "SKIP_INSTALL=\"$SKIP_INSTALL\"" >> "$PIPELINE_FILE"
    echo "SKIP_SUBDOMAIN=\"$SKIP_SUBDOMAIN\"" >> "$PIPELINE_FILE"
    echo "SKIP_PERMUTATION=\"$SKIP_PERMUTATION\"" >> "$PIPELINE_FILE"
    echo "SKIP_FINGERPRINT=\"$SKIP_FINGERPRINT\"" >> "$PIPELINE_FILE"
    echo "SKIP_PORTSCAN=\"$SKIP_PORTSCAN\"" >> "$PIPELINE_FILE"
    echo "SKIP_SPIDER=\"$SKIP_SPIDER\"" >> "$PIPELINE_FILE"
    echo "SKIP_VULNANALYSIS=\"$SKIP_VULNANALYSIS\"" >> "$PIPELINE_FILE"
    echo "SKIP_JSANALYSIS=\"$SKIP_JSANALYSIS\"" >> "$PIPELINE_FILE"
    
    echo -e "${GREEN}[✓] Pipeline configuration saved: $PIPELINE_FILE${NC}"
}

# Function to load pipeline from file
load_pipeline() {
    PIPELINE_FILE="$WORKING_DIR/pipelines/$TARGET_DOMAIN-pipeline.conf"
    
    if [ -f "$PIPELINE_FILE" ]; then
        echo -e "${BLUE}[+] Found existing pipeline for $TARGET_DOMAIN. Loading...${NC}"
        source "$PIPELINE_FILE"
        echo -e "${GREEN}[✓] Pipeline loaded${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] No existing pipeline found for $TARGET_DOMAIN${NC}"
        return 1
    fi
}

# Function to list all saved pipelines
list_pipelines() {
    echo -e "${BLUE}[+] Available saved pipelines:${NC}"
    
    if [ -d "$WORKING_DIR/pipelines" ]; then
        count=0
        for pipeline in "$WORKING_DIR/pipelines"/*-pipeline.conf; do
            if [ -f "$pipeline" ]; then
                domain=$(basename "$pipeline" | sed 's/-pipeline.conf//')
                echo -e "${GREEN}[$((++count))]${NC} $domain"
            fi
        done
        
        if [ $count -eq 0 ]; then
            echo -e "${YELLOW}[!] No saved pipelines found${NC}"
        fi
    else
        echo -e "${YELLOW}[!] No saved pipelines found${NC}"
    fi
}

# Function to show a progress spinner
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep -w $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Main function
main() {
    parse_arguments "$@"
    
    if [ -z "$TARGET_DOMAIN" ]; then
        list_pipelines
        
        echo -e "${YELLOW}[?] Would you like to load an existing pipeline? (y/n)${NC}"
        read -r load_choice
        
        if [[ "$load_choice" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}[?] Enter the domain name of the pipeline to load:${NC}"
            read -r TARGET_DOMAIN
            
            if ! load_pipeline; then
                get_target_domain
            fi
        else
            get_target_domain
        fi
    else
        load_pipeline || true
    fi
    
    setup_directories
    
    if [ "$SKIP_INSTALL" = false ]; then
        check_prerequisites
    fi
    
    load_config
    
    save_pipeline
    
    start_time=$(date +%s)

    # Phase 0: Cloud Asset Discovery
    if [ "$SKIP_CLOUDRECON" = false ]; then
        cloud_asset_discovery
    else
        echo -e "${YELLOW}[!] Skipping cloud asset discovery${NC}"
    fi

    if [ "$SKIP_SUBDOMAIN" = false ]; then
        subdomain_enumeration
    else
        echo -e "${YELLOW}[!] Skipping subdomain enumeration${NC}"
    fi

    if [ "$SKIP_PERMUTATION" = false ]; then
        subdomain_permutation
    else
        echo -e "${YELLOW}[!] Skipping subdomain permutation${NC}"
    fi

    # Phase 2.5: ASN Expansion
    if [ "$SKIP_ASN" = false ]; then
        asn_expansion
    else
        echo -e "${YELLOW}[!] Skipping ASN expansion${NC}"
    fi

    if [ "$SKIP_FINGERPRINT" = false ]; then
        identify_live_subdomains
    else
        echo -e "${YELLOW}[!] Skipping subdomain fingerprinting${NC}"
    fi

    # Phase 3.5: Takeover Detection (after live detection)
    if [ "$SKIP_TAKEOVER" = false ]; then
        takeover_detection
    else
        echo -e "${YELLOW}[!] Skipping takeover detection${NC}"
    fi

    # Phase 3.6: Favicon Fingerprinting
    favicon_fingerprinting

    # Phase 3.7: Headers / CORS Audit
    if [ "$SKIP_HEADERS" = false ]; then
        headers_audit
    else
        echo -e "${YELLOW}[!] Skipping headers audit${NC}"
    fi

    if [ "$SKIP_PORTSCAN" = false ]; then
        port_scanning
    else
        echo -e "${YELLOW}[!] Skipping port scanning${NC}"
    fi

    # Phase 4.5: Wayback URL Mining
    if [ "$SKIP_WAYBACK" = false ]; then
        wayback_mining
    else
        echo -e "${YELLOW}[!] Skipping wayback URL mining${NC}"
    fi

    if [ "$SKIP_SPIDER" = false ]; then
        content_discovery
    else
        echo -e "${YELLOW}[!] Skipping content discovery${NC}"
    fi

    if [ "$SKIP_VULNANALYSIS" = false ]; then
        analyze_vulnerabilities
        categorize_endpoints
    else
        echo -e "${YELLOW}[!] Skipping vulnerability analysis${NC}"
    fi

    # Phase 7.5: Parameter Discovery
    if [ "$SKIP_PARAMS" = false ]; then
        parameter_discovery
    else
        echo -e "${YELLOW}[!] Skipping parameter discovery${NC}"
    fi

    # Phase 7.6: Nuclei Scanning
    if [ "$SKIP_NUCLEI" = false ]; then
        nuclei_scan
    else
        echo -e "${YELLOW}[!] Skipping Nuclei scan${NC}"
    fi

    # Phase 7.7: GitHub Dorking
    if [ "$SKIP_GITHUBDORK" = false ]; then
        github_dorking
    else
        echo -e "${YELLOW}[!] Skipping GitHub dorking${NC}"
    fi

    if [ "$SKIP_JSANALYSIS" = false ]; then
        js_analysis
    else
        echo -e "${YELLOW}[!] Skipping JavaScript analysis${NC}"
    fi
    
    generate_report
    
    cleanup
    
    end_time=$(date +%s)
    execution_time=$((end_time - start_time))
    hours=$((execution_time / 3600))
    minutes=$(( (execution_time % 3600) / 60 ))
    seconds=$((execution_time % 60))
    
    echo -e "\n${GREEN}[✓] Reconnaissance completed in ${hours}h ${minutes}m ${seconds}s${NC}"
    echo -e "${GREEN}[✓] Results saved to: $RESULTS_DIR${NC}"
    echo -e "${GREEN}[✓] Report available at: $RESULTS_DIR/recon-report.md${NC}"
}

main "$@"