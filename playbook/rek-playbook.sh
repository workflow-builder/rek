#!/bin/bash

# ╔═════════════════════════════════════════════════════════════╗
# ║  Modern Recon Playbook for Bug Bounty Hunters               ║
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
echo "║   From Subdomains to Secrets: A Modern Recon Playbook for Bug Hunters     ║"
echo "║                                                                           ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Variables
# Use environment variables or dynamically determine paths
WORKING_DIR="${RECON_TOOLKIT_DIR:-$(dirname "$(realpath "$0")")}"
TOOLS_DIR="${TOOLS_DIR:-$WORKING_DIR/tools}"
OUTPUT_DIR=""
TARGET_DOMAIN=""
CONFIG_FILE="${CONFIG_PATH:-$WORKING_DIR/config.conf}"
API_KEYS=()
RESOLVERS_FILE="$WORKING_DIR/resolvers.txt"
THREADS=100
WORDLISTS_DIR="${WORDLISTS_DIR:-$WORKING_DIR/wordlists}"
RESULTS_DIR=""
# Update PATH to include tools
export PATH="$TOOLS_DIR:$HOME/go/bin:$PATH"

# Create required directories
setup_directories() {
    echo -e "${BLUE}[+] Setting up directories...${NC}"
    mkdir -p "$WORKING_DIR"
    mkdir -p "$TOOLS_DIR"
    mkdir -p "$WORDLISTS_DIR"
    
    # Create results directory with timestamp
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
        if [ -x "$(command -v $1)" ]; then
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
        wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
        rm go1.21.0.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.profile
        source ~/.profile
    fi
    echo -e "${GREEN}[✓] Go installed successfully${NC}"
}

# Function to install required tools
install_tools() {
    echo -e "${BLUE}[+] Installing required tools...${NC}"
    
    # Install Go if not installed
    if ! command_exists go; then
        install_go
    fi
    
    # Install Python tools
    if command_exists pip3; then
        echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
        pip3 install requests dnsgen tldextract dnspython
    fi
    
    # Install Go tools if not already installed
    if command_exists go; then
        if ! go_tool_exists subfinder; then
            echo -e "${YELLOW}[*] Installing subfinder...${NC}"
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        fi
        
        if ! go_tool_exists assetfinder; then
            echo -e "${YELLOW}[*] Installing assetfinder...${NC}"
            go install -v github.com/tomnomnom/assetfinder@latest
        fi
        
        if ! go_tool_exists findomain; then
            echo -e "${YELLOW}[*] Installing findomain...${NC}"
            if [ "$(uname)" == "Darwin" ]; then
                brew install findomain
            else
                curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux
                chmod +x findomain-linux
                mv findomain-linux "$TOOLS_DIR/findomain"
            fi
        fi
        
        if ! go_tool_exists chaos; then
            echo -e "${YELLOW}[*] Installing chaos...${NC}"
            go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
        fi
        
        if ! go_tool_exists httpx; then
            echo -e "${YELLOW}[*] Installing httpx...${NC}"
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        fi
        
        if ! go_tool_exists naabu; then
            echo -e "${YELLOW}[*] Installing naabu...${NC}"
            go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
        fi
        
        if ! go_tool_exists gospider; then
            echo -e "${YELLOW}[*] Installing gospider...${NC}"
            go install -v github.com/jaeles-project/gospider@latest
        fi
        
        if ! go_tool_exists katana; then
            echo -e "${YELLOW}[*] Installing katana...${NC}"
            go install -v github.com/projectdiscovery/katana/cmd/katana@latest
        fi
        
        if ! go_tool_exists gau; then
            echo -e "${YELLOW}[*] Installing gau...${NC}"
            go install -v github.com/lc/gau/v2/cmd/gau@latest
        fi
        
        if ! go_tool_exists getjs; then
            echo -e "${YELLOW}[*] Installing getJS...${NC}"
            go install -v github.com/003random/getJS@latest
        fi
        
        if ! go_tool_exists cariddi; then
            echo -e "${YELLOW}[*] Installing cariddi...${NC}"
            go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest
        fi
        
        if ! go_tool_exists goaltdns; then
            echo -e "${YELLOW}[*] Installing goaltdns...${NC}"
            go install -v github.com/subfinder/goaltdns@latest
        fi
        
        if ! go_tool_exists gotator; then
            echo -e "${YELLOW}[*] Installing gotator...${NC}"
            go install -v github.com/Josue87/gotator@latest
        fi
        
        if ! go_tool_exists ripgen; then
            echo -e "${YELLOW}[*] Skipping ripgen due to package issues...${NC}"
            # go install -v github.com/resyncgg/ripgen/cmd/ripgen@latest
        fi
        
        if ! go_tool_exists puredns; then
            echo -e "${YELLOW}[*] Installing puredns...${NC}"
            go install -v github.com/d3mondev/puredns/v2@latest
        fi
        
        if ! go_tool_exists gf; then
            echo -e "${YELLOW}[*] Installing gf...${NC}"
            go install -v github.com/tomnomnom/gf@latest
            
            echo -e "${YELLOW}[*] Installing gf patterns...${NC}"
            if [ -d ~/.gf ]; then
                echo -e "${YELLOW}[!] ~/.gf already exists. Updating...${NC}"
                git -C ~/.gf pull
            else
                mkdir -p ~/.gf
                git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf/
            fi
        fi
        
        if ! command_exists github-subdomains; then
            echo -e "${YELLOW}[*] Installing github-subdomains...${NC}"
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
        fi
        
        if ! command_exists gitlab-subdomains; then
            echo -e "${YELLOW}[*] Installing gitlab-subdomains...${NC}"
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
        fi
    fi
    
    # Download resolvers if they don't exist
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
        
        echo -e "${YELLOW}[?] Default number of threads to use (default: 100):${NC}"
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

# Step 1: Subdomain Enumeration
subdomain_enumeration() {
    echo -e "\n${BLUE}[+] Step 1: Subdomain Enumeration${NC}"
    cd "$RESULTS_DIR/subdomains"
    
    echo -e "${YELLOW}[*] Running subfinder...${NC}"
    subfinder -d "$TARGET_DOMAIN" -all -recursive -silent -o subfinder.txt
    
    echo -e "${YELLOW}[*] Running assetfinder...${NC}"
    echo "$TARGET_DOMAIN" | assetfinder -subs-only | tee assetfinder.txt
    
    echo -e "${YELLOW}[*] Running findomain...${NC}"
    findomain -t "$TARGET_DOMAIN" --quiet | tee findomain.txt
    
    if [ -n "$CHAOS_API_KEY" ]; then
        echo -e "${YELLOW}[*] Running chaos...${NC}"
        chaos -key "$CHAOS_API_KEY" -d "$TARGET_DOMAIN" -o chaos.txt
    else
        echo -e "${YELLOW}[!] Chaos API key not provided, skipping...${NC}"
    fi
    
    if [ -n "$GITHUB_API_TOKEN" ]; then
        echo -e "${YELLOW}[*] Running github-subdomains...${NC}"
        github-subdomains -d "$TARGET_DOMAIN" -t "$GITHUB_API_TOKEN" -o github-subdomains.txt
    else
        echo -e "${YELLOW}[!] GitHub API token not provided, skipping github-subdomains...${NC}"
    fi
    
    if [ -n "$GITLAB_API_TOKEN" ]; then
        echo -e "${YELLOW}[*] Running gitlab-subdomains...${NC}"
        gitlab-subdomains -d "$TARGET_DOMAIN" -t "$GITLAB_API_TOKEN" -o gitlab-subdomains.txt
    else
        echo -e "${YELLOW}[!] GitLab API token not provided, skipping gitlab-subdomains...${NC}"
    fi
    
    echo -e "${YELLOW}[*] Consolidating and deduplicating results...${NC}"
    cat *.txt 2>/dev/null > all.txt
    cat all.txt | sort -u | tee sorted-subdomains.txt
    
    total_subdomains=$(wc -l < sorted-subdomains.txt)
    echo -e "${GREEN}[✓] Subdomain enumeration completed. Found $total_subdomains unique subdomains${NC}"
}

# Step 2: Subdomain Permutation and Bruteforce
subdomain_permutation() {
    echo -e "\n${BLUE}[+] Step 2: Subdomain Permutation and Bruteforce${NC}"
    cd "$RESULTS_DIR/subdomains"
    
    echo -e "${YELLOW}[*] Generating permutation wordlist...${NC}"
    cat sorted-subdomains.txt | tr . '\n' | sort -u > perms.txt
    cat sorted-subdomains.txt | sed 's/[.]/-/g' | awk -F '-' '{for(i=1;i<=NF;i++){print $i}}' | sort -u >> perms.txt
    
    echo -e "${YELLOW}[*] Running dnsgen...${NC}"
    cat sorted-subdomains.txt | dnsgen - > output-dnsgen.txt
    
    echo -e "${YELLOW}[*] Running goaltdns...${NC}"
    if command_exists goaltdns; then
        goaltdns -w perms.txt -l sorted-subdomains.txt -o output-goaltdns.txt
    else
        echo -e "${RED}[!] goaltdns not found, skipping...${NC}"
    fi
    
    echo -e "${YELLOW}[*] Running gotator...${NC}"
    if command_exists gotator; then
        gotator -sub sorted-subdomains.txt -perm perms.txt -depth 1 -numbers 1 > output-gotator.txt
    else
        echo -e "${RED}[!] gotator not found, skipping...${NC}"
    fi
    
    echo -e "${YELLOW}[*] Skipping ripgen due to package issues...${NC}"
    # cat sorted-subdomains.txt | ripgen > output-ripgen.txt
    
    echo -e "${YELLOW}[*] Merging permutation results...${NC}"
    cat output*.txt | sort -u > output.txt
    
    echo -e "${YELLOW}[*] Resolving permutated subdomains...${NC}"
    if command_exists puredns; then
        cat output.txt | puredns resolve --resolvers "$RESOLVERS_FILE" --write subdomains-permutated.txt
    else
        echo -e "${RED}[!] puredns not found, skipping resolution...${NC}"
    fi
    
    echo -e "${YELLOW}[*] Merging all subdomains...${NC}"
    if [ -f "subdomains-permutated.txt" ]; then
        cat sorted-subdomains.txt subdomains-permutated.txt > all-subdomains.txt
        cat all-subdomains.txt | sort -u | tee final-subdomains.txt
    else
        cp sorted-subdomains.txt final-subdomains.txt
    fi
    
    total_subdomains=$(wc -l < final-subdomains.txt)
    echo -e "${GREEN}[✓] Subdomain permutation completed. Found $total_subdomains total unique subdomains${NC}"
}

# Step 3: Identify Live Subdomains and Fingerprint Applications
identify_live_subdomains() {
    echo -e "\n${BLUE}[+] Step 3: Identifying Live Subdomains${NC}"
    cd "$RESULTS_DIR/subdomains"
    
    echo -e "${YELLOW}[*] Running httpx to identify live subdomains...${NC}"
    httpx -l final-subdomains.txt -threads "$THREADS" -o subs-alive.txt
    
    echo -e "${YELLOW}[*] Fingerprinting live subdomains...${NC}"
    httpx -l subs-alive.txt -title -sc -td -server -fr -probe -location -o httpx-output.txt
    
    total_live=$(wc -l < subs-alive.txt)
    echo -e "${GREEN}[✓] Live subdomain identification completed. Found $total_live live subdomains${NC}"
}

# Step 4: Port Scanning
port_scanning() {
    echo -e "\n${BLUE}[+] Step 4: Port Scanning${NC}"
    cd "$RESULTS_DIR/subdomains"
    
    echo -e "${YELLOW}[*] Running naabu for port scanning...${NC}"
    naabu -c "$THREADS" -l subs-alive.txt -port 80,443,3000,5000,8080,8000,8081,8888,8443 -o subs-portscanned.txt
    
    echo -e "${YELLOW}[*] Fingerprinting services on open ports...${NC}"
    httpx -l subs-portscanned.txt -title -sc -td -server -fr -o httpx-naabu.txt
    
    echo -e "${GREEN}[✓] Port scanning completed${NC}"
}

# Step 5: Content Discovery (Spidering)
content_discovery() {
    echo -e "\n${BLUE}[+] Step 5: Content Discovery (Spidering)${NC}"
    cd "$RESULTS_DIR/endpoints"
    
    echo -e "${YELLOW}[*] Running gospider...${NC}"
    gospider -S "$RESULTS_DIR/subdomains/subs-alive.txt" -a -r --js --sitemap --robots -d 30 -c 10 -o gospider-output
    find gospider-output -type f -exec cat {} \; > gospider-all.txt
    
    echo -e "${YELLOW}[*] Running katana...${NC}"
    katana -list "$RESULTS_DIR/subdomains/subs-alive.txt" -kf all -jc -d 30 -c 50 -silent | tee katana-output.txt
    
    echo -e "${YELLOW}[*] Running gau...${NC}"
    cat "$RESULTS_DIR/subdomains/subs-alive.txt" | gau --threads 50 --blacklist jpg,jpeg,png,gif,svg,css | tee gau-output.txt
    
    echo -e "${YELLOW}[*] Combining all spider results...${NC}"
    cat gospider-all.txt katana-output.txt gau-output.txt | sort -u > spider-output.txt
    
    total_urls=$(wc -l < spider-output.txt)
    echo -e "${GREEN}[✓] Content discovery completed. Found $total_urls unique URLs${NC}"
}

# Step 6: Analyze Spidering Output for Vulnerabilities
analyze_vulnerabilities() {
    echo -e "\n${BLUE}[+] Step 6: Analyzing Spidering Output for Vulnerabilities${NC}"
    cd "$RESULTS_DIR/vulnerabilities"
    
    if [ -d "$HOME/.gf" ]; then
        echo -e "${YELLOW}[*] Filtering for potential vulnerabilities...${NC}"
        
        cat "$RESULTS_DIR/endpoints/spider-output.txt" | gf xss | tee checkfor-xss.txt
        cat "$RESULTS_DIR/endpoints/spider-output.txt" | gf lfi | tee checkfor-lfi.txt
        cat "$RESULTS_DIR/endpoints/spider-output.txt" | gf ssrf | tee checkfor-ssrf.txt
        cat "$RESULTS_DIR/endpoints/spider-output.txt" | gf sqli | tee checkfor-sqli.txt
        cat "$RESULTS_DIR/endpoints/spider-output.txt" | gf rce | tee checkfor-rce.txt
        cat "$RESULTS_DIR/endpoints/spider-output.txt" | gf ssti | tee checkfor-ssti.txt
        cat "$RESULTS_DIR/endpoints/spider-output.txt" | gf idor | tee checkfor-idor.txt
        
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
    
    cat spider-output.txt | grep -i -e '\.json$' | tee json-endpoints.txt
    cat spider-output.txt | grep -i -e '\.bak$' -e '\.backup$' -e '\.old$' -e '\.tmp$' | tee backup-endpoints.txt
    cat spider-output.txt | grep -i -e '\.conf$' -e '\.config$' -e '\.env$' -e '\.ini$' | tee config-endpoints.txt
    cat spider-output.txt | grep -i -e '\.pdf$' | tee pdf-endpoints.txt
    cat spider-output.txt | grep -i -e '\.xml$' | tee xml-endpoints.txt
    cat spider-output.txt | grep -i -e '\.sql$' | tee sql-endpoints.txt
    cat spider-output.txt | grep -i -e '\.log$' | tee log-endpoints.txt
    
    echo -e "${GREEN}[✓] Endpoint categorization completed${NC}"
}

# Step 8: JavaScript Analysis for Secrets
js_analysis() {
    echo -e "\n${BLUE}[+] Step 8: JavaScript Analysis for Secrets${NC}"
    cd "$RESULTS_DIR/js"
    
    echo -e "${YELLOW}[*] Extracting JavaScript files...${NC}"
    if command_exists getjs; then
        getjs --input "$RESULTS_DIR/endpoints/spider-output.txt" --complete --resolve --threads 50 --output getjs-output.txt
    else
        echo -e "${RED}[!] getJS not found. Attempting alternative extraction...${NC}"
        cat "$RESULTS_DIR/endpoints/spider-output.txt" | grep -i '\.js' | tee getjs-output.txt
    fi
    
    echo -e "${YELLOW}[*] Scanning JavaScript files for secrets...${NC}"
    if command_exists cariddi; then
        cat getjs-output.txt | cariddi -headers "User-Agent: Mozilla/5.0" -intensive -e -s | tee js-secrets.txt
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
    
    if [ -f "$RESULTS_DIR/subdomains/final-subdomains.txt" ]; then
        total_subdomains=$(wc -l < "$RESULTS_DIR/subdomains/final-subdomains.txt")
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
    
    for ext in "json" "backup" "config" "pdf" "xml" "sql" "log"; do
        if [ -f "$RESULTS_DIR/endpoints/$ext-endpoints.txt" ] && [ -s "$RESULTS_DIR/endpoints/$ext-endpoints.txt" ]; then
            echo "" >> "$REPORT_FILE"
            echo "### Interesting $ext files (sample)" >> "$REPORT_FILE"
            echo "```" >> "$REPORT_FILE"
            head -5 "$RESULTS_DIR/endpoints/$ext-endpoints.txt" >> "$REPORT_FILE"
            echo "```" >> "$REPORT_FILE"
        fi
    done
    
    echo "" >> "$REPORT_FILE"
    echo "## Next Steps" >> "$REPORT_FILE"
    echo "- Manual verification of potential vulnerabilities" >> "$REPORT_FILE"
    echo "- Deeper analysis of JavaScript files for secrets" >> "$REPORT_FILE"
    echo "- Testing discovered endpoints for business logic flaws" >> "$REPORT_FILE"
    echo "- Exploring technologies detected by fingerprinting" >> "$REPORT_FILE"
    
    echo -e "${GREEN}[✓] Report generated: $REPORT_FILE${NC}"
}

# Function to clean up temporary files
cleanup() {
    echo -e "\n${BLUE}[+] Cleaning up temporary files...${NC}"
    
    if [ -f "$RESULTS_DIR/subdomains/all.txt" ]; then
        rm "$RESULTS_DIR/subdomains/all.txt"
    fi
    
    if [ -f "$RESULTS_DIR/subdomains/output.txt" ]; then
        rm "$RESULTS_DIR/subdomains/output.txt"
    fi
    
    echo -e "${GREEN}[✓] Cleanup completed${NC}"
}

# Function to display program help
display_help() {
    echo -e "${BLUE}Usage:${NC}"
    echo -e "  ./recon-playbook.sh [OPTIONS]"
    echo ""
    echo -e "${BLUE}Options:${NC}"
    echo -e "  -h, --help                 Display this help message"
    echo -e "  -d, --domain DOMAIN        Specify target domain"
    echo -e "  -o, --output DIR           Specify output directory"
    echo -e "  -t, --threads NUMBER       Specify number of threads (default: 100)"
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
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  ./recon-playbook.sh -d example.com"
    echo -e "  ./recon-playbook.sh -d example.com -t 200 --skip-portscan"
    echo -e "  ./recon-playbook.sh -d example.com --chaos-key YOUR_KEY --github-token YOUR_TOKEN"
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
    
    if [ "$SKIP_FINGERPRINT" = false ]; then
        identify_live_subdomains
    else
        echo -e "${YELLOW}[!] Skipping subdomain fingerprinting${NC}"
    fi
    
    if [ "$SKIP_PORTSCAN" = false ]; then
        port_scanning
    else
        echo -e "${YELLOW}[!] Skipping port scanning${NC}"
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