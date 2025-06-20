#!/bin/bash

# ╔═════════════════════════════════════════════════════════════╗
# ║  Streamlined Recon Playbook for Quick Bug Bounty Recon (v2) ║
# ║  Fast pipeline using Katana, HTTPX, and Nuclei              ║
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
echo "║   Streamlined Recon Playbook (v2): Fast Bug Bounty Recon with Katana,     ║"
echo "║   HTTPX, and Nuclei                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Variables
WORKING_DIR="${RECON_TOOLKIT_DIR:-$(dirname "$(realpath "$0")")}"
TOOLS_DIR="${TOOLS_DIR:-$WORKING_DIR/tools}"
OUTPUT_DIR=""
TARGET_URL=""
CONFIG_FILE="${CONFIG_PATH:-$WORKING_DIR/config.conf}"
THREADS=20
RATE_LIMIT=25
RESULTS_DIR=""
export PATH="$TOOLS_DIR:$HOME/go/bin:$PATH"

# Create required directories
setup_directories() {
    echo -e "${BLUE}[+] Setting up directories...${NC}"
    mkdir -p "$WORKING_DIR"
    mkdir -p "$TOOLS_DIR"
    
    timestamp=$(date +"%Y%m%d-%H%M%S")
    TARGET_DOMAIN=$(echo "$TARGET_URL" | awk -F/ '{print $3}')
    RESULTS_DIR="$WORKING_DIR/results/$TARGET_DOMAIN-$timestamp"
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$RESULTS_DIR/urls"
    mkdir -p "$RESULTS_DIR/probed"
    mkdir -p "$RESULTS_DIR/vulnerabilities"
    
    echo -e "${GREEN}[✓] Directories set up successfully${NC}"
    echo -e "${GREEN}[✓] Results will be saved to: $RESULTS_DIR${NC}"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
    echo -e "${BLUE}[+] Checking prerequisites...${NC}"
    
    printf "%-20s %-10s\n" "Tool" "Status"
    printf "%-20s %-10s\n" "--------------------" "----------"
    
    local all_tools_installed=true
    local tools=("katana" "httpx" "nuclei")
    
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            printf "%-20s ${GREEN}%-10s${NC}\n" "$tool" "Installed"
        else
            printf "%-20s ${RED}%-10s${NC}\n" "$tool" "Missing"
            all_tools_installed=false
        fi
    done
    
    if [ "$all_tools_installed" = false ]; then
        echo -e "\n${YELLOW}[!] Some prerequisites are missing. Please run install-script-v2.sh${NC}"
        exit 1
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
        
        echo -e "${YELLOW}[?] Default number of threads (default: 20):${NC}"
        read -r input_threads
        THREADS=${input_threads:-20}
        
        echo -e "${YELLOW}[?] Default rate limit per second (default: 25):${NC}"
        read -r input_rate_limit
        RATE_LIMIT=${input_rate_limit:-25}
        
        echo "THREADS=\"$THREADS\"" > "$CONFIG_FILE"
        echo "RATE_LIMIT=\"$RATE_LIMIT\"" >> "$CONFIG_FILE"
        
        echo -e "${GREEN}[✓] Configuration saved${NC}"
    fi
}

# Function to get target URL from user
get_target_url() {
    echo -e "${YELLOW}[?] Enter the target URL (e.g., https://example.com):${NC}"
    read -r TARGET_URL
    
    if [ -z "$TARGET_URL" ]; then
        echo -e "${RED}[!] No URL provided. Exiting.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[✓] Target URL set to: $TARGET_URL${NC}"
}

# Recon pipeline: Katana -> HTTPX -> Nuclei
recon_pipeline() {
    echo -e "\n${BLUE}[+] Starting Recon Pipeline: Katana -> HTTPX -> Nuclei${NC}"
    
    # Random User-Agent for consistency
    USER_AGENT=$(shuf -n 1 -e \
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
        "Mozilla/5.0 (X11; Linux x86_64)" \
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
    
    echo -e "${YELLOW}[*] Running Katana for URL discovery...${NC}"
    cd "$RESULTS_DIR/urls"
    katana -u "$TARGET_URL" -hl -jc --no-sandbox -c 1 -p 1 -rd 3 -rl 5 \
        -H "User-Agent: $USER_AGENT" -o katana-output.txt || {
        echo -e "${RED}[!] Katana failed${NC}"
        exit 1
    }
    
    total_urls=$(wc -l < katana-output.txt)
    echo -e "${GREEN}[✓] Katana completed. Found $total_urls URLs${NC}"
    
    echo -e "${YELLOW}[*] Running HTTPX for validation and enrichment...${NC}"
    cd "$RESULTS_DIR/probed"
    cat "$RESULTS_DIR/urls/katana-output.txt" | httpx -silent -status-code \
        -follow-redirects -tls-probe -random-agent -fr \
        -o httpx-output.txt || {
        echo -e "${RED}[!] HTTPX failed${NC}"
        exit 1
    }
    
    total_live=$(wc -l < httpx-output.txt)
    echo -e "${GREEN}[✓] HTTPX completed. Found $total_live live URLs${NC}"
    
    echo -e "${YELLOW}[*] Running Nuclei for vulnerability scanning...${NC}"
    cd "$RESULTS_DIR/vulnerabilities"
    cat "$RESULTS_DIR/probed/httpx-output.txt" | nuclei -headless -sresp \
        -rate-limit "$RATE_LIMIT" -concurrency "$THREADS" \
        -severity critical,high,medium -tags login,auth,exposure,api \
        -markdown-export "$RESULTS_DIR/vulnerabilities/report" \
        -H "User-Agent: $USER_AGENT" -tlsi -stats || {
        echo -e "${RED}[!] Nuclei failed${NC}"
        exit 1
    }
    
    echo -e "${GREEN}[✓] Nuclei completed. Report saved in $RESULTS_DIR/vulnerabilities/report${NC}"
}

# Function to generate a summary report
generate_report() {
    echo -e "\n${BLUE}[+] Generating Summary Report${NC}"
    
    REPORT_FILE="$RESULTS_DIR/recon-report.md"
    
    echo "# Reconnaissance Report for $TARGET_URL" > "$REPORT_FILE"
    echo "Generated on: $(date)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    echo "## Summary" >> "$REPORT_FILE"
    echo "- Target URL: $TARGET_URL" >> "$REPORT_FILE"
    
    if [ -f "$RESULTS_DIR/urls/katana-output.txt" ]; then
        total_urls=$(wc -l < "$RESULTS_DIR/urls/katana-output.txt")
        echo "- Total URLs discovered: $total_urls" >> "$REPORT_FILE"
    fi
    
    if [ -f "$RESULTS_DIR/probed/httpx-output.txt" ]; then
        total_live=$(wc -l < "$RESULTS_DIR/probed/httpx-output.txt")
        echo "- Live URLs: $total_live" >> "$REPORT_FILE"
    fi
    
    if [ -d "$RESULTS_DIR/vulnerabilities/report" ]; then
        echo "- Vulnerability report: $RESULTS_DIR/vulnerabilities/report" >> "$REPORT_FILE"
    fi
    
    echo "" >> "$REPORT_FILE"
    echo "## Next Steps" >> "$REPORT_FILE"
    echo "- Review Nuclei markdown report for vulnerabilities" >> "$REPORT_FILE"
    echo "- Manually verify high and critical findings" >> "$REPORT_FILE"
    echo "- Investigate exposed APIs and authentication endpoints" >> "$REPORT_FILE"
    
    echo -e "${GREEN}[✓] Report generated: $REPORT_FILE${NC}"
}

# Main function
main() {
    if [ -z "$TARGET_URL" ]; then
        get_target_url
    fi
    
    setup_directories
    check_prerequisites
    load_config
    start_time=$(date +%s)
    
    recon_pipeline
    generate_report
    
    end_time=$(date +%s)
    execution_time=$((end_time - start_time))
    hours=$((execution_time / 3600))
    minutes=$(( (execution_time % 3600) / 60 ))
    seconds=$((execution_time % 60))
    
    echo -e "\n${GREEN}[✓] Reconnaissance completed in ${hours}h ${minutes}m ${seconds}s${NC}"
    echo -e "${GREEN}[✓] Results saved to: $RESULTS_DIR${NC}"
    echo -e "${GREEN}[✓] Report available at: $REPORT_FILE${NC}"
}

main "$@"