#!/bin/bash

# ╔═════════════════════════════════════════════════════════════╗
# ║  Streamlined Recon Playbook for Shodan Data Retrieval (v3)  ║
# ║  Fetches IP addresses, hostnames, ports, and URLs in CSV    ║
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
echo "║   Streamlined Recon Playbook (v3): Fetch IP, Hostnames, Ports, URLs from  ║"
echo "║   Shodan in CSV Format                                                    ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Variables
WORKING_DIR="${RECON_TOOLKIT_DIR:-$(dirname "$(realpath "$0")")}"
TOOLS_DIR="${TOOLS_DIR:-$WORKING_DIR/tools}"
CONFIG_FILE="${CONFIG_PATH:-$WORKING_DIR/config.conf}"
RESULTS_DIR=""
TARGET=""
SHODAN_API_KEY=""
export PATH="$TOOLS_DIR:$HOME/.local/bin:$PATH"
export PYTHONWARNINGS=ignore

# Determine shuf command (gshuf on macOS, shuf elsewhere)
if command -v gshuf >/dev/null 2>&1; then
    SHUF_CMD="gshuf"
else
    SHUF_CMD="shuf"
fi

# Create required directories
setup_directories() {
    echo -e "${BLUE}[+] Setting up directories...${NC}"
    mkdir -p "$WORKING_DIR" "$TOOLS_DIR" "$RESULTS_DIR"
    
    timestamp=$(date +"%Y%m%d-%H%M%S")
    if [[ $TARGET =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TARGET_NAME=$(echo "$TARGET" | tr '.' '-')
    else
        TARGET_NAME=$(echo "$TARGET" | sed 's/[^a-zA-Z0-9]/-/g')
    fi
    RESULTS_DIR="$WORKING_DIR/results/$TARGET_NAME-$timestamp"
    mkdir -p "$RESULTS_DIR"
    
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
    local tools=("shodan" "$SHUF_CMD")
    
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            printf "%-20s ${GREEN}%-10s${NC}\n" "$tool" "Installed"
        else
            printf "%-20s ${RED}%-10s${NC}\n" "$tool" "Missing"
            all_tools_installed=false
        fi
    done
    
    if [ "$all_tools_installed" = false ]; then
        echo -e "\n${YELLOW}[!] Some prerequisites are missing. Please run install-script-v3.sh${NC}"
        exit 1
    else
        echo -e "\n${GREEN}[✓] All prerequisites are installed${NC}"
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

# Function to load configuration
load_config() {
    echo -e "${BLUE}[+] Loading configuration...${NC}"
    
    if check_shodan_init; then
        echo -e "${GREEN}[✓] Shodan CLI is initialized${NC}"
        if [ -f "$CONFIG_FILE" ]; then
            source "$CONFIG_FILE"
            [ -z "$SHODAN_API_KEY" ] && echo -e "${YELLOW}[!] SHODAN_API_KEY is empty in config${NC}"
        fi
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
    
    echo -e "${GREEN}[✓] Configuration loaded${NC}"
}

# Function to get target domain or IP from user
get_target() {
    echo -e "${YELLOW}[?] Enter the target domain or IP (e.g., example.com or 8.8.8.8):${NC}"
    read -r TARGET
    
    if [ -z "$TARGET" ]; then
        echo -e "${RED}[!] No target provided. Exiting.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[✓] Target set to: $TARGET${NC}"
}

# Shodan query pipeline
shodan_pipeline() {
    echo -e "\n${BLUE}[+] Starting Shodan Query Pipeline${NC}"
    
    USER_AGENT=$($SHUF_CMD -n 1 -e \
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
        "Mozilla/5.0 (X11; Linux x86_64)" \
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
    
    if [[ $TARGET =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        QUERY="ip:$TARGET"
    else
        QUERY="hostname:$TARGET"
    fi
    
    echo -e "${YELLOW}[*] Querying Shodan for $QUERY...${NC}"
    cd "$RESULTS_DIR" || { echo -e "${RED}[!] Failed to change to $RESULTS_DIR${NC}"; exit 1; }
    if ! shodan download shodan-results "$QUERY" --limit 1000 2> shodan-error.log; then
        echo -e "${RED}[!] Shodan download failed${NC}"
        cat shodan-error.log
        exit 1
    fi
    
    # Check if results file is empty
    if [ ! -s shodan-results.json.gz ]; then
        echo -e "${RED}[!] No results retrieved. Possible causes:${NC}"
        echo -e "${RED}    - Insufficient Shodan query credits (check with 'shodan info')${NC}"
        echo -e "${RED}    - Invalid query or no matching results${NC}"
        echo -e "${RED}    - Network connectivity issues${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}[*] Parsing Shodan results to CSV...${NC}"
    if ! shodan parse --fields ip_str,hostnames,port,http.host --separator "," shodan-results.json.gz > shodan-output.csv 2> parse-error.log; then
        echo -e "${RED}[!] Shodan parse failed${NC}"
        cat parse-error.log
        exit 1
    fi
    
    sed -i 's/,,$/,N/A/' shodan-output.csv 2>/dev/null || echo -e "${YELLOW}[!] Warning: Could not modify shodan-output.csv${NC}"
    
    total_records=$(wc -l < shodan-output.csv)
    if [ "$total_records" -eq 0 ]; then
        echo -e "${RED}[!] No records found in CSV output${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓] Shodan query completed. Found $total_records records${NC}"
}

# Function to generate a summary report
generate_report() {
    echo -e "\n${BLUE}[+] Generating Summary Report${NC}"
    
    REPORT_FILE="$RESULTS_DIR/shodan-report.md"
    
    {
        echo "# Shodan Reconnaissance Report for $TARGET"
        echo "Generated on: $(date)"
        echo ""
        echo "## Summary"
        echo "- Target: $TARGET"
        
        if [ -f "$RESULTS_DIR/shodan-output.csv" ]; then
            total_records=$(wc -l < "$RESULTS_DIR/shodan-output.csv")
            echo "- Total records retrieved: $total_records"
            echo "- CSV output: $RESULTS_DIR/shodan-output.csv"
        fi
        
        echo ""
        echo "## CSV Format"
        echo "The CSV file contains the following columns:"
        echo "- **ip_str**: IP address of the host"
        echo "- **hostnames**: Associated hostnames (comma-separated)"
        echo "- **port**: Open port number"
        echo "- **http.host**: URL or hostname from HTTP banner (N/A if not HTTP)"
        
        echo ""
        echo "## Next Steps"
        echo "- Review the CSV file for detailed results"
        echo "- Verify open ports and URLs for potential vulnerabilities"
        echo "- Cross-reference hostnames with other reconnaissance tools"
    } > "$REPORT_FILE"
    
    echo -e "${GREEN}[✓] Report generated: $REPORT_FILE${NC}"
}

# Main function
main() {
    if [ -z "$TARGET" ]; then
        get_target
    fi
    
    setup_directories
    check_prerequisites
    load_config
    start_time=$(date +%s)
    
    shodan_pipeline
    generate_report
    
    end_time=$(date +%s)
    execution_time=$((end_time - start_time))
    hours=$((execution_time / 3600))
    minutes=$(( (execution_time % 3600) / 60 ))
    seconds=$((execution_time % 60))
    
    echo -e "\n${GREEN}[✓] Shodan reconnaissance completed in ${hours}h ${minutes}m ${seconds}s${NC}"
    echo -e "${GREEN}[✓] Results saved to: $RESULTS_DIR/shodan-output.csv${NC}"
    echo -e "${GREEN}[✓] Report available at: $REPORT_FILE${NC}"
}

main "$@"