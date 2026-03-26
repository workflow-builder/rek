
# REK - Reconnaissance Toolkit (Cross-Platform Edition)

**A Modern Recon Playbook for Bug Bounty Hunters**

REK is a comprehensive reconnaissance toolkit designed for ethical hackers and bug bounty hunters. It provides automated reconnaissance pipelines through sophisticated playbooks, along with modular subdomain enumeration, HTTP status checking, directory scanning, and email search capabilities.

This branch is a modified Cross-Platform edition that features Python scripts for the install and playbook scripts.

**Authors:** Jayresearcher, NarutoX, Ninja, jackb898


## 🤖 LLM Assistant (Local + Remote)

REK now includes an LLM assistant for recon guidance without removing existing workflows.

- **Local mode** (default): uses an Ollama-compatible endpoint (`/api/generate`)
- **Remote mode**: uses an OpenAI-compatible Chat Completions endpoint (`/chat/completions`)
- **Config storage**: optional saved config at `~/.rek_llm_config.json` (chmod `600`)

### CLI Examples

```bash
# Local model
python3 rek.py --llm-prompt "Suggest recon steps for example.com" --llm-provider local --llm-model llama3.1

# Remote API (OpenAI-compatible)
python3 rek.py --llm-prompt "Prioritize my findings" --llm-provider remote --llm-api-key sk-***
```

### Interactive Mode

Run `python3 rek.py` and select **REK LLM Assistant** from the main menu to:
1. Ask with local model
2. Ask with remote API
3. Save/update default provider/model/URLs/API key

## 🚀 Automated Playbook System

### Core Playbook Features
The REK toolkit includes two main automated reconnaissance playbooks:

- **[rek-playbook-v1.py](playbook/rek-playbook-v1.py)**: Enhanced version with advanced features and better error handling
- **[rek-playbook-v2.py](playbook/rek-playbook-v2.py)**: Enhanced URL crawler with better outcomes
- **[rek-playbook.py](playbook/rek-playbook.py)**: Standard reconnaissance pipeline

Note these are now Python scripts with the same functionality as the Shell scripts. If you are on a Unix system, you can use either the .sh or the .py versions. On Windows you must use the Python versions.

### Quick Start with Playbooks

#### Interactive Playbook Execution (Recommended)
```bash
# Run the interactive menu system
python3 rek.py

# Select option 1: Run Recon Playbook
# Choose your preferred playbook version (can use .sh versions on Unix, or use Python version on Unix or Windows)
# Enter target domain and thread count
# The system automatically installs dependencies and runs the playbook
```

The interactive mode provides:
- Automatic dependency installation via `install-script.sh` or `install-script.py`
- Playbook version selection
- Real-time output streaming
- Error handling and validation

#### Direct Playbook Execution
For Linux:
```bash
# Make playbook executable
chmod +x playbook/rek-playbook-v1.sh

# Run basic reconnaissance
./playbook/rek-playbook-v1.sh -d example.com

# Run with custom configuration
./playbook/rek-playbook-v1.sh -d example.com -t 200 --chaos-key YOUR_KEY --github-token YOUR_TOKEN

# Skip specific phases
./playbook/rek-playbook-v1.sh -d example.com --skip-portscan --skip-jsanalysis
```

For Windows: 
```
# Run basic reconnaissance
python ./playbook/rek-playbook-v1.py -d example.com

# Run with custom configuration
python ./playbook/rek-playbook-v1.py -d example.com -t 200 --chaos-key YOUR_KEY --github-token YOUR_TOKEN

# Skip specific phases
python ./playbook/rek-playbook-v1.sh -d example.com --skip-portscan --skip-jsanalysis
```
#### Manual Installation
For Linux:
```bash
# Install all prerequisites and tools
chmod +x playbook/install-script.sh
./playbook/install-script.sh
```

For Windows:
```bash
# Install all prerequisites and tools
python ./playbook/install-script.py
```


## 🖥️ Web UI (Control Center)

REK now includes a lightweight built-in Python web UI to simplify navigation, monitor live run logs, and inspect generated results without digging through folders manually.

### Features
- Start recon playbooks (`v1`, `v2`, `standard`) from a browser form.
- Track scan status (`queued`, `running`, `completed`, `failed`) with persisted job history in `ui_runs/jobs.json`.
- Monitor logs with auto-refresh on a dedicated log page.
- Browse result files under `results/` directly from the UI.
- View an architecture-at-a-glance panel summarizing REK pipeline phases for faster navigation.

### Run the UI
```bash
pip install -r requirements.txt
python3 ui_app.py
```
Then open: `http://localhost:5000`

## 📋 Playbook Architecture Wireframe

### High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         REK PLAYBOOK SYSTEM ARCHITECTURE                        │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐
│   User Input    │    │  Configuration  │    │  Tool Manager   │    │   Results   │
│                 │    │    System       │    │                 │    │  Processor  │
│ • Domain Name   │────│ • API Keys      │────│ • Dependency    │────│ • Markdown  │
│ • CLI Arguments │    │ • Thread Count  │    │   Checking      │    │   Reports   │
│ • Pipeline      │    │ • Skip Flags    │    │ • Installation  │    │ • CSV Files │
│   Settings      │    │ • Tool Paths    │    │ • Version Check │    │ • Cleanup   │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────┘
         │                       │                       │                       │
         └───────────────────────┼───────────────────────┼───────────────────────┘
                                 │                       │
         ┌───────────────────────▼───────────────────────▼───────────────────────┐
         │                    CORE PLAYBOOK ENGINE                               │
         │                                                                       │
         │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐      │
         │  │   Phase 1-2     │  │   Phase 3-4     │  │   Phase 5-8     │      │
         │  │   Subdomain     │  │  Live Detection │  │   Content &     │      │
         │  │   Discovery     │  │  & Port Scan    │  │  Vulnerability  │      │
         │  └─────────────────┘  └─────────────────┘  └─────────────────┘      │
         └───────────────────────────────────────────────────────────────────────┘
                                        │
         ┌──────────────────────────────▼──────────────────────────────────────┐
         │                    EXTERNAL TOOL INTEGRATIONS                       │
         │                                                                     │
         │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │
         │  │ Subdomain   │ │ HTTP/Port   │ │ Content     │ │ Analysis    │  │
         │  │ Tools       │ │ Scanners    │ │ Discovery   │ │ Tools       │  │
         │  │             │ │             │ │             │ │             │  │
         │  │ • Subfinder │ │ • HTTPx     │ │ • Gospider  │ │ • GF        │  │
         │  │ • Assetfind │ │ • Naabu     │ │ • Katana    │ │ • Cariddi   │  │
         │  │ • Findomain │ │ • Puredns   │ │ • GAU       │ │ • GetJS     │  │
         │  │ • Chaos     │ │             │ │             │ │             │  │
         │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘  │
         └─────────────────────────────────────────────────────────────────────┘
```

### Detailed Playbook Flow Architecture

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                           RECONNAISSANCE PIPELINE FLOW                            │
└───────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   PHASE 1   │──▶│   PHASE 2   │──▶│   PHASE 3   │──▶│   PHASE 4   │──▶│   PHASE 5   │
│  Subdomain  │   │  Subdomain  │   │    Live     │   │    Port     │   │  Content    │
│ Enumeration │   │ Permutation │   │ Detection   │   │  Scanning   │   │ Discovery   │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
       │                 │                 │                 │                 │
       ▼                 ▼                 ▼                 ▼                 ▼
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│• Subfinder  │   │• DNSGen     │   │• HTTPx      │   │• Naabu      │   │• Gospider   │
│• Assetfinder│   │• Gotator    │   │• Response   │   │• Port List  │   │• Katana     │
│• Findomain  │   │• Goaltdns   │   │  Analysis   │   │• Service    │   │• GAU        │
│• Chaos API  │   │• Permute    │   │• Tech Stack │   │  Detection  │   │• Sitemap    │
│• GitHub API │   │• Puredns    │   │• Headers    │   │• HTTPx Port │   │• Robots.txt │
│• GitLab API │   │• Resolve    │   │• Status     │   │  Probe      │   │• JS Files   │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘

         │                                                                        │
         ▼                                                                        ▼
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   PHASE 6   │──▶│   PHASE 7   │──▶│   PHASE 8   │──▶│  REPORTING  │──▶│   CLEANUP   │
│Vulnerability│   │  Endpoint   │   │ JavaScript  │   │  & Summary  │   │& Archival   │
│  Analysis   │   │Categorization│   │  Analysis   │   │  Generation │   │             │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
       │                 │                 │                 │                 │
       ▼                 ▼                 ▼                 ▼                 ▼
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│• GF Patterns│   │• File Types │   │• GetJS      │   │• Markdown   │   │• Archive    │
│• XSS Filter │   │• JSON Files │   │• Secret     │   │  Report     │   │• Temp File  │
│• SQLi Filter│   │• Config     │   │  Detection  │   │• Statistics │   │  Removal    │
│• SSRF Filter│   │• Backup     │   │• Cariddi    │   │• Findings   │   │• Results    │
│• LFI Filter │   │• PDF Files  │   │• API Keys   │   │• Next Steps │   │  Structure  │
│• RCE Filter │   │• Log Files  │   │• Tokens     │   │• Timeline   │   │• Validation │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
```

### Tool Integration Matrix

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          TOOL INTEGRATION & DATA FLOW                           │
└─────────────────────────────────────────────────────────────────────────────────┘

    INPUT                 PROCESSING                      OUTPUT
┌─────────────┐     ┌─────────────────────────┐     ┌─────────────────────┐
│   Domain    │────▶│    Subdomain Tools      │────▶│  Raw Subdomains     │
│ example.com │     │                         │     │                     │
└─────────────┘     │ ┌─────────────────────┐ │     │ • subfinder.txt     │
                    │ │   Subfinder         │ │     │ • assetfinder.txt   │
                    │ │   • DNS Brute       │ │     │ • findomain.txt     │
                    │ │   • CT Logs         │ │     │ • chaos.txt         │
                    │ │   • Certificate     │ │     │ • github-subs.txt   │
                    │ │     Transparency    │ │     │ • gitlab-subs.txt   │
                    │ └─────────────────────┘ │     └─────────────────────┘
                    │                         │               │
                    │ ┌─────────────────────┐ │               ▼
                    │ │   Assetfinder       │ │     ┌─────────────────────┐
                    │ │   • API Sources     │ │     │   Deduplicated      │
                    │ │   • Search Engines  │ │────▶│   Subdomain List    │
                    │ └─────────────────────┘ │     │                     │
                    │                         │     │ • sorted-subs.txt   │
                    │ ┌─────────────────────┐ │     │ • 1000+ subdomains  │
                    │ │   External APIs     │ │     └─────────────────────┘
                    │ │   • Chaos Project   │ │               │
                    │ │   • GitHub Commits  │ │               ▼
                    │ │   • GitLab Repos    │ │     ┌─────────────────────┐
                    │ └─────────────────────┘ │     │    Permutation      │
                    └─────────────────────────┘     │     Generation      │
                                                    │                     │
                                                    │ • DNSGen            │
                                                    │ • Gotator           │
                                                    │ • Goaltdns          │
                                                    │ • Custom Wordlists  │
                                                    └─────────────────────┘
                                                              │
                                                              ▼
                                                    ┌─────────────────────┐
                                                    │   DNS Resolution    │
                                                    │                     │
                                                    │ • Puredns           │
                                                    │ • Mass DNS          │
                                                    │ • Custom Resolvers  │
                                                    │ • Validation        │
                                                    └─────────────────────┘
                                                              │
                                                              ▼
                                                    ┌─────────────────────┐
                                                    │   Live Detection    │
                                                    │                     │
                                                    │ • HTTPx Probing     │
                                                    │ • Status Codes      │
                                                    │ • Technology Stack  │
                                                    │ • Response Headers  │
                                                    └─────────────────────┘
```

### Configuration and Pipeline Management

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        CONFIGURATION & PIPELINE SYSTEM                          │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Configuration  │    │   Pipeline      │    │    Results      │
│    Manager      │    │   Executor      │    │   Management    │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ config.conf │ │    │ │ Phase Logic │ │    │ │ Timestamped │ │
│ │             │ │    │ │             │ │    │ │ Directories │ │
│ │ • API Keys  │ │◄──►│ │ • Execution │ │◄──►│ │             │ │
│ │ • Threads   │ │    │ │   Control   │ │    │ │ • Subdomains│ │
│ │ • Timeouts  │ │    │ │ • Skip Logic│ │    │ │ • Endpoints │ │
│ │ • Paths     │ │    │ │ • Error     │ │    │ │ • JS Files  │ │
│ └─────────────┘ │    │ │   Handling  │ │    │ │ • Vulns     │ │
│                 │    │ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │                 │    │                 │
│ │ Pipeline    │ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Storage     │ │    │ │ Progress    │ │    │ │   Report    │ │
│ │             │ │    │ │ Tracking    │ │    │ │ Generation  │ │
│ │ • Saved     │ │    │ │             │ │    │ │             │ │
│ │   Settings  │ │    │ │ • Spinner   │ │    │ │ • Markdown  │ │
│ │ • Domain    │ │    │ │ • Timers    │ │    │ │ • Summary   │ │
│ │   History   │ │    │ │ • Logging   │ │    │ │ • Statistics│ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Tool Installation Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        AUTOMATED INSTALLATION SYSTEM                            │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    System       │    │   Language      │    │     Tool        │
│   Detection     │    │   Runtimes      │    │  Installation   │
│                 │    │                 │    │                 │
│ • OS Type       │    │ • Go Lang       │    │ • GitHub Repos  │
│ • Architecture  │────│ • Python 3      │────│ • Binary Downloads│
│ • Package Mgr   │    │ • Node.js       │    │ • Compilation   │
│ • Permissions   │    │ • Dependencies  │    │ • Path Setup    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌───────────────────────▼───────────────────────┐
         │              VERIFICATION SYSTEM              │
         │                                               │
         │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
         │  │Tool Version │ │ Dependency  │ │ Integration │
         │  │  Checking   │ │  Validation │ │   Testing   │
         │  │             │ │             │ │             │
         │  │ • Command   │ │ • Libraries │ │ • Tool      │
         │  │   Available │ │ • Paths     │ │   Execution │
         │  │ • Version   │ │ • Resolvers │ │ • Output    │
         │  │   Compare   │ │ • Wordlists │ │   Parsing   │
         │  └─────────────┘ └─────────────┘ └─────────────┘
         └───────────────────────────────────────────────────┘
```

## 🛠️ Playbook Command Reference

### Basic Usage
(Choose .sh if Unix, or .py if Windows system)
```bash
# Quick reconnaissance
./playbook/rek-playbook-v1.[sh/py] -d target.com

# Custom thread count
./playbook/rek-playbook-v1.[sh/py] -d target.com -t 200

# Use API keys for enhanced results
./playbook/rek-playbook-v1.[sh/py] -d target.com \
  --chaos-key YOUR_CHAOS_KEY \
  --github-token YOUR_GITHUB_TOKEN \
  --gitlab-token YOUR_GITLAB_TOKEN
```

### Phase Control
(Choose .sh if Unix, or .py if Windows system)
```bash
# Skip specific phases
./playbook/rek-playbook-v1.[sh/py] -d target.com \
  --skip-portscan \
  --skip-jsanalysis \
  --skip-vulnanalysis

# Run only subdomain discovery
./playbook/rek-playbook-v1.[sh/py] -d target.com \
  --skip-permutation \
  --skip-fingerprint \
  --skip-portscan \
  --skip-spider \
  --skip-vulnanalysis \
  --skip-jsanalysis
```

### Configuration Options
```bash
# Custom configuration file
./playbook/rek-playbook-v1.[sh/py] -d target.com -c /path/to/config.conf

# Custom output directory
./playbook/rek-playbook-v1.[sh/py] -d target.com -o /path/to/results

# Help and options
./playbook/rek-playbook-v1.[sh/py] --help
```

## 📊 Output Structure

### Directory Layout
```
results/
└── target.com-20240101-120000/
    ├── subdomains/
    │   ├── sorted-subs.txt
    │   ├── subs-alive.txt
    │   ├── httpx-output.txt
    │   └── subs-portscanned.txt
    ├── endpoints/
    │   ├── spider-output.txt
    │   ├── json-endpoints.txt
    │   └── backup-endpoints.txt
    ├── js/
    │   ├── getjs-output.txt
    │   └── js-secrets.txt
    ├── vulnerabilities/
    │   ├── checkfor-xss.txt
    │   ├── checkfor-sqli.txt
    │   └── checkfor-ssrf.txt
    └── recon-report.md
```

### Generated Report
- **Markdown Summary**: Complete reconnaissance report with statistics
- **CSV Exports**: Machine-readable data for further analysis
- **Categorized Findings**: Organized by vulnerability type and file extension
- **Next Steps**: Actionable recommendations for manual testing

## 🔧 Additional REK Features

### Core Modules
- **Subdomain Enumeration**: Multi-source subdomain discovery using DNS Dumpster, Certificate Transparency, and DNS brute-forcing
- **HTTP Status Checking**: Concurrent HTTP/HTTPS probing with detailed response analysis
- **Directory Scanning**: Technology-aware directory and file discovery with screenshot capabilities
- **Email Search**: GitHub-based email harvesting with breach detection via HIBP

### Advanced Capabilities
- **Technology Detection**: Automatic web technology identification for targeted scanning
- **Parallel Processing**: Async/await implementation for maximum performance
- **Screenshot Capture**: Automated visual documentation of discovered endpoints
- **Breach Intelligence**: Integration with Have I Been Pwned API
- **Custom Wordlists**: Domain-specific wordlist generation and global wordlist learning

## 🚀 Installation

### Prerequisites
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Chrome/Chromium for screenshot functionality
# Ubuntu/Debian:
sudo apt-get install chromium-browser

# macOS:
brew install chromium
```

### Tool Dependencies
The toolkit includes installation scripts for external tools:
```bash
# Run the installation script for your platform (.sh for Unix, .py for Windows or Unix)
chmod +x playbook/install-script.[sh/py]
./playbook/install-script.[sh/py]
```

## 📚 Technical Usage

### Command Line Interface

#### 1. Subdomain Enumeration
```bash
# Basic subdomain enumeration
python3 rek.py -d example.com -o results.txt

# Advanced enumeration with custom wordlist and GitHub token
python3 rek.py -d example.com \
  -w wordlists/subdomains-top5000.txt \
  --token ghp_your_github_token \
  -t 15 -c 100 --limit-commits 50
```

#### 2. HTTP Status Checking
```bash
# Check HTTP status for discovered subdomains
python3 rek.py --input results.txt -o http_results.csv -t 10 -c 50
```

#### 3. Directory Scanning
```bash
# Scan live subdomains for directories and files
python3 rek.py --input http_results.csv --status 200,301,403 \
  --dir-wordlist wordlists/common-paths.txt \
  --depth 5 -t 10 -c 30
```

#### 4. Email Search
```bash
# Search by domain
python3 rek.py --email-domain example.com \
  --token ghp_your_github_token \
  --hibp-key your_hibp_api_key \
  -o email_results.csv

# Search by organization/username
python3 rek.py --org microsoft \
  --token ghp_your_github_token \
  --limit-commits 100
```

### Interactive Mode

#### Main Menu Options
```bash
python3 rek.py

# Main Menu Options:
# 1. Run Recon Playbook    - Execute automated reconnaissance playbooks
# 2. Subdomain Enumeration - Discover subdomains using multiple techniques  
# 3. HTTP Status Checking  - Check HTTP status of discovered domains
# 4. Directory Scanning    - Scan for directories and files on web servers
# 5. REK Email Search      - Search for email addresses in GitHub repositories
# 6. REK Wordlist Generator- Generate and download wordlists for testing
# 7. Exit                  - Exit the application
```

### Command Line Help
```bash
# Get detailed help information
python3 rek.py --help

# Or use the short form
python3 rek.py -h
```

### Detailed Parameter Reference

#### Subdomain Enumeration Parameters
```bash
python3 rek.py -d example.com [OPTIONS]

Required:
  -d, --domain DOMAIN         Target domain (e.g., example.com)

Optional:
  -w, --subdomain-wordlist    Custom wordlist for subdomain enumeration
  -o, --output FILE          Output file (default: results.txt)
  --token TOKEN              GitHub Personal Access Token for enhanced results
  --limit-commits N          Max commits to scan per repo (default: 50)
  --skip-forks              Skip forked repositories during GitHub search
  -t, --timeout N           Request timeout in seconds (default: 10)
  -c, --concurrency N       Maximum concurrent requests (default: 50)
  -r, --retries N           Number of retries for failed requests (default: 3)
  --silent                  Run in silent mode (minimal output)

Example:
python3 rek.py -d example.com -w wordlists/subdomains.txt --token ghp_xxx -t 15 -c 100
```

#### HTTP Status Checking Parameters
```bash
python3 rek.py --input FILE [OPTIONS]

Required:
  --input FILE              Input file with URLs to check

Optional:
  -o, --output FILE         Output CSV file (default: http_results.csv)
  -t, --timeout N           Request timeout in seconds (default: 10)
  -c, --concurrency N       Maximum concurrent requests (default: 50)
  --silent                  Run in silent mode (minimal output)

Example:
python3 rek.py --input results.txt -o http_results.csv -t 15 -c 100
```

#### Directory Scanning Parameters
```bash
python3 rek.py --input FILE --status CODES [OPTIONS]
# OR
python3 rek.py --url URL [OPTIONS]

Required (Option 1):
  --input FILE              Input CSV file with URLs and status codes
  --status CODES            Comma-separated status codes (e.g., 200,301,403)

Required (Option 2):
  --url URL                 Single URL to scan directly

Optional:
  --dir-wordlist FILE       Custom wordlist for directory scanning
  --depth N                 Maximum crawling depth (1-10, default: 5)
  -t, --timeout N           Request timeout in seconds (default: 10)
  -c, --concurrency N       Maximum concurrent requests (default: 50)
  --silent                  Run in silent mode (minimal output)

Examples:
python3 rek.py --input http_results.csv --status 200,301,403 --depth 3
python3 rek.py --url https://example.com --dir-wordlist wordlists/common.txt
```

#### Email Search Parameters
```bash
# Search by domain
python3 rek.py --email-domain DOMAIN [OPTIONS]

# Search by GitHub username
python3 rek.py --email-username USERNAME [OPTIONS]

# Search by GitHub organization
python3 rek.py --org ORGANIZATION [OPTIONS]

Required (choose one):
  --email-domain DOMAIN     Domain for email search
  --email-username USER     GitHub username for email search
  --org ORGANIZATION        GitHub organization for email search

Optional:
  --token TOKEN             GitHub Personal Access Token (recommended)
  --hibp-key KEY            Have I Been Pwned API key for breach checking
  --limit-commits N         Max commits to scan per repo (default: 50)
  --skip-forks              Skip forked repositories during search
  -o, --output FILE         Output CSV file (default: email_results.csv)
  -t, --timeout N           Request timeout in seconds (default: 10)
  --silent                  Run in silent mode (minimal output)

Examples:
python3 rek.py --email-domain example.com --token ghp_xxx --hibp-key xxx
python3 rek.py --org microsoft --token ghp_xxx --limit-commits 100
python3 rek.py --email-username johndoe --token ghp_xxx --skip-forks
```

#### REK Wordlist Generator
The wordlist generator is available through the interactive menu (option 6) and provides:

**Features:**
- Download SecLists wordlists by category
- Generate domain-specific custom wordlists
- Merge multiple wordlists with deduplication
- List and manage existing wordlists
- Clean up old or duplicate wordlists

**Categories Available:**
- Subdomains (basic and advanced)
- Directories (basic and advanced) 
- Files (basic and advanced)
- Parameters (basic and advanced)
- Vulnerabilities (XSS, SQLi, LFI, RCE)
- API endpoints and methods

**Technology-Specific Wordlists:**
- WordPress, Drupal, Joomla
- Laravel, Django, Node.js
- Apache, Nginx, IIS
- PHP, Python, Java

**Usage:**
```bash
# Access through interactive menu
python3 rek.py
# Select option 6: REK Wordlist Generator

# Or run the standalone generator
python3 advanced_wordlist_generator.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems.
