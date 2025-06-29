
#!/usr/bin/env python3
"""
REK Wordlist Generator
Intelligent wordlist generation for domain-specific reconnaissance
"""

import os
import sys
import json
import requests
import argparse
import threading
import time
from urllib.parse import urlparse, urljoin
from pathlib import Path
import subprocess
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from collections import defaultdict
from termcolor import colored

class REKWordlistGenerator:
    def __init__(self, silent: bool = False, domain: str = None):
        self.silent = silent
        self.domain = domain
        self.seclists_base_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
        
        if domain:
            self.wordlists_dir = f"{domain}-wordlists"
            self.output_dir = f"{domain}-wordlists/generated"
        else:
            self.wordlists_dir = "wordlists"
            self.output_dir = "generated_wordlists"
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        
        # Initialize wordlist containers
        self.global_wordlist = set()
        self.subdomain_wordlist = set()
        self.directory_wordlist = set()
        
        # Technology-specific patterns
        self.tech_patterns = {
            'wordpress': ['wp-admin', 'wp-login.php', 'wp-content', 'wp-includes', 'xmlrpc.php', 'wp-config.php', 'wp-load.php'],
            'drupal': ['sites/default', 'modules', 'themes', 'core', 'install.php', 'settings.php'],
            'php': ['phpinfo.php', 'admin.php', 'config.php', 'info.php', 'install.php', 'setup.php'],
            'apache': ['server-status', 'server-info', '.htaccess', 'access_log'],
            'nginx': ['nginx_status', 'stub_status', 'error.log'],
            'django': ['admin', 'api', 'static', 'media', 'debug', 'urls.py', 'settings.py'],
            'laravel': ['.env', 'artisan', 'storage', 'vendor', 'bootstrap', 'routes.php'],
            'java': ['WEB-INF', 'META-INF', 'struts', 'actuator', 'jsp', 'servlet'],
            'javascript': ['js', 'scripts', 'assets', 'bundle.js', 'min.js', 'vendor.js'],
            'cms': ['admin', 'login', 'dashboard', 'content', 'editor', 'manage', 'control']
        }
        
        # Common subdomain patterns
        self.subdomain_patterns = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "www1", "beta", "webserver",
            "staging", "api", "cdn", "shop", "store", "portal", "demo", "secure"
        ]
        
        self.setup_directories()

    def setup_directories(self):
        """Create output directories"""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(f"{self.wordlists_dir}/temp").mkdir(parents=True, exist_ok=True)

    def log(self, message, color="white"):
        """Log message if not in silent mode"""
        if not self.silent:
            print(colored(message, color))

    def analyze_domain(self):
        """Analyze target domain to generate custom wordlist"""
        if not self.domain:
            return
            
        self.log(f"[*] Analyzing domain: {self.domain}", "yellow")
        
        # Extract domain components
        domain_parts = self.domain.split('.')
        
        # Add domain name variations
        if len(domain_parts) >= 2:
            base_domain = domain_parts[-2]  # e.g., 'example' from 'example.com'
            
            # Generate variations
            variations = [
                base_domain,
                base_domain + "1", base_domain + "2", base_domain + "01", base_domain + "02",
                base_domain + "_old", base_domain + "_new", base_domain + "_test",
                base_domain + "_dev", base_domain + "_staging", base_domain + "_prod",
                "old_" + base_domain, "new_" + base_domain, "test_" + base_domain,
                "dev_" + base_domain, "staging_" + base_domain, "prod_" + base_domain,
                base_domain + "-old", base_domain + "-new", base_domain + "-test",
                base_domain + "-dev", base_domain + "-staging", base_domain + "-prod"
            ]
            
            self.subdomain_wordlist.update(variations)
            self.directory_wordlist.update([v + "/" for v in variations])
        
        # Try to fetch robots.txt and sitemap
        self.analyze_robots_txt()
        self.analyze_sitemap()

    def analyze_robots_txt(self):
        """Extract paths from robots.txt"""
        try:
            for protocol in ['https', 'http']:
                robots_url = f"{protocol}://{self.domain}/robots.txt"
                response = self.session.get(robots_url, timeout=10, verify=False)
                if response.status_code == 200:
                    self.log(f"[+] Found robots.txt on {protocol}", "green")
                    for line in response.text.split('\n'):
                        if line.strip() and (line.startswith('Disallow:') or line.startswith('Allow:')):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/' and not path.startswith('*'):
                                clean_path = path.lstrip('/').split('?')[0]
                                if clean_path:
                                    self.directory_wordlist.add(clean_path)
                    break
        except Exception as e:
            self.log(f"[!] Error analyzing robots.txt: {e}", "red")

    def analyze_sitemap(self):
        """Extract paths from sitemap.xml"""
        try:
            sitemap_urls = [
                f"https://{self.domain}/sitemap.xml",
                f"http://{self.domain}/sitemap.xml",
                f"https://{self.domain}/sitemap_index.xml",
                f"http://{self.domain}/sitemap_index.xml"
            ]
            
            for sitemap_url in sitemap_urls:
                try:
                    response = self.session.get(sitemap_url, timeout=10, verify=False)
                    if response.status_code == 200:
                        self.log(f"[+] Found sitemap at {sitemap_url}", "green")
                        # Simple regex to extract URLs
                        urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                        for url in urls:
                            parsed = urlparse(url)
                            path = parsed.path.strip('/')
                            if path and '?' not in path:
                                self.directory_wordlist.add(path)
                        break
                except:
                    continue
        except Exception as e:
            self.log(f"[!] Error analyzing sitemap: {e}", "red")

    def detect_technologies(self, url=None):
        """Detect technologies and add relevant wordlists"""
        if not url and self.domain:
            url = f"https://{self.domain}"
        
        if not url:
            return
        
        self.log(f"[*] Detecting technologies for {url}", "yellow")
        
        try:
            # Try to import Wappalyzer
            try:
                from Wappalyzer import Wappalyzer, WebPage
                wappalyzer = Wappalyzer.latest()
                webpage = WebPage.new_from_url(url, headers={'User-Agent': 'Mozilla/5.0'})
                techs = wappalyzer.analyze_with_versions_and_categories(webpage)
                
                self.log(f"[+] Detected technologies: {list(techs.keys())}", "green")
                
                # Add technology-specific wordlists
                for tech, details in techs.items():
                    tech_lower = tech.lower()
                    for pattern_key, patterns in self.tech_patterns.items():
                        if pattern_key in tech_lower:
                            self.directory_wordlist.update(patterns)
                            self.log(f"[+] Added {pattern_key} patterns", "green")
                            
            except ImportError:
                self.log("[!] Wappalyzer not available, using basic detection", "yellow")
                # Basic technology detection through headers and content
                response = self.session.get(url, timeout=10, verify=False)
                headers = response.headers
                content = response.text.lower()
                
                # Check server headers
                server = headers.get('server', '').lower()
                if 'apache' in server:
                    self.directory_wordlist.update(self.tech_patterns['apache'])
                elif 'nginx' in server:
                    self.directory_wordlist.update(self.tech_patterns['nginx'])
                
                # Check content for technology indicators
                if 'wp-content' in content or 'wordpress' in content:
                    self.directory_wordlist.update(self.tech_patterns['wordpress'])
                if 'drupal' in content:
                    self.directory_wordlist.update(self.tech_patterns['drupal'])
                if 'laravel' in content:
                    self.directory_wordlist.update(self.tech_patterns['laravel'])
                    
        except Exception as e:
            self.log(f"[!] Error detecting technologies: {e}", "red")

    def download_seclists(self):
        """Download and process SecLists repository"""
        self.log("[*] Downloading SecLists wordlists...", "yellow")
        
        # Known good wordlist files from SecLists
        seclists_files = {
            "Discovery/DNS/subdomains-top1million-5000.txt": "subdomain",
            "Discovery/Web-Content/common.txt": "directory",
            "Discovery/Web-Content/big.txt": "directory",
            "Discovery/Web-Content/raft-medium-directories.txt": "directory",
            "Discovery/Web-Content/directory-list-2.3-medium.txt": "directory"
        }
        
        for file_path, wordlist_type in seclists_files.items():
            try:
                url = f"{self.seclists_base_url}/{file_path}"
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    self.log(f"[+] Downloaded {file_path}", "green")
                    temp_file = Path(f"{self.wordlists_dir}/temp/temp_{wordlist_type}.txt")
                    temp_file.write_text(response.text, encoding='utf-8')
                    self.process_wordlist_file(temp_file, wordlist_type)
                    temp_file.unlink()
                else:
                    self.log(f"[!] Failed to download {file_path}", "red")
            except Exception as e:
                self.log(f"[!] Error downloading {file_path}: {e}", "red")

    def download_github_wordlists(self):
        """Download wordlists from various GitHub repositories"""
        self.log("[*] Downloading additional wordlists...", "yellow")
        
        # Additional wordlist sources
        repo_files = {
            "assetnote/commonspeak2-wordlists": [
                ("subdomains/subdomains.txt", "subdomain"),
                ("wordlists/paramnames.txt", "directory")
            ],
            "six2dez/OneListForAll": [
                ("onelistforallmicro.txt", "directory")
            ]
        }
        
        for repo, files in repo_files.items():
            for file_path, wordlist_type in files:
                try:
                    url = f"https://raw.githubusercontent.com/{repo}/master/{file_path}"
                    response = self.session.get(url, timeout=30)
                    if response.status_code == 200:
                        self.log(f"[+] Downloaded {repo}/{file_path}", "green")
                        temp_file = Path(f"{self.wordlists_dir}/temp/github_{repo.replace('/', '_')}_{file_path.replace('/', '_')}")
                        temp_file.write_text(response.text, encoding='utf-8')
                        self.process_wordlist_file(temp_file, wordlist_type)
                        temp_file.unlink()
                except Exception as e:
                    self.log(f"[!] Error downloading {repo}/{file_path}: {e}", "red")

    def process_wordlist_file(self, file_path, wordlist_type):
        """Process a wordlist file and add to appropriate set"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#') and len(word) > 0:
                        if wordlist_type == "subdomain":
                            self.subdomain_wordlist.add(word)
                        elif wordlist_type == "directory":
                            self.directory_wordlist.add(word)
                        
                        # Add to global wordlist
                        self.global_wordlist.add(word)
                        
        except Exception as e:
            self.log(f"[!] Error processing {file_path}: {e}", "red")

    def generate_custom_patterns(self):
        """Generate custom patterns based on domain and common patterns"""
        self.log("[*] Generating custom patterns...", "yellow")
        
        # Common directory patterns
        common_dirs = [
            "admin", "administrator", "login", "panel", "dashboard", "control",
            "wp-admin", "wp-content", "wp-includes", "backup", "backups",
            "config", "configuration", "settings", "api", "v1", "v2", "v3",
            "test", "testing", "dev", "development", "staging", "prod",
            "uploads", "files", "images", "img", "css", "js", "assets",
            "include", "includes", "lib", "library", "vendor", "node_modules",
            "tmp", "temp", "cache", "logs", "log", "data", "database", "db"
        ]
        
        # Add to directory wordlist
        self.directory_wordlist.update(common_dirs)
        
        # Generate year-based patterns
        current_year = 2024
        for year in range(current_year - 10, current_year + 2):
            self.directory_wordlist.add(str(year))
            self.subdomain_wordlist.add(str(year))

    def generate_permutations(self):
        """Generate permutations and mutations of existing words"""
        if not self.domain:
            return
            
        self.log("[*] Generating domain-specific permutations...", "yellow")
        
        domain_parts = self.domain.split('.')
        if len(domain_parts) >= 2:
            base_name = domain_parts[-2]
            
            # Generate permutations
            permutations = []
            
            # Number suffixes
            for i in range(1, 20):
                permutations.extend([
                    f"{base_name}{i}",
                    f"{base_name}0{i}",
                    f"{base_name}-{i}",
                    f"{base_name}_{i}"
                ])
            
            # Common prefixes/suffixes
            prefixes = ["dev", "test", "staging", "beta", "alpha", "pre", "old", "new", "tmp", "temp"]
            suffixes = ["dev", "test", "staging", "beta", "prod", "old", "new", "bak", "backup", "tmp"]
            
            for prefix in prefixes:
                permutations.extend([
                    f"{prefix}-{base_name}",
                    f"{prefix}{base_name}",
                    f"{prefix}.{base_name}",
                    f"{prefix}_{base_name}"
                ])
            
            for suffix in suffixes:
                permutations.extend([
                    f"{base_name}-{suffix}",
                    f"{base_name}{suffix}",
                    f"{base_name}.{suffix}",
                    f"{base_name}_{suffix}"
                ])
            
            # Add permutations to both subdomain and directory lists
            self.subdomain_wordlist.update(permutations)
            self.directory_wordlist.update([p + "/" for p in permutations])

    def clean_and_deduplicate(self):
        """Clean and deduplicate wordlists"""
        self.log("[*] Cleaning and deduplicating wordlists...", "yellow")
        
        # Remove empty strings and clean
        self.global_wordlist = {w.strip() for w in self.global_wordlist if w.strip() and len(w.strip()) > 0}
        self.subdomain_wordlist = {w.strip() for w in self.subdomain_wordlist if w.strip() and len(w.strip()) > 0}
        self.directory_wordlist = {w.strip() for w in self.directory_wordlist if w.strip() and len(w.strip()) > 0}
        
        # Remove duplicates and sort
        self.global_wordlist = sorted(list(self.global_wordlist))
        self.subdomain_wordlist = sorted(list(self.subdomain_wordlist))
        self.directory_wordlist = sorted(list(self.directory_wordlist))

    def save_wordlists(self):
        """Save generated wordlists to files"""
        self.log("[*] Saving wordlists...", "yellow")
        
        # Save global wordlist
        global_file = Path(f"{self.output_dir}/global_wordlist.txt")
        global_file.write_text('\n'.join(self.global_wordlist), encoding='utf-8')
        
        # Save subdomain wordlist
        subdomain_file = Path(f"{self.output_dir}/subdomain_wordlist.txt")
        subdomain_file.write_text('\n'.join(self.subdomain_wordlist), encoding='utf-8')
        
        # Save directory wordlist
        directory_file = Path(f"{self.output_dir}/directory_wordlist.txt")
        directory_file.write_text('\n'.join(self.directory_wordlist), encoding='utf-8')
        
        self.log(f"[+] Global wordlist saved: {global_file} ({len(self.global_wordlist)} words)", "green")
        self.log(f"[+] Subdomain wordlist saved: {subdomain_file} ({len(self.subdomain_wordlist)} words)", "green")
        self.log(f"[+] Directory wordlist saved: {directory_file} ({len(self.directory_wordlist)} words)", "green")

    def cleanup(self):
        """Clean up temporary files"""
        temp_dir = Path(f"{self.wordlists_dir}/temp")
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

    def run_interactive(self):
        """Run interactive wordlist generator"""
        if not self.silent:
            print(colored("\n🔧 REK Wordlist Generator", "cyan", attrs=["bold"]))
            print(colored("Intelligent wordlist generation for domain reconnaissance", "cyan"))
        
        # Ask for domain if not provided
        if not self.domain:
            domain = input(colored("Enter domain name for wordlist generation (e.g., example.com): ", "yellow")).strip()
            if domain:
                self.domain = domain
                self.wordlists_dir = f"{domain}-wordlists"
                self.output_dir = f"{domain}-wordlists/generated"
                self.setup_directories()
        
        # Ask for wordlist types to generate
        print(colored("\nSelect wordlist types to generate:", "cyan"))
        print("1. Subdomain wordlist")
        print("2. Directory wordlist") 
        print("3. Global wordlist (combined)")
        print("4. All wordlists (recommended)")
        
        choice = input(colored("Select option (1-4) [default: 4]: ", "yellow")).strip()
        if not choice:
            choice = "4"
        
        # Ask for technology detection
        tech_detect = input(colored("Enable technology detection? (y/n) [default: y]: ", "yellow")).strip().lower()
        if not tech_detect:
            tech_detect = "y"
        
        # Generate wordlists
        self.generate_wordlists(choice, tech_detect == "y")

    def generate_wordlists(self, choice="4", tech_detect=True):
        """Generate wordlists based on selection"""
        self.log("[*] Starting intelligent wordlist generation...", "cyan")
        
        # Step 1: Analyze target domain if provided
        if self.domain:
            self.analyze_domain()
            
            # Step 2: Detect technologies if enabled
            if tech_detect:
                self.detect_technologies()
        
        # Step 3: Download SecLists
        self.download_seclists()
        
        # Step 4: Download from other GitHub repositories
        self.download_github_wordlists()
        
        # Step 5: Generate custom patterns
        self.generate_custom_patterns()
        
        # Step 6: Generate permutations
        if self.domain:
            self.generate_permutations()
        
        # Step 7: Add base subdomain patterns
        self.subdomain_wordlist.update(self.subdomain_patterns)
        
        # Step 8: Clean and deduplicate
        self.clean_and_deduplicate()
        
        # Step 9: Save wordlists based on choice
        if choice in ["1", "4"]:
            subdomain_file = Path(f"{self.output_dir}/subdomain_wordlist.txt")
            subdomain_file.write_text('\n'.join(self.subdomain_wordlist), encoding='utf-8')
            self.log(f"[+] Subdomain wordlist saved: {subdomain_file} ({len(self.subdomain_wordlist)} words)", "green")
        
        if choice in ["2", "4"]:
            directory_file = Path(f"{self.output_dir}/directory_wordlist.txt")
            directory_file.write_text('\n'.join(self.directory_wordlist), encoding='utf-8')
            self.log(f"[+] Directory wordlist saved: {directory_file} ({len(self.directory_wordlist)} words)", "green")
        
        if choice in ["3", "4"]:
            global_file = Path(f"{self.output_dir}/global_wordlist.txt")
            global_file.write_text('\n'.join(self.global_wordlist), encoding='utf-8')
            self.log(f"[+] Global wordlist saved: {global_file} ({len(self.global_wordlist)} words)", "green")
        
        # Step 10: Cleanup
        self.cleanup()
        
        self.log("[+] Intelligent wordlist generation completed!", "green")

def main():
    """Main function for standalone execution."""
    print(colored("🔧 REK Wordlist Generator", "cyan", attrs=["bold"]))
    print(colored("Intelligent wordlist generation for domain reconnaissance", "cyan"))

    parser = argparse.ArgumentParser(description="REK Intelligent Wordlist Generator")
    parser.add_argument("-d", "--domain", help="Target domain to analyze")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode")
    parser.add_argument("--no-tech", action="store_true", help="Skip technology detection")
    parser.add_argument("-t", "--type", choices=["1", "2", "3", "4"], default="4",
                       help="Wordlist type: 1=subdomain, 2=directory, 3=global, 4=all")
    
    args = parser.parse_args()
    
    # Validate domain if provided
    if args.domain:
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', args.domain):
            print(colored("[!] Invalid domain format", "red"))
            sys.exit(1)
    
    # Initialize generator
    generator = REKWordlistGenerator(silent=args.silent, domain=args.domain)
    
    if args.output:
        generator.output_dir = args.output
        generator.setup_directories()
    
    try:
        if args.domain:
            generator.generate_wordlists(args.type, not args.no_tech)
        else:
            generator.run_interactive()
    except KeyboardInterrupt:
        print(colored("\n[!] Generation interrupted by user", "red"))
        generator.cleanup()
    except Exception as e:
        print(colored(f"[!] Error during generation: {e}", "red"))
        generator.cleanup()

if __name__ == "__main__":
    main()
