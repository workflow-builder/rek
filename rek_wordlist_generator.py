
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
        
        # Local wordlists directory
        self.local_wordlists_dir = "wordlists"
        
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
        
        # Local wordlist file mappings
        self.local_wordlist_files = {
            'subdomain': [
                'subdomains-top1million-5000.txt',
                'subdomains-top5000.txt',
                'dns_names.txt'
            ],
            'directory': [
                'raft-medium-directories.txt',
                'common-paths.txt',
                'api-endpoints.txt'
            ]
        }
        
        # Technology-specific patterns for intelligent detection
        self.tech_patterns = {
            'wordpress': {
                'indicators': ['wp-content', 'wp-admin', 'wordpress', 'wp-includes'],
                'paths': ['wp-admin', 'wp-login.php', 'wp-content', 'wp-includes', 'xmlrpc.php', 'wp-config.php', 'wp-load.php']
            },
            'drupal': {
                'indicators': ['drupal', 'sites/default', 'modules'],
                'paths': ['sites/default', 'modules', 'themes', 'core', 'install.php', 'settings.php']
            },
            'php': {
                'indicators': ['.php', 'phpinfo', 'index.php'],
                'paths': ['phpinfo.php', 'admin.php', 'config.php', 'info.php', 'install.php', 'setup.php']
            },
            'apache': {
                'indicators': ['apache', 'httpd'],
                'paths': ['server-status', 'server-info', '.htaccess', 'access_log']
            },
            'nginx': {
                'indicators': ['nginx'],
                'paths': ['nginx_status', 'stub_status', 'error.log']
            },
            'django': {
                'indicators': ['django', 'admin/', 'static/'],
                'paths': ['admin', 'api', 'static', 'media', 'debug', 'urls.py', 'settings.py']
            },
            'laravel': {
                'indicators': ['laravel', 'artisan'],
                'paths': ['.env', 'artisan', 'storage', 'vendor', 'bootstrap', 'routes.php']
            },
            'java': {
                'indicators': ['java', 'jsp', 'servlet'],
                'paths': ['WEB-INF', 'META-INF', 'struts', 'actuator', 'jsp', 'servlet']
            },
            'javascript': {
                'indicators': ['js/', 'javascript', 'node'],
                'paths': ['js', 'scripts', 'assets', 'bundle.js', 'min.js', 'vendor.js']
            },
            'react': {
                'indicators': ['react', 'build/', 'public/'],
                'paths': ['build', 'public', 'static', 'assets', 'manifest.json']
            },
            'angular': {
                'indicators': ['angular', 'ng-'],
                'paths': ['assets', 'app', 'main.js', 'polyfills.js', 'vendor.js']
            },
            'api': {
                'indicators': ['api/', 'rest/', 'graphql'],
                'paths': ['api', 'api/v1', 'api/v2', 'rest', 'graphql', 'swagger', 'docs']
            }
        }
        
        # Common subdomain patterns based on industry standards
        self.intelligent_subdomain_patterns = {
            'infrastructure': ['mail', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'dns', 'mx'],
            'development': ['dev', 'test', 'staging', 'beta', 'alpha', 'demo', 'sandbox'],
            'admin': ['admin', 'cpanel', 'webmail', 'portal', 'dashboard', 'control'],
            'services': ['api', 'cdn', 'cache', 'proxy', 'gateway', 'auth', 'sso'],
            'content': ['blog', 'news', 'forum', 'wiki', 'docs', 'support', 'help'],
            'ecommerce': ['shop', 'store', 'cart', 'checkout', 'payment', 'billing'],
            'security': ['vpn', 'secure', 'ssl', 'firewall', 'monitor'],
            'mobile': ['m', 'mobile', 'app', 'apps'],
            'cloud': ['cloud', 'aws', 'azure', 'gcp', 'k8s', 'docker']
        }
        
        self.setup_directories()

    def setup_directories(self):
        """Create output directories"""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(f"{self.wordlists_dir}/temp").mkdir(parents=True, exist_ok=True)

    def log(self, message, color="white"):
        """Log message if not in silent mode"""
        if not self.silent:
            print(colored(message, color))

    def load_local_wordlists(self, wordlist_type='all'):
        """Load wordlists from local wordlists directory first"""
        self.log(f"[*] Loading local wordlists for {wordlist_type}...", "yellow")
        loaded_count = 0
        
        if wordlist_type in ['subdomain', 'all']:
            for filename in self.local_wordlist_files['subdomain']:
                filepath = Path(self.local_wordlists_dir) / filename
                if filepath.exists():
                    self.log(f"[+] Loading local subdomain wordlist: {filename}", "green")
                    loaded_count += self.process_wordlist_file(filepath, 'subdomain')
                else:
                    self.log(f"[!] Local wordlist not found: {filename}, will download", "yellow")
        
        if wordlist_type in ['directory', 'all']:
            for filename in self.local_wordlist_files['directory']:
                filepath = Path(self.local_wordlists_dir) / filename
                if filepath.exists():
                    self.log(f"[+] Loading local directory wordlist: {filename}", "green")
                    loaded_count += self.process_wordlist_file(filepath, 'directory')
                else:
                    self.log(f"[!] Local wordlist not found: {filename}, will download", "yellow")
        
        self.log(f"[+] Loaded {loaded_count} words from local wordlists", "green")
        return loaded_count

    def analyze_domain_intelligently(self):
        """Intelligent domain analysis to determine what wordlists to generate"""
        if not self.domain:
            return {'type': 'generic', 'technologies': [], 'industry': 'unknown'}
        
        self.log(f"[*] Performing intelligent analysis of domain: {self.domain}", "yellow")
        
        analysis = {
            'type': 'custom',
            'technologies': [],
            'industry': 'unknown',
            'patterns': []
        }
        
        # Extract domain components for intelligent analysis
        domain_parts = self.domain.split('.')
        if len(domain_parts) >= 2:
            base_domain = domain_parts[-2].lower()
            tld = domain_parts[-1].lower()
            
            # Industry detection based on domain name and TLD
            industry_keywords = {
                'tech': ['tech', 'dev', 'code', 'soft', 'app', 'digital', 'cyber', 'cloud'],
                'finance': ['bank', 'finance', 'pay', 'money', 'invest', 'crypto', 'coin'],
                'ecommerce': ['shop', 'store', 'market', 'buy', 'sell', 'cart', 'commerce'],
                'media': ['news', 'media', 'blog', 'press', 'journal', 'tv', 'radio'],
                'education': ['edu', 'school', 'university', 'college', 'learn', 'course'],
                'health': ['health', 'medical', 'doctor', 'clinic', 'hospital', 'care'],
                'government': ['gov', 'government', 'city', 'state', 'federal', 'public']
            }
            
            for industry, keywords in industry_keywords.items():
                if any(keyword in base_domain for keyword in keywords) or tld in ['edu', 'gov']:
                    analysis['industry'] = industry
                    break
            
            # Generate intelligent subdomain patterns based on base domain
            base_variations = self.generate_intelligent_domain_variations(base_domain)
            analysis['patterns'].extend(base_variations)
        
        # Try to detect technologies from the domain
        self.detect_technologies_from_domain(analysis)
        
        return analysis

    def generate_intelligent_domain_variations(self, base_domain):
        """Generate intelligent variations based on the base domain"""
        variations = []
        
        # Add base domain variations
        variations.extend([
            base_domain,
            f"{base_domain}1", f"{base_domain}2", f"{base_domain}01", f"{base_domain}02",
            f"old-{base_domain}", f"new-{base_domain}", f"test-{base_domain}",
            f"dev-{base_domain}", f"staging-{base_domain}", f"prod-{base_domain}",
            f"{base_domain}-old", f"{base_domain}-new", f"{base_domain}-test",
            f"{base_domain}-dev", f"{base_domain}-staging", f"{base_domain}-prod",
            f"{base_domain}_old", f"{base_domain}_new", f"{base_domain}_test"
        ])
        
        # Add contextual variations based on common patterns
        for category, patterns in self.intelligent_subdomain_patterns.items():
            for pattern in patterns[:3]:  # Limit to top 3 per category
                variations.extend([
                    f"{pattern}-{base_domain}",
                    f"{pattern}{base_domain}",
                    f"{base_domain}-{pattern}",
                    f"{base_domain}{pattern}"
                ])
        
        return variations

    def detect_technologies_from_domain(self, analysis):
        """Detect technologies by analyzing the domain and making intelligent requests"""
        if not self.domain:
            return
        
        self.log(f"[*] Detecting technologies for {self.domain}...", "yellow")
        
        try:
            # Try multiple protocols and common paths
            test_urls = [
                f"https://{self.domain}",
                f"http://{self.domain}",
                f"https://www.{self.domain}",
                f"http://www.{self.domain}"
            ]
            
            for url in test_urls:
                try:
                    response = self.session.get(url, timeout=10, verify=False)
                    if response.status_code == 200:
                        self.analyze_response_for_technology(response, analysis)
                        break
                except:
                    continue
        except Exception as e:
            self.log(f"[!] Error detecting technologies: {e}", "red")

    def analyze_response_for_technology(self, response, analysis):
        """Analyze HTTP response to detect technologies"""
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # Check headers for technology indicators
        server = headers.get('server', '')
        powered_by = headers.get('x-powered-by', '')
        
        for tech_name, tech_info in self.tech_patterns.items():
            # Check content for technology indicators
            if any(indicator in content for indicator in tech_info['indicators']):
                analysis['technologies'].append(tech_name)
                self.directory_wordlist.update(tech_info['paths'])
                self.log(f"[+] Detected {tech_name} - added {len(tech_info['paths'])} specific paths", "green")
            
            # Check headers
            if any(indicator in server or indicator in powered_by for indicator in tech_info['indicators']):
                if tech_name not in analysis['technologies']:
                    analysis['technologies'].append(tech_name)
                    self.directory_wordlist.update(tech_info['paths'])

    def download_missing_wordlists(self):
        """Download only missing wordlists that aren't available locally"""
        self.log("[*] Checking for missing wordlists to download...", "yellow")
        
        missing_files = []
        
        # Check subdomain wordlists
        for filename in self.local_wordlist_files['subdomain']:
            filepath = Path(self.local_wordlists_dir) / filename
            if not filepath.exists():
                missing_files.append(('subdomain', filename))
        
        # Check directory wordlists
        for filename in self.local_wordlist_files['directory']:
            filepath = Path(self.local_wordlists_dir) / filename
            if not filepath.exists():
                missing_files.append(('directory', filename))
        
        if not missing_files:
            self.log("[+] All required wordlists are available locally", "green")
            return
        
        self.log(f"[*] Downloading {len(missing_files)} missing wordlists...", "yellow")
        
        # Download missing files
        download_urls = {
            'subdomains-top1million-5000.txt': 'Discovery/DNS/subdomains-top1million-5000.txt',
            'dns_names.txt': 'Discovery/DNS/dns_names.txt',
            'raft-medium-directories.txt': 'Discovery/Web-Content/raft-medium-directories.txt'
        }
        
        for wordlist_type, filename in missing_files:
            if filename in download_urls:
                try:
                    url = f"{self.seclists_base_url}/{download_urls[filename]}"
                    response = self.session.get(url, timeout=30)
                    if response.status_code == 200:
                        local_path = Path(self.local_wordlists_dir) / filename
                        local_path.parent.mkdir(exist_ok=True)
                        local_path.write_text(response.text, encoding='utf-8')
                        self.log(f"[+] Downloaded {filename}", "green")
                        self.process_wordlist_file(local_path, wordlist_type)
                    else:
                        self.log(f"[!] Failed to download {filename}: HTTP {response.status_code}", "red")
                except Exception as e:
                    self.log(f"[!] Error downloading {filename}: {e}", "red")

    def process_wordlist_file(self, file_path, wordlist_type):
        """Process a wordlist file and add to appropriate set"""
        try:
            count = 0
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
                        count += 1
            
            return count
        except Exception as e:
            self.log(f"[!] Error processing {file_path}: {e}", "red")
            return 0

    def generate_domain_specific_patterns(self, analysis):
        """Generate domain-specific patterns based on intelligent analysis"""
        self.log("[*] Generating domain-specific patterns...", "yellow")
        
        # Add patterns based on analysis
        if analysis['patterns']:
            self.subdomain_wordlist.update(analysis['patterns'])
        
        # Add industry-specific patterns
        industry = analysis.get('industry', 'unknown')
        if industry != 'unknown' and industry in self.intelligent_subdomain_patterns:
            # Add relevant subdomain patterns for the detected industry
            relevant_categories = []
            if industry == 'tech':
                relevant_categories = ['development', 'services', 'api']
            elif industry == 'ecommerce':
                relevant_categories = ['ecommerce', 'services', 'content']
            elif industry == 'finance':
                relevant_categories = ['security', 'services', 'admin']
            elif industry == 'education':
                relevant_categories = ['content', 'admin', 'services']
            
            for category in relevant_categories:
                if category in self.intelligent_subdomain_patterns:
                    self.subdomain_wordlist.update(self.intelligent_subdomain_patterns[category])

    def generate_intelligent_permutations(self, analysis):
        """Generate intelligent permutations based on domain analysis"""
        if not self.domain:
            return
        
        self.log("[*] Generating intelligent permutations...", "yellow")
        
        domain_parts = self.domain.split('.')
        if len(domain_parts) >= 2:
            base_name = domain_parts[-2]
            
            # Generate smarter permutations based on industry and technologies
            industry = analysis.get('industry', 'unknown')
            technologies = analysis.get('technologies', [])
            
            # Industry-specific prefixes and suffixes
            industry_affixes = {
                'tech': {'prefixes': ['dev', 'api', 'test', 'staging'], 'suffixes': ['api', 'dev', 'test']},
                'ecommerce': {'prefixes': ['shop', 'store', 'cart'], 'suffixes': ['shop', 'store', 'pay']},
                'finance': {'prefixes': ['secure', 'pay', 'bank'], 'suffixes': ['secure', 'pay', 'wallet']},
                'education': {'prefixes': ['learn', 'course', 'student'], 'suffixes': ['edu', 'learn', 'portal']}
            }
            
            # Use industry-specific affixes if available
            if industry in industry_affixes:
                prefixes = industry_affixes[industry]['prefixes']
                suffixes = industry_affixes[industry]['suffixes']
            else:
                # Generic but intelligent prefixes/suffixes
                prefixes = ['dev', 'test', 'staging', 'api', 'admin']
                suffixes = ['dev', 'test', 'api', 'admin', 'portal']
            
            # Generate permutations
            permutations = []
            
            # Technology-specific permutations
            for tech in technologies:
                permutations.extend([
                    f"{tech}-{base_name}",
                    f"{base_name}-{tech}",
                    f"{tech}{base_name}",
                    f"{base_name}{tech}"
                ])
            
            # Industry and number-based permutations
            for i in range(1, 10):
                permutations.extend([f"{base_name}{i}", f"{base_name}0{i}"])
            
            for prefix in prefixes[:5]:  # Limit to top 5
                permutations.extend([f"{prefix}-{base_name}", f"{prefix}{base_name}"])
            
            for suffix in suffixes[:5]:  # Limit to top 5
                permutations.extend([f"{base_name}-{suffix}", f"{base_name}{suffix}"])
            
            # Add permutations to wordlists
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

    def save_wordlists(self, choice="4"):
        """Save generated wordlists to files"""
        self.log("[*] Saving intelligent wordlists...", "yellow")
        
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

    def cleanup(self):
        """Clean up temporary files"""
        temp_dir = Path(f"{self.wordlists_dir}/temp")
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

    def run_interactive(self):
        """Run interactive wordlist generator"""
        if not self.silent:
            print(colored("\n🔧 REK Intelligent Wordlist Generator", "cyan", attrs=["bold"]))
            print(colored("AI-powered wordlist generation for domain reconnaissance", "cyan"))
        
        # Ask for domain if not provided
        if not self.domain:
            domain = input(colored("Enter domain name for intelligent wordlist generation (e.g., example.com): ", "yellow")).strip()
            if domain:
                self.domain = domain
                self.wordlists_dir = f"{domain}-wordlists"
                self.output_dir = f"{domain}-wordlists/generated"
                self.setup_directories()
        
        # Ask for wordlist types to generate
        print(colored("\nSelect wordlist types to generate:", "cyan"))
        print("1. Subdomain wordlist (intelligent)")
        print("2. Directory wordlist (technology-aware)") 
        print("3. Global wordlist (combined)")
        print("4. All wordlists (recommended)")
        
        choice = input(colored("Select option (1-4) [default: 4]: ", "yellow")).strip()
        if not choice:
            choice = "4"
        
        # Generate wordlists intelligently
        self.generate_intelligent_wordlists(choice)

    def generate_intelligent_wordlists(self, choice="4"):
        """Generate intelligent wordlists based on domain analysis"""
        self.log("[*] Starting intelligent wordlist generation...", "cyan")
        
        # Step 1: Perform intelligent domain analysis
        analysis = self.analyze_domain_intelligently()
        self.log(f"[+] Domain analysis: Industry={analysis['industry']}, Technologies={analysis['technologies']}", "green")
        
        # Step 2: Load local wordlists first (prioritize local resources)
        local_count = self.load_local_wordlists()
        
        # Step 3: Download only missing wordlists
        self.download_missing_wordlists()
        
        # Step 4: Generate domain-specific patterns based on analysis
        self.generate_domain_specific_patterns(analysis)
        
        # Step 5: Generate intelligent permutations
        if self.domain:
            self.generate_intelligent_permutations(analysis)
        
        # Step 6: Add base patterns from intelligent subdomain patterns
        for category_patterns in self.intelligent_subdomain_patterns.values():
            self.subdomain_wordlist.update(category_patterns[:5])  # Top 5 from each category
        
        # Step 7: Clean and deduplicate
        self.clean_and_deduplicate()
        
        # Step 8: Save wordlists based on choice
        self.save_wordlists(choice)
        
        # Step 9: Cleanup
        self.cleanup()
        
        self.log("[+] Intelligent wordlist generation completed!", "green")
        if self.domain:
            self.log(f"[+] Generated domain-specific wordlists for {self.domain}", "green")
            self.log(f"[+] Technologies detected: {analysis['technologies']}", "green")
            self.log(f"[+] Industry classification: {analysis['industry']}", "green")

def main():
    """Main function for standalone execution."""
    print(colored("🔧 REK Intelligent Wordlist Generator", "cyan", attrs=["bold"]))
    print(colored("AI-powered wordlist generation for domain reconnaissance", "cyan"))

    parser = argparse.ArgumentParser(description="REK Intelligent Wordlist Generator")
    parser.add_argument("-d", "--domain", help="Target domain to analyze")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode")
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
            generator.generate_intelligent_wordlists(args.type)
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
