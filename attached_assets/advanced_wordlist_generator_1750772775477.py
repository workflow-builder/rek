#!/usr/bin/env python3
"""
Advanced Wordlist Generator
Generates comprehensive wordlists from multiple sources including SecLists, GitHub repos, and domain analysis
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

class AdvancedWordlistGenerator:
    def __init__(self, target_domain=None, output_dir="wordlists", threads=10):
        self.target_domain = target_domain
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        
        # Initialize wordlist containers
        self.global_wordlist = set()
        self.subdomain_wordlist = set()
        self.directory_wordlist = set()
        
        # GitHub repositories for wordlists
        self.github_repos = [
            "danielmiessler/SecLists",
            "assetnote/commonspeak2-wordlists",
            "fuzzdb-project/fuzzdb",
            "Bo0oM/fuzz.txt",
            "six2dez/OneListForAll",
            "maurosoria/dirsearch",
            "OJ/gobuster",
            "ffuf/ffuf"
        ]
        
        # Common subdomain patterns
        self.subdomain_patterns = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "www1", "beta", "webserver",
            "staging", "api", "cdn", "shop", "store", "portal", "demo", "secure"
        ]
        
        # Technology-specific patterns
        self.tech_patterns = {
            'php': ['admin.php', 'config.php', 'index.php', 'login.php', 'upload.php'],
            'asp': ['admin.asp', 'default.asp', 'index.asp', 'login.asp'],
            'jsp': ['admin.jsp', 'index.jsp', 'login.jsp', 'test.jsp'],
            'python': ['admin.py', 'app.py', 'main.py', 'manage.py'],
            'nodejs': ['app.js', 'index.js', 'server.js', 'main.js']
        }
        
        self.setup_directories()

    def setup_directories(self):
        """Create output directories"""
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "temp").mkdir(exist_ok=True)

    def analyze_domain(self):
        """Analyze target domain to generate custom wordlist"""
        if not self.target_domain:
            return
            
        print(f"[*] Analyzing domain: {self.target_domain}")
        
        # Extract domain components
        domain_parts = self.target_domain.split('.')
        
        # Add domain name variations
        if len(domain_parts) >= 2:
            base_domain = domain_parts[-2]  # e.g., 'example' from 'example.com'
            
            # Generate variations
            variations = [
                base_domain,
                base_domain + "1",
                base_domain + "2",
                base_domain + "_old",
                base_domain + "_new",
                base_domain + "_test",
                base_domain + "_dev",
                base_domain + "_staging",
                "old_" + base_domain,
                "new_" + base_domain,
                "test_" + base_domain,
                "dev_" + base_domain
            ]
            
            self.subdomain_wordlist.update(variations)
            self.directory_wordlist.update([v + "/" for v in variations])
        
        # Try to fetch robots.txt and sitemap
        self.analyze_robots_txt()
        self.analyze_sitemap()
        
    def analyze_robots_txt(self):
        """Extract paths from robots.txt"""
        try:
            robots_url = f"http://{self.target_domain}/robots.txt"
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            self.directory_wordlist.add(path.lstrip('/'))
        except:
            pass

    def analyze_sitemap(self):
        """Extract paths from sitemap.xml"""
        try:
            sitemap_urls = [
                f"http://{self.target_domain}/sitemap.xml",
                f"http://{self.target_domain}/sitemap_index.xml"
            ]
            
            for sitemap_url in sitemap_urls:
                response = self.session.get(sitemap_url, timeout=10)
                if response.status_code == 200:
                    # Simple regex to extract URLs
                    urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                    for url in urls:
                        parsed = urlparse(url)
                        path = parsed.path.strip('/')
                        if path:
                            self.directory_wordlist.add(path)
        except:
            pass

    def download_seclists(self):
        """Download and process SecLists repository"""
        print("[*] Downloading SecLists...")
        
        temp_dir = self.output_dir / "temp" / "seclists"
        
        try:
            # Clone SecLists repository
            if not temp_dir.exists():
                subprocess.run([
                    "git", "clone", "--depth", "1",
                    "https://github.com/danielmiessler/SecLists.git",
                    str(temp_dir)
                ], check=True, capture_output=True)
            
            # Process different categories
            self.process_seclists_directory(temp_dir)
            
        except subprocess.CalledProcessError:
            print("[!] Failed to clone SecLists. Trying direct download...")
            self.download_seclists_direct()

    def process_seclists_directory(self, seclists_path):
        """Process SecLists directory structure"""
        
        # Discovery/DNS subdomain lists
        subdomain_paths = [
            "Discovery/DNS/subdomains-top1million-5000.txt",
            "Discovery/DNS/subdomains-top1million-20000.txt",
            "Discovery/DNS/fierce-hostlist.txt",
            "Discovery/DNS/namelist.txt"
        ]
        
        # Discovery/Web-Content directory lists
        directory_paths = [
            "Discovery/Web-Content/common.txt",
            "Discovery/Web-Content/big.txt",
            "Discovery/Web-Content/directory-list-2.3-medium.txt",
            "Discovery/Web-Content/raft-medium-directories.txt",
            "Discovery/Web-Content/raft-large-directories.txt"
        ]
        
        # Process subdomain wordlists
        for path in subdomain_paths:
            full_path = seclists_path / path
            if full_path.exists():
                self.process_wordlist_file(full_path, "subdomain")
        
        # Process directory wordlists
        for path in directory_paths:
            full_path = seclists_path / path
            if full_path.exists():
                self.process_wordlist_file(full_path, "directory")

    def download_seclists_direct(self):
        """Download specific SecLists files directly"""
        base_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        
        files_to_download = [
            ("Discovery/DNS/subdomains-top1million-5000.txt", "subdomain"),
            ("Discovery/Web-Content/common.txt", "directory"),
            ("Discovery/Web-Content/big.txt", "directory"),
            ("Discovery/Web-Content/raft-medium-directories.txt", "directory")
        ]
        
        for file_path, wordlist_type in files_to_download:
            try:
                url = base_url + file_path
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    temp_file = self.output_dir / "temp" / f"temp_{wordlist_type}.txt"
                    temp_file.write_text(response.text)
                    self.process_wordlist_file(temp_file, wordlist_type)
                    temp_file.unlink()
            except Exception as e:
                print(f"[!] Failed to download {file_path}: {e}")

    def download_github_wordlists(self):
        """Download wordlists from various GitHub repositories"""
        print("[*] Downloading wordlists from GitHub repositories...")
        
        # Known good wordlist files from repositories
        repo_files = {
            "assetnote/commonspeak2-wordlists": [
                "subdomains/subdomains.txt",
                "wordlists/paramnames.txt"
            ],
            "six2dez/OneListForAll": [
                "onelistforallmicro.txt",
                "onelistforallshort.txt"
            ],
            "Bo0oM/fuzz.txt": [
                "fuzz.txt"
            ]
        }
        
        for repo, files in repo_files.items():
            for file_path in files:
                try:
                    url = f"https://raw.githubusercontent.com/{repo}/master/{file_path}"
                    response = self.session.get(url, timeout=30)
                    if response.status_code == 200:
                        if "subdomain" in file_path or "subdomain" in repo:
                            wordlist_type = "subdomain"
                        else:
                            wordlist_type = "directory"
                        
                        temp_file = self.output_dir / "temp" / f"github_{repo.replace('/', '_')}_{file_path.replace('/', '_')}"
                        temp_file.write_text(response.text)
                        self.process_wordlist_file(temp_file, wordlist_type)
                        temp_file.unlink()
                        
                except Exception as e:
                    print(f"[!] Failed to download {repo}/{file_path}: {e}")

    def process_wordlist_file(self, file_path, wordlist_type):
        """Process a wordlist file and add to appropriate set"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        if wordlist_type == "subdomain":
                            self.subdomain_wordlist.add(word)
                        elif wordlist_type == "directory":
                            self.directory_wordlist.add(word)
                        
                        # Add to global wordlist
                        self.global_wordlist.add(word)
                        
        except Exception as e:
            print(f"[!] Error processing {file_path}: {e}")

    def generate_custom_patterns(self):
        """Generate custom patterns based on domain and common patterns"""
        print("[*] Generating custom patterns...")
        
        # Common directory patterns
        common_dirs = [
            "admin", "administrator", "login", "panel", "dashboard", "control",
            "wp-admin", "wp-content", "wp-includes", "backup", "backups",
            "config", "configuration", "settings", "api", "v1", "v2",
            "test", "testing", "dev", "development", "staging", "prod",
            "uploads", "files", "images", "img", "css", "js", "assets",
            "include", "includes", "lib", "library", "vendor", "node_modules"
        ]
        
        # Add to directory wordlist
        self.directory_wordlist.update(common_dirs)
        
        # Generate year-based patterns
        current_year = 2024
        for year in range(current_year - 5, current_year + 2):
            self.directory_wordlist.add(str(year))
            self.subdomain_wordlist.add(str(year))
        
        # Add technology-specific patterns
        for tech, patterns in self.tech_patterns.items():
            self.directory_wordlist.update(patterns)

    def generate_permutations(self):
        """Generate permutations and mutations of existing words"""
        if not self.target_domain:
            return
            
        print("[*] Generating permutations...")
        
        domain_parts = self.target_domain.split('.')
        if len(domain_parts) >= 2:
            base_name = domain_parts[-2]
            
            # Generate permutations
            permutations = []
            
            # Number suffixes
            for i in range(1, 10):
                permutations.append(f"{base_name}{i}")
                permutations.append(f"{base_name}0{i}")
            
            # Common prefixes/suffixes
            prefixes = ["dev", "test", "staging", "beta", "alpha", "pre", "old", "new"]
            suffixes = ["dev", "test", "staging", "beta", "prod", "old", "new", "bak"]
            
            for prefix in prefixes:
                permutations.append(f"{prefix}-{base_name}")
                permutations.append(f"{prefix}{base_name}")
            
            for suffix in suffixes:
                permutations.append(f"{base_name}-{suffix}")
                permutations.append(f"{base_name}{suffix}")
            
            # Add permutations to both subdomain and directory lists
            self.subdomain_wordlist.update(permutations)
            self.directory_wordlist.update([p + "/" for p in permutations])

    def clean_and_deduplicate(self):
        """Clean and deduplicate wordlists"""
        print("[*] Cleaning and deduplicating wordlists...")
        
        # Remove empty strings and clean
        self.global_wordlist = {w.strip() for w in self.global_wordlist if w.strip()}
        self.subdomain_wordlist = {w.strip() for w in self.subdomain_wordlist if w.strip()}
        self.directory_wordlist = {w.strip() for w in self.directory_wordlist if w.strip()}
        
        # Remove duplicates and sort
        self.global_wordlist = sorted(list(self.global_wordlist))
        self.subdomain_wordlist = sorted(list(self.subdomain_wordlist))
        self.directory_wordlist = sorted(list(self.directory_wordlist))

    def save_wordlists(self):
        """Save generated wordlists to files"""
        print("[*] Saving wordlists...")
        
        # Save global wordlist
        global_file = self.output_dir / "global_wordlist.txt"
        with open(global_file, 'w') as f:
            f.write('\n'.join(self.global_wordlist))
        
        # Save subdomain wordlist
        subdomain_file = self.output_dir / "subdomain_wordlist.txt"
        with open(subdomain_file, 'w') as f:
            f.write('\n'.join(self.subdomain_wordlist))
        
        # Save directory wordlist
        directory_file = self.output_dir / "directory_wordlist.txt"
        with open(directory_file, 'w') as f:
            f.write('\n'.join(self.directory_wordlist))
        
        print(f"[+] Global wordlist saved: {global_file} ({len(self.global_wordlist)} words)")
        print(f"[+] Subdomain wordlist saved: {subdomain_file} ({len(self.subdomain_wordlist)} words)")
        print(f"[+] Directory wordlist saved: {directory_file} ({len(self.directory_wordlist)} words)")

    def cleanup(self):
        """Clean up temporary files"""
        temp_dir = self.output_dir / "temp"
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

    def generate(self):
        """Main generation process"""
        print(f"[*] Starting wordlist generation for domain: {self.target_domain or 'generic'}")
        
        # Step 1: Analyze target domain if provided
        if self.target_domain:
            self.analyze_domain()
        
        # Step 2: Download SecLists
        self.download_seclists()
        
        # Step 3: Download from other GitHub repositories
        self.download_github_wordlists()
        
        # Step 4: Generate custom patterns
        self.generate_custom_patterns()
        
        # Step 5: Generate permutations
        if self.target_domain:
            self.generate_permutations()
        
        # Step 6: Add base subdomain patterns
        self.subdomain_wordlist.update(self.subdomain_patterns)
        
        # Step 7: Clean and deduplicate
        self.clean_and_deduplicate()
        
        # Step 8: Save wordlists
        self.save_wordlists()
        
        # Step 9: Cleanup
        self.cleanup()
        
        print("[+] Wordlist generation completed!")

def main():
    parser = argparse.ArgumentParser(description="Advanced Wordlist Generator")
    parser.add_argument("-d", "--domain", help="Target domain to analyze")
    parser.add_argument("-o", "--output", default="wordlists", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--no-github", action="store_true", help="Skip GitHub repositories")
    parser.add_argument("--no-seclists", action="store_true", help="Skip SecLists download")
    
    args = parser.parse_args()
    
    # Validate domain if provided
    if args.domain:
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', args.domain):
            print("[!] Invalid domain format")
            sys.exit(1)
    
    # Initialize generator
    generator = AdvancedWordlistGenerator(
        target_domain=args.domain,
        output_dir=args.output,
        threads=args.threads
    )
    
    try:
        generator.generate()
    except KeyboardInterrupt:
        print("\n[!] Generation interrupted by user")
        generator.cleanup()
    except Exception as e:
        print(f"[!] Error during generation: {e}")
        generator.cleanup()

if __name__ == "__main__":
    main()
