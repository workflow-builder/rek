import warnings
from urllib3.exceptions import NotOpenSSLWarning
warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
import dns.resolver
import httpx
import asyncio
import argparse
import logging
import pandas as pd
import os
from typing import List, Set, Dict
from urllib.parse import urlparse
from Wappalyzer import Wappalyzer, WebPage
import sys
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import re
from termcolor import colored
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import shlex
import csv
import threading
from rek_email_search import EmailSearcher
import subprocess
import glob
from tldextract import extract

# Configure logging
logger = logging.getLogger(__name__)

class SubdomainScanner:
    def __init__(self, timeout: int = 30, wordlist_path: str = None, concurrency: int = 50, retries: int = 3, silent: bool = False):
        self.timeout = timeout
        self.wordlist_path = wordlist_path
        self.concurrency = concurrency
        self.retries = retries
        self.silent = silent
        self.subdomains: Set[str] = set()
        self.validated_subdomains: Set[str] = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.default_wordlist = [
            'www', 'api', 'app', 'blog', 'dev', 'staging', 'test', 'mail', 'admin', 'login', 'dashboard', 'secure',
            'portal', 'vpn', 'ftp', 'support', 'shop', 'store', 'news', 'events', 'forum', 'community', 'docs', 'help',
            'status', 'beta', 'demo', 'internal', 'old', 'new', 'web', 'mobile', 'cloud', 'data', 'auth', 'oauth', 'sso',
            'my', 'user', 'account', 'profile', 'settings', 'signup', 'login', 'gateway', 'proxy', 'cdn', 'cache', 'backup',
            'devops', 'ci', 'cd', 'monitoring', 'analytics', 'payments', 'billing', 'support', 'chat', 'ws', 'wss'
        ]
        self.email_searcher = EmailSearcher(timeout=timeout, silent=silent)

    def load_wordlist(self) -> List[str]:
        """Load wordlist from file or use enhanced default."""
        if self.wordlist_path:
            try:
                with open(self.wordlist_path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                if not self.silent:
                    logger.error(colored(f"Error loading wordlist {self.wordlist_path}: {e}", "red"))
        return self.default_wordlist

    def dns_dumpster(self, domain: str, max_retries: int = 3) -> None:
        """Enumerate subdomains using DNS Dumpster with retry logic."""
        try:
            if not self.silent:
                logger.info(colored("Querying DNS Dumpster...", "green"))
            url = 'https://dnsdumpster.com/'
            for attempt in range(max_retries):
                try:
                    res = self.session.get(url, headers=self.headers, timeout=self.timeout)
                    res.raise_for_status()
                    soup = BeautifulSoup(res.text, 'html.parser')
                    csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'}) or soup.find('input', {'name': '__csrf_token'})
                    if not csrf_input:
                        if not self.silent and attempt == max_retries - 1:
                            logger.warning(colored("CSRF token not found on DNS Dumpster after retries", "yellow"))
                        continue

                    csrf_token = csrf_input.get('value')
                    if not csrf_token:
                        if not self.silent and attempt == max_retries - 1:
                            logger.warning(colored("Empty CSRF token received after retries", "yellow"))
                        continue

                    data = {
                        'csrfmiddlewaretoken': csrf_token,
                        'targetip': domain,
                        'user': 'free'
                    }
                    cookies = {'csrftoken': self.session.cookies.get('csrftoken', '')}
                    res = self.session.post(url, data=data, headers=self.headers, cookies=cookies, timeout=self.timeout)
                    res.raise_for_status()
                    soup = BeautifulSoup(res.text, 'html.parser')

                    for td in soup.find_all('td', class_='col-md-4') or soup.find_all('td', {'data-label': 'Domain'}):
                        subdomain = td.text.strip().split('\n')[0]
                        if subdomain.endswith(domain):
                            self.subdomains.add(subdomain)
                    if not self.silent:
                        logger.info(colored(f"Found {len(self.subdomains)} subdomains via DNS Dumpster", "green"))
                    break
                except requests.exceptions.RequestException as e:
                    if not self.silent and attempt == max_retries - 1:
                        logger.error(colored(f"DNS Dumpster request failed after {max_retries} attempts: {e}", "red"))
                    time.sleep(2 ** attempt)
                except Exception as e:
                    if not self.silent and attempt == max_retries - 1:
                        logger.error(colored(f"DNS Dumpster parsing error after {max_retries} attempts: {e}", "red"))
                    time.sleep(2 ** attempt)
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Unexpected DNS Dumpster error: {e}", "red"))

    def fetch_cert_transparency(self, domain: str) -> None:
        """Fetch subdomains from certificate transparency logs (e.g., crt.sh) with retry."""
        try:
            if not self.silent:
                logger.info(colored("Querying crt.sh...", "green"))
            url = f"https://crt.sh/?q={domain}&output=json"
            for attempt in range(3):
                try:
                    res = self.session.get(url, headers=self.headers, timeout=self.timeout)
                    res.raise_for_status()
                    data = res.json()
                    for entry in data:
                        name = entry.get('name_value', '').strip()
                        for line in name.split('\n'):
                            if line.endswith(domain) and not line.startswith('*'):
                                self.subdomains.add(line)
                    if not self.silent:
                        logger.info(colored(f"Fetched {len(self.subdomains)} subdomains from certificate transparency", "green"))
                    time.sleep(1)
                    break
                except requests.exceptions.Timeout:
                    if not self.silent and attempt == 2:
                        logger.error(colored(f"crt.sh timed out after {self.timeout} seconds after 3 attempts", "red"))
                    time.sleep(2 ** attempt)
                except requests.exceptions.RequestException as e:
                    if not self.silent and attempt == 2:
                        logger.error(colored(f"crt.sh request failed after 3 attempts: {e}", "red"))
                    time.sleep(2 ** attempt)
                except ValueError as e:
                    if not self.silent and attempt == 2:
                        logger.error(colored(f"crt.sh JSON parsing error after 3 attempts: {e}", "red"))
                    time.sleep(2 ** attempt)
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Unexpected crt.sh error: {e}", "red"))

    async def dns_brute_force(self, domain: str, wordlist: List[str], semaphore: asyncio.Semaphore):
        """Perform DNS brute-forcing with a wordlist asynchronously."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        async def check_subdomain(subdomain: str):
            async with semaphore:
                target = f"{subdomain}.{domain}"
                try:
                    answers = resolver.resolve(target, 'A')
                    for rdata in answers:
                        self.validated_subdomains.add(target)
                        if not self.silent:
                            logger.info(colored(f"Validated subdomain: {target} ({rdata})", "green"))
                    await asyncio.sleep(0.1)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    pass
                except Exception as e:
                    if not self.silent:
                        logger.error(colored(f"DNS query error for {target}: {e}", "red"))

        tasks = [check_subdomain(subdomain) for subdomain in wordlist]
        await asyncio.gather(*tasks)

    async def enumerate_subdomains(self, domain: str, output_file: str, github_token: str = None, max_commits: int = 50, skip_forks: bool = True):
        """Enumerate subdomains and run email search in parallel."""
        if not self.silent:
            logger.info(colored(f"Starting subdomain enumeration for {domain}", "green"))

        # Start email search in a separate thread
        email_output = f"{os.path.splitext(output_file)[0]}_emails.csv" if output_file else "email_results.csv"
        email_thread = threading.Thread(
            target=self.email_searcher.run,
            args=(domain, None, github_token, email_output, max_commits, skip_forks)
        )
        email_thread.start()

        # Step 1: DNS Dumpster
        self.dns_dumpster(domain)

        # Step 2: Certificate Transparency
        self.fetch_cert_transparency(domain)

        # Step 3: Combine with default wordlist and save all subdomains to results.txt
        wordlist = self.load_wordlist()
        combined_subdomains = set(self.subdomains)
        for sub in wordlist:
            combined_subdomains.add(f"{sub}.{domain}")

        unvalidated_output = output_file or "results.txt"
        if not unvalidated_output or not unvalidated_output.strip():
            unvalidated_output = "results.txt"
            if not self.silent:
                logger.info(colored(f"No output file specified. Using default: {unvalidated_output}", "yellow"))

        try:
            output_dir = os.path.dirname(unvalidated_output)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            else:
                unvalidated_output = os.path.join(os.getcwd(), unvalidated_output)

            with open(unvalidated_output, 'w') as f:
                for subdomain in sorted(combined_subdomains):
                    f.write(f"{subdomain}\n")
            if not self.silent:
                logger.info(colored(f"Saved {len(combined_subdomains)} unvalidated subdomains to {unvalidated_output}", "green"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error saving unvalidated subdomains to {unvalidated_output}: {e}", "red"))
            raise

        # Step 4: DNS Brute-Forcing on combined wordlist
        combined_wordlist = list(combined_subdomains)
        if not self.silent:
            logger.info(colored(f"Using {len(combined_wordlist)} unique subdomains for DNS validation", "green"))
        semaphore = asyncio.Semaphore(self.concurrency)
        await self.dns_brute_force(domain, wordlist, semaphore)

        # Step 5: Save validated subdomains
        validated_output = "results_dns_validated.txt" if not output_file else f"{os.path.splitext(output_file)[0]}_dns_validated.txt"
        try:
            output_dir = os.path.dirname(validated_output)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            else:
                validated_output = os.path.join(os.getcwd(), validated_output)

            with open(validated_output, 'w') as f:
                for subdomain in sorted(self.validated_subdomains):
                    f.write(f"{subdomain}\n")
            if not self.silent:
                logger.info(colored(f"Saved {len(self.validated_subdomains)} validated subdomains to {validated_output}", "green"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error saving validated subdomains to {validated_output}: {e}", "red"))
            raise

        # Wait for email search to complete
        email_thread.join()
        if not self.silent:
            logger.info(colored("Completed email search in parallel", "green"))

class WordlistGenerator:
    def __init__(self, silent: bool = False):
        self.silent = silent
        self.seclists_base_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
        self.wordlists_dir = "wordlists"
        self.common_wordlists = {
            "subdomains": [
                "Discovery/DNS/subdomains-top1million-5000.txt",
                "Discovery/DNS/dns-Jhaddix.txt",
                "Discovery/DNS/fierce-hostlist.txt"
            ],
            "directories": [
                "Discovery/Web-Content/directory-list-2.3-medium.txt",
                "Discovery/Web-Content/raft-medium-directories.txt",
                "Discovery/Web-Content/common.txt"
            ],
            "files": [
                "Discovery/Web-Content/raft-medium-files.txt",
                "Discovery/Web-Content/common-extensions.txt",
                "Discovery/Web-Content/web-extensions.txt"
            ],
            "parameters": [
                "Discovery/Web-Content/burp-parameter-names.txt",
                "Discovery/Web-Content/raft-medium-words.txt"
            ],
            "vulnerabilities": [
                "Fuzzing/XSS/XSS-BruteLogic.txt",
                "Fuzzing/SQLi/Generic-SQLi.txt",
                "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
            ]
        }

    def create_wordlists_directory(self):
        """Create wordlists directory if it doesn't exist."""
        try:
            os.makedirs(self.wordlists_dir, exist_ok=True)
            if not self.silent:
                logger.info(colored(f"Created/verified wordlists directory: {self.wordlists_dir}", "green"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error creating wordlists directory: {e}", "red"))

    def download_wordlist(self, url: str, filename: str) -> bool:
        """Download a wordlist from URL."""
        try:
            if not self.silent:
                logger.info(colored(f"Downloading {filename}...", "yellow"))

            response = requests.get(url, timeout=30)
            response.raise_for_status()

            filepath = os.path.join(self.wordlists_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(response.text)

            if not self.silent:
                logger.info(colored(f"Successfully downloaded {filename}", "green"))
            return True
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Failed to download {filename}: {e}", "red"))
            return False

    def generate_custom_wordlist(self, domain: str, wordlist_type: str) -> str:
        """Generate custom wordlist based on domain and type."""
        custom_filename = f"custom-{wordlist_type}-{domain}.txt"
        custom_filepath = os.path.join(self.wordlists_dir, custom_filename)

        try:
            base_words = []
            domain_parts = domain.replace('.', '-').split('-')

            if wordlist_type == "subdomains":
                base_words = [
                    'www', 'api', 'app', 'blog', 'dev', 'staging', 'test', 'mail', 'admin', 'login',
                    'dashboard', 'secure', 'portal', 'vpn', 'ftp', 'support', 'shop', 'store', 'news',
                    'events', 'forum', 'community', 'docs', 'help', 'status', 'beta', 'demo', 'internal',
                    'old', 'new', 'web', 'mobile', 'cloud', 'data', 'auth', 'oauth', 'sso', 'my', 'user',
                    'account', 'profile', 'settings', 'signup', 'gateway', 'proxy', 'cdn', 'cache', 'backup'
                ]
            elif wordlist_type == "directories":
                base_words = [
                    'admin', 'login', 'dashboard', 'api', 'config', 'backup', 'test', 'dev', 'staging',
                    '.env', 'config.php', 'wp-admin', 'wp-login.php', 'wp-content', 'sites/default',
                    'adminer.php', 'admin/login', 'api/v1', 'graphql', 'rest', 'static', 'media',
                    'uploads', '.git', '.svn', 'debug', 'trace', 'swagger', 'docs', 'robots.txt',
                    'sitemap.xml', 'web.config', 'cache', 'logs', 'tmp', 'assets', 'js', 'css', 'images'
                ]

            # Add domain-specific variations
            custom_words = set(base_words)
            for part in domain_parts:
                if len(part) > 2:
                    for word in base_words[:20]:  # Use top 20 base words
                        custom_words.add(f"{part}-{word}")
                        custom_words.add(f"{word}-{part}")
                        custom_words.add(f"{part}{word}")

            with open(custom_filepath, 'w') as f:
                for word in sorted(custom_words):
                    f.write(f"{word}\n")

            if not self.silent:
                logger.info(colored(f"Generated custom wordlist: {custom_filename} ({len(custom_words)} entries)", "green"))

            return custom_filepath
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error generating custom wordlist: {e}", "red"))
            return ""

    def list_available_wordlists(self):
        """List all available wordlists in the wordlists directory."""
        try:
            if not os.path.exists(self.wordlists_dir):
                if not self.silent:
                    logger.warning(colored("Wordlists directory not found", "yellow"))
                return []

            wordlists = [f for f in os.listdir(self.wordlists_dir) if f.endswith('.txt')]
            return sorted(wordlists)
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error listing wordlists: {e}", "red"))
            return []

    def run_interactive(self):
        """Run interactive wordlist generator."""
        if not self.silent:
            print(colored("\n🔧 REK Wordlist Generator", "cyan", attrs=["bold"]))

        while True:
            print(colored("\nWordlist Generator Options:", "cyan"))
            print(colored("1. Download SecLists wordlists", "green"))
            print(colored("2. Generate custom domain-based wordlist", "green"))
            print(colored("3. List available wordlists", "green"))
            print(colored("4. Exit", "red"))

            choice = input(colored("Select an option (1-4): ", "yellow")).strip()

            if choice == '1':
                self.download_seclists()
            elif choice == '2':
                self.generate_custom_interactive()
            elif choice == '3':
                self.list_wordlists_interactive()
            elif choice == '4':
                break
            else:
                print(colored("Invalid choice. Please select 1-4.", "red"))

    def download_seclists(self):
        """Download popular SecLists wordlists."""
        self.create_wordlists_directory()

        print(colored("\nSelect wordlist category:", "cyan"))
        for i, category in enumerate(self.common_wordlists.keys(), 1):
            print(colored(f"{i}. {category.title()}", "green"))
        print(colored(f"{len(self.common_wordlists) + 1}. All categories", "green"))

        try:
            choice = int(input(colored("Select category: ", "yellow")).strip())
            categories = list(self.common_wordlists.keys())

            if choice == len(self.common_wordlists) + 1:
                selected_categories = categories
            elif 1 <= choice <= len(categories):
                selected_categories = [categories[choice - 1]]
            else:
                print(colored("Invalid choice", "red"))
                return

            for category in selected_categories:
                if not self.silent:
                    print(colored(f"\nDownloading {category} wordlists...", "yellow"))

                for wordlist_path in self.common_wordlists[category]:
                    url = f"{self.seclists_base_url}/{wordlist_path}"
                    filename = f"{category}-{os.path.basename(wordlist_path)}"
                    self.download_wordlist(url, filename)
                    time.sleep(1)  # Be respectful to GitHub

            if not self.silent:
                print(colored("\nWordlist download completed!", "green"))

        except ValueError:
            print(colored("Invalid input. Please enter a number.", "red"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error in download process: {e}", "red"))

    def generate_custom_interactive(self):
        """Interactive custom wordlist generation."""
        domain = input(colored("Enter domain name (e.g., example.com): ", "yellow")).strip()
        if not domain:
            print(colored("Domain name is required", "red"))
            return

        print(colored("\nSelect wordlist type:", "cyan"))
        print(colored("1. Subdomains", "green"))
        print(colored("2. Directories", "green"))

        try:
            choice = int(input(colored("Select type (1-2): ", "yellow")).strip())
            wordlist_type = "subdomains" if choice == 1 else "directories" if choice == 2 else None

            if not wordlist_type:
                print(colored("Invalid choice", "red"))
                return

            self.create_wordlists_directory()
            filepath = self.generate_custom_wordlist(domain, wordlist_type)

            if filepath:
                print(colored(f"Custom wordlist generated: {filepath}", "green"))

        except ValueError:
            print(colored("Invalid input. Please enter a number.", "red"))

    def list_wordlists_interactive(self):
        """List available wordlists interactively."""
        wordlists = self.list_available_wordlists()

        if not wordlists:
            print(colored("No wordlists found in the wordlists directory", "yellow"))
            return

        print(colored(f"\nAvailable wordlists ({len(wordlists)}):", "cyan"))
        for i, wordlist in enumerate(wordlists, 1):
            filepath = os.path.join(self.wordlists_dir, wordlist)
            try:
                with open(filepath, 'r') as f:
                    line_count = sum(1 for _ in f)
                print(colored(f"{i:2d}. {wordlist} ({line_count} entries)", "green"))
            except:
                print(colored(f"{i:2d}. {wordlist} (error reading file)", "yellow"))


class HTTPStatusChecker:
    def __init__(self, timeout: int = 10, max_concurrent: int = 100, silent: bool = False):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.client = None
        self.silent = silent
        self.default_input_file = "results.txt"

    async def initialize_client(self):
        """Initialize the httpx AsyncClient."""
        limits = httpx.Limits(max_connections=self.max_concurrent, max_keepalive_connections=10)
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            limits=limits,
            follow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )

    async def close_client(self):
        """Close the httpx AsyncClient."""
        if self.client:
            await self.client.aclose()

    async def check_status(self, url: str, subdomain: str, semaphore: asyncio.Semaphore) -> Dict:
        """Check the HTTP status of a single URL."""
        async with semaphore:
            result = {
                'subdomain': subdomain,
                'url': url,
                'status_code': None,
                'title': None,
                'server': None,
                'error': None
            }
            try:
                response = await self.client.get(url)
                result['status_code'] = response.status_code
                result['server'] = response.headers.get('server', 'Unknown')

                if 'text/html' in response.headers.get('content-type', '') and response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title = soup.find('title')
                    result['title'] = title.text.strip() if title and title.text.strip() else 'No Title'

                if not self.silent:
                    color = "green" if result['status_code'] == 200 else "cyan" if result['status_code'] in [301, 302] else "yellow" if result['status_code'] == 403 else "red"
                    logger.info(colored(f"{url}: {result['status_code']}", color))
            except httpx.TimeoutException as e:
                result['error'] = f'Timeout: {str(e)}'
                if not self.silent:
                    logger.warning(colored(f"{url}: Timeout - {str(e)}", "yellow"))
            except httpx.ConnectError as e:
                result['error'] = f'Connection Failed: {str(e)}'
                if not self.silent:
                    logger.warning(colored(f"{url}: Connection Failed - {str(e)}", "yellow"))
            except httpx.HTTPStatusError as e:
                result['status_code'] = e.response.status_code if hasattr(e.response, 'status_code') else None
                result['error'] = f'HTTP Status Error: {str(e)}'
                if not self.silent:
                    color = "green" if result['status_code'] == 200 else "cyan" if result['status_code'] in [301, 302] else "yellow" if result['status_code'] == 403 else "red"
                    logger.warning(colored(f"{url}: HTTP Status Error - {result['status_code'] or 'Unknown'}", color))
            except Exception as e:
                result['error'] = f'Unexpected Error: {str(e)}'
                if not self.silent:
                    logger.error(colored(f"{url}: Unexpected Error - {str(e)}", "red"))
            return result

    async def check_all_urls(self, urls: List[str], output_file: str):
        """Check HTTP status for all URLs."""
        await self.initialize_client()
        try:
            semaphore = asyncio.Semaphore(self.max_concurrent)
            results = []
            tasks = []
            for url in urls:
                if not url:
                    if not self.silent:
                        logger.warning(colored("Skipping empty URL", "yellow"))
                    continue
                subdomain = urlparse(url).netloc if urlparse(url).netloc else url
                tasks.append(self.check_status(f"https://{url}", subdomain, semaphore))
                tasks.append(self.check_status(f"http://{url}", subdomain, semaphore))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            valid_results = []
            for result in results:
                if isinstance(result, dict):
                    required_keys = {'subdomain', 'url', 'status_code', 'title', 'server', 'error'}
                    if not all(key in result for key in required_keys):
                        if not self.silent:
                            logger.warning(colored(f"Invalid result format for URL {result.get('url', 'unknown')}: {result}", "yellow"))
                        continue
                    if result['status_code'] is not None:
                        try:
                            result['status_code'] = int(result['status_code'])
                        except (ValueError, TypeError):
                            if not self.silent:
                                logger.warning(colored(f"Non-numeric status code for URL {result['url']}: {result['status_code']}", "yellow"))
                            result['status_code'] = None
                    valid_results.append(result)
                else:
                    if not self.silent:
                        logger.warning(colored(f"Unexpected result type: {type(result)}", "yellow"))

            if not self.silent:
                logger.info(colored(f"Completed checking {len(urls)} URLs", "green"))

            try:
                output_dir = os.path.dirname(output_file)
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)
                else:
                    output_file = os.path.join(os.getcwd(), output_file)

                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL, escapechar='\\')
                    writer.writerow(["Subdomain", "URL", "Status Code", "Title", "Server", "Error"])
                    for result in sorted(valid_results, key=lambda x: x['subdomain']):
                        writer.writerow([
                            result['subdomain'] or '',
                            result['url'] or '',
                            result['status_code'] if result['status_code'] is not None else '',
                            result['title'] or '',
                            result['server'] or '',
                            result['error'] or ''
                        ])
                if not self.silent:
                    logger.info(colored(f"Saved {len(valid_results)} results to {output_file}", "green"))

                df = pd.read_csv(output_file, encoding='utf-8', dtype_backend='numpy_nullable')
                non_numeric = df['Status Code'][df['Status Code'].notna() & ~df['Status Code'].astype(str).str.isnumeric()]
                if not non_numeric.empty:
                    if not self.silent:
                        logger.warning(colored(f"Non-numeric values found in 'Status Code' column after writing: {non_numeric.tolist()}", "yellow"))
            except Exception as e:
                if not self.silent:
                    logger.error(colored(f"Error saving results to {output_file}: {e}", "red"))
                raise
        finally:
            await self.close_client()

    def run(self, input_file: str, output_file: str):
        """Run the HTTP status checker."""
        input_file = input_file or self.default_input_file

        if not os.path.exists(input_file):
            if not self.silent:
                logger.error(colored(f"Input file {input_file} does not exist.", "red"))
            sys.exit(1)

        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            if not self.silent:
                logger.info(colored(f"Loaded {len(urls)} URLs from {input_file}", "green"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error reading input file {input_file}: {e}", "red"))
            sys.exit(1)

        if not urls:
            if not self.silent:
                logger.warning(colored("No URLs to check", "yellow"))
            return

        if not self.silent:
            print(colored("Running HTTP Status Checking...", "green"))
        asyncio.run(self.check_all_urls(urls, output_file))
        if not self.silent:
            print(colored("Finished HTTP Status Checking.", "green"))

class DirectoryScanner:
    def __init__(self, timeout: int = 10, max_concurrent: int = 50, max_depth: int = 5, silent: bool = False):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.max_depth = min(max_depth, 10)
        self.results: Dict[str, List[Dict]] = {}
        self.client = None
        self.global_wordlist_path = "global_wordlist.txt"
        self.global_wordlist: Set[str] = self.load_global_wordlist()
        self.default_wordlist = [
            'admin', 'login', 'dashboard', 'api', 'config', 'backup', 'test', 'dev', 'staging', '.env', 'config.php',
            'wp-config.php', '.htaccess', 'backup.sql', 'db.sql', 'phpinfo.php', 'wp-admin', 'wp-login.php', 'wp-content',
            'sites/default', 'adminer.php', 'admin/login', 'api/v1', 'graphql', 'rest', 'static', 'media', 'uploads',
            '.git', '.svn', 'debug', 'trace', 'swagger', 'docs', 'openapi.json', 'index.php', 'index.html', 'home',
            'portal', 'user', 'account', 'settings', 'robots.txt', 'sitemap.xml', 'web.config', 'app_data', 'cache',
            'logs', 'tmp', 'assets', 'js', 'css', 'images', 'vendor', 'src', 'dist', 'build', 'public', 'private',
            'secret', 'credentials', 'key', 'token', 'jwt', 'oauth2', 'auth', 'signin', 'signup', 'profile', 'logout'
        ]
        self.fallback_tech_wordlist = [
            'admin', 'login', 'api', '.env', 'config', 'static', 'media', 'uploads', 'robots.txt', 'sitemap.xml'
        ]
        self.screenshot_driver = None
        self.silent = silent

    def load_global_wordlist(self) -> Set[str]:
        """Load the global wordlist from file."""
        try:
            if os.path.exists(self.global_wordlist_path):
                with open(self.global_wordlist_path, 'r') as f:
                    return set(line.strip() for line in f if line.strip())
            return set()
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error loading global wordlist: {e}", "red"))
            return set()

    def save_global_wordlist(self):
        """Save the global wordlist to file."""
        try:
            global_output_path = self.global_wordlist_path
            output_dir = os.path.dirname(global_output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            else:
                global_output_path = os.path.join(os.getcwd(), global_output_path)

            with open(global_output_path, 'w') as f:
                for path in sorted(self.global_wordlist):
                    f.write(f"{path}\n")
            if not self.silent:
                logger.info(colored(f"Updated global wordlist: {global_output_path}", "green"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error saving global wordlist: {e}", "red"))

    async def initialize_client(self):
        """Initialize the httpx AsyncClient."""
        limits = httpx.Limits(max_connections=self.max_concurrent, max_keepalive_connections=10)
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            limits=limits,
            follow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )

    async def close_client(self):
        """Close the httpx AsyncClient."""
        if self.client:
            await self.client.aclose()

    def initialize_screenshot_driver(self):
        """Initialize the Selenium WebDriver for screenshots."""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            self.screenshot_driver = webdriver.Chrome(options=chrome_options)
            if not self.silent:
                logger.info(colored("Initialized Selenium WebDriver", "green"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error initializing Selenium WebDriver: {e}", "red"))
            self.screenshot_driver = None

    def close_screenshot_driver(self):
        """Close the Selenium WebDriver."""
        if self.screenshot_driver:
            self.screenshot_driver.quit()
            if not self.silent:
                logger.info(colored("Closed Selenium WebDriver", "green"))

    def read_urls_by_status(self, input_file: str, status_codes: List[int]) -> List[str]:
        """Read URLs from CSV file filtered by status codes with improved error handling."""
        try:
            df = pd.read_csv(input_file, encoding='utf-8', sep=',', dtype_backend='numpy_nullable')
            if df.empty:
                if not self.silent:
                    logger.warning(colored(f"Input file {input_file} is empty", "yellow"))
                return []

            if not self.silent:
                logger.info(colored(f"Columns in {input_file}: {list(df.columns)}", "green"))
                logger.info(colored(f"First 5 rows of {input_file}:\n{df.head(5).to_string()}", "green"))

            status_col = 'Status Code'
            if status_col not in df.columns:
                if not self.silent:
                    logger.error(colored(f"Required column '{status_col}' not found in {input_file}", "red"))
                return []

            if not self.silent:
                logger.info(colored(f"Raw values in '{status_col}' column: {df[status_col].tolist()}", "green"))

            non_numeric = df[status_col][df[status_col].notna() & ~df[status_col].astype(str).str.isnumeric()]
            if not non_numeric.empty:
                if not self.silent:
                    logger.warning(colored(f"Non-numeric values found in '{status_col}' column: {non_numeric.tolist()}", "yellow"))
                possible_status_cols = ['status_code', 'Status', 'status']
                for col in possible_status_cols:
                    if col in df.columns:
                        non_numeric_check = df[col][df[col].notna() & ~df[col].astype(str).str.isnumeric()]
                        if non_numeric_check.empty:
                            status_col = col
                            if not self.silent:
                                logger.info(colored(f"Falling back to column '{col}' for status codes", "green"))
                            break
                else:
                    if not self.silent:
                        logger.error(colored(f"No valid status code column found in {input_file}", "red"))
                    return []

            df[status_col] = pd.to_numeric(df[status_col], errors='coerce').astype('Int64')
            df = df[df[status_col].notna()]

            unique_statuses = df[status_col].dropna().unique().tolist()
            if not self.silent:
                logger.info(colored(f"Unique status codes in {input_file}: {unique_statuses}", "green"))

            df_filtered = df[df[status_col].isin(status_codes)]
            urls = df_filtered['URL'].dropna().tolist()

            if not urls:
                if not self.silent:
                    logger.warning(colored(f"No URLs found with status codes {status_codes} in {input_file}", "yellow"))

            if not self.silent:
                logger.info(colored(f"Found {len(urls)} URLs with status codes {status_codes}", "green"))
            return urls
        except FileNotFoundError:
            if not self.silent:
                logger.error(colored(f"Input file {input_file} does not exist", "red"))
            return []
        except pd.errors.ParserError as e:
            if not self.silent:
                logger.error(colored(f"CSV parsing error in {input_file}: {e}", "red"))
            return []
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error reading input file {input_file}: {e}", "red"))
            return []

    def load_wordlist(self, wordlist_path: str = None) -> List[str]:
        """Load wordlist from file or use enhanced default."""
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                if not self.silent:
                    logger.error(colored(f"Error loading wordlist {wordlist_path}: {e}", "red"))
        return self.default_wordlist

    def detect_technologies(self, url: str) -> List[str]:
        """Detect technologies and generate domain-specific wordlist."""
        if not self.silent:
            logger.info(colored(f"Detecting technologies for {url}", "green"))
        wordlist = []
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(url, headers={'User-Agent': 'Mozilla/5.0'})
            techs = wappalyzer.analyze_with_versions_and_categories(webpage)
            if not self.silent:
                logger.info(colored(f"Detected technologies: {techs.keys()}", "green"))

            for tech, details in techs.items():
                category = details.get('categories', [{}])[0].get('name', '').lower()
                if 'wordpress' in tech.lower():
                    wordlist.extend(['wp-admin', 'wp-login.php', 'wp-content', 'wp-includes', 'xmlrpc.php', 'wp-config', 'wp-load.php'])
                elif 'drupal' in tech.lower():
                    wordlist.extend(['sites/default', 'modules', 'themes', 'core', 'install.php', 'settings.php'])
                elif 'php' in tech.lower():
                    wordlist.extend(['phpinfo.php', 'admin.php', 'config.php', 'info.php', 'install.php', 'setup.php'])
                elif 'apache' in tech.lower():
                    wordlist.extend(['server-status', 'server-info', '.htaccess', 'access_log'])
                elif 'nginx' in tech.lower():
                    wordlist.extend(['nginx_status', 'stub_status', 'error.log'])
                elif 'django' in tech.lower():
                    wordlist.extend(['admin', 'api', 'static', 'media', 'debug', 'urls.py', 'settings.py'])
                elif 'javascript' in category:
                    wordlist.extend(['js', 'scripts', 'assets', 'bundle.js', 'min.js', 'vendor.js'])
                elif 'cms' in category:
                    wordlist.extend(['admin', 'login', 'dashboard', 'content', 'editor', 'manage', 'control'])
                elif 'java' in tech.lower():
                    wordlist.extend(['WEB-INF', 'META-INF', 'struts', 'actuator', 'jsp', 'servlet'])
                elif 'laravel' in tech.lower():
                    wordlist.extend(['.env', 'artisan', 'storage', 'vendor', 'bootstrap', 'routes.php'])

            wordlist = list(set(wordlist))
            if not wordlist:
                if not self.silent:
                    logger.warning(colored(f"No technology-specific paths detected for {url}, using fallback wordlist", "yellow"))
                wordlist = self.fallback_tech_wordlist
            if not self.silent:
                logger.info(colored(f"Generated {len(wordlist)} paths for {url}: {wordlist[:10]}...", "green"))
            return wordlist
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Technology detection failed for {url}: {e}", "red"))
                logger.info(colored(f"Using fallback wordlist for {url}", "green"))
            return self.fallback_tech_wordlist

    def save_domain_wordlist(self, domain: str, wordlist: List[str]):
        """Save domain-specific wordlist."""
        try:
            wordlist_path = f"wordlists/{domain}.txt"
            os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
            with open(wordlist_path, 'w') as f:
                for path in sorted(wordlist):
                    f.write(f"{path}\n")
            if not self.silent:
                logger.info(colored(f"Saved domain-specific wordlist: {wordlist_path} with {len(wordlist)} entries", "green"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error saving domain wordlist for {domain}: {e}", "red"))

    def take_screenshot(self, url: str, domain: str) -> str:
        """Take a screenshot of the URL and save it with a filename based on the full URL path."""
        if not self.screenshot_driver:
            return "Selenium not initialized"

        try:
            screenshot_dir = f"results/{domain}/screenshots"
            os.makedirs(screenshot_dir, exist_ok=True)
            safe_filename = re.sub(r'[^\w\-._]', '_', url)
            safe_filename = safe_filename.replace('http_', 'http')
            safe_filename = safe_filename[:200] + '.png'
            screenshot_path = os.path.join(screenshot_dir, safe_filename)

            self.screenshot_driver.set_window_size(1920, 1080)
            self.screenshot_driver.get(url)
            time.sleep(1)
            self.screenshot_driver.save_screenshot(screenshot_path)
            if not self.silent:
                logger.info(colored(f"Screenshot saved: {screenshot_path}", "green"))
            return screenshot_path
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error taking screenshot for {url}: {e}", "red"))
            return f"Error: {str(e)}"

    async def scan_directory(self, url: str, path: str, depth: int) -> List[Dict]:
        """Scan a single directory path and crawl if status is 200."""
        full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        results = []
        result = {
            'url': full_url,
            'status_code': None,
            'content_type': None,
            'screenshot': None,
            'error': None,
            'depth': depth
        }
        try:
            response = await self.client.get(full_url)
            result['status_code'] = response.status_code
            result['content_type'] = response.headers.get('content-type', 'Unknown')

            if response.status_code in [200, 301, 302, 403]:
                self.global_wordlist.add(path)
                results.append(result)
                if response.status_code == 200 and depth < self.max_depth:
                    sub_results = await self.crawl_subdirectories(full_url, depth + 1)
                    results.extend(sub_results)
                    result['screenshot'] = self.take_screenshot(full_url, urlparse(url).netloc)
        except httpx.TimeoutException as e:
            result['error'] = f'Timeout: {str(e)}'
            results.append(result)
            if not self.silent:
                logger.warning(colored(f"{full_url}: Timeout - {str(e)}", "yellow"))
        except httpx.ConnectError as e:
            result['error'] = f'Connection Failed: {str(e)}'
            results.append(result)
            if not self.silent:
                logger.warning(colored(f"{full_url}: Connection Failed - {str(e)}", "yellow"))
        except httpx.HTTPStatusError as e:
            result['status_code'] = e.response.status_code if hasattr(e.response, 'status_code') else None
            result['error'] = f'HTTP Status Error: {str(e)}'
            results.append(result)
            if not self.silent:
                color = "green" if result['status_code'] == 200 else "cyan" if result['status_code'] in [301, 302] else "yellow" if result['status_code'] == 403 else "red"
                logger.warning(colored(f"{full_url}: HTTP Status Error - {result['status_code'] or 'Unknown'}", color))
        except Exception as e:
            result['error'] = f'Unexpected Error: {str(e)}'
            results.append(result)
            if not self.silent:
                logger.error(colored(f"{full_url}: Unexpected Error - {str(e)}", "red"))

        return results

    async def crawl_subdirectories(self, url: str, depth: int) -> List[Dict]:
        """Recursively crawl subdirectories for status 200 responses."""
        results = []
        for path in self.default_wordlist:
            sub_results = await self.scan_directory(url, path, depth)
            results.extend(sub_results)
        return results

    def filter_deepest_paths(self, results: List[Dict]) -> List[Dict]:
        """Filter results to keep only the deepest path for each branch."""
        path_map: Dict[str, Dict] = {}
        for result in results:
            if not result.get('status_code') and not result.get('error'):
                continue
            url = result['url']
            path = urlparse(url).path.lstrip('/')
            if not path:
                path = '/'
            path_components = path.split('/')
            path_key = '/'.join(path_components[:-1]) if path_components else '/'

            if path_key not in path_map or (
                result.get('depth', 0) > path_map[path_key].get('depth', 0) or
                (result.get('status_code') in [301, 302, 403] and path_map[path_key].get('status_code') == 200)
            ):
                path_map[path_key] = result

        return list(path_map.values())

    async def scan_url(self, url: str, wordlist: List[str], semaphore: asyncio.Semaphore):
        """Scan a single URL with the provided wordlist."""
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            if not self.silent:
                logger.error(colored(f"Invalid URL: {url}", "red"))
            return

        domain = parsed_url.netloc
        if domain not in self.results:
            self.results[domain] = []

        async with semaphore:
            if not self.silent:
                logger.info(colored(f"Generating domain-specific wordlist for {domain}", "green"))
            tech_wordlist = self.detect_technologies(url)
            self.save_domain_wordlist(domain, tech_wordlist or self.fallback_tech_wordlist)
            combined_wordlist = list(set(wordlist + tech_wordlist))
            if not self.silent:
                logger.info(colored(f"Using {len(combined_wordlist)} paths for {url}", "green"))

            tasks = [self.scan_directory(url, path, depth=1) for path in combined_wordlist]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result_list in results:
                if isinstance(result_list, list):
                    self.results[domain].extend(result_list)

            self.results[domain] = self.filter_deepest_paths(self.results[domain])

    async def scan_all_urls(self, urls: List[str], wordlist: List[str]):
        """Scan all URLs with the provided wordlist."""
        await self.initialize_client()
        self.initialize_screenshot_driver()
        try:
            semaphore = asyncio.Semaphore(self.max_concurrent)
            tasks = [self.scan_url(url, wordlist, semaphore) for url in urls]
            await asyncio.gather(*tasks)
            if not self.silent:
                logger.info(colored(f"Completed scanning {len(urls)} URLs", "green"))
        finally:
            await self.close_client()
            self.close_screenshot_driver()
            self.save_global_wordlist()

    def run(self, input_file: str = None, status_codes: List[int] = None, url: str = None, wordlist_path: str = None):
        """Run the directory scanner."""
        wordlist = self.load_wordlist(wordlist_path)
        urls = []

        if status_codes and input_file:
            urls = self.read_urls_by_status(input_file, status_codes)
        elif url:
            urls = [url]
        else:
            if not self.silent:
                logger.error(colored("Must provide either status codes with input file or a URL", "red"))
            return

        if not urls:
            if not self.silent:
                logger.warning(colored("No URLs to scan", "yellow"))
            return

        if not self.silent:
            print(colored("Running Directory Scanning...", "green"))
        asyncio.run(self.scan_all_urls(urls, wordlist))
        if not self.silent:
            print(colored("Finished Directory Scanning.", "green"))
        self.save_results()

    def save_results(self):
        """Save scan results per domain."""
        try:
            for domain, results in self.results.items():
                output_path = f"results/{domain}/dirs.csv"
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, 'w') as f:
                    f.write("URL,Status Code,Content Type,Screenshot,Error\n")
                    for result in sorted(results, key=lambda x: x['url']):
                        f.write(
                            f"{result['url']},"
                            f"{result['status_code'] or ''},"
                            f"{result['content_type'] or ''},"
                            f"{result['screenshot'] or ''},"
                            f"{result['error'] or ''}\n"
                        )
                if not self.silent:
                    logger.info(colored(f"Saved results for {domain}: {output_path}", "green"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error saving results: {e}", "red"))

class ReconTool:
    def __init__(self, args):
        self.args = args
        self.subdomain_scanner = SubdomainScanner(args.timeout, args.subdomain_wordlist, args.concurrency, args.retries, args.silent)
        self.http_checker = HTTPStatusChecker(args.timeout, args.concurrency, args.silent)
        self.dir_scanner = DirectoryScanner(args.timeout, args.concurrency, args.depth, args.silent)
        self.email_searcher = EmailSearcher(args.timeout, args.silent)
        self.wordlist_generator = WordlistGenerator(args.silent)
        self.silent = args.silent
        self.default_input_file = "http_results.csv"

    def display_banner(self):
        """Display the banner."""
        banner = """
**************************************
  RRR   EEEEE  K   K
  R  R  E      K  K
  BJP   EEEE   KKK
  R  R  E      K  K
  R   R EEEEE  K   K

  rek - Reconnaissance Tool
  Authored by: Jayresearcher, NarutoX , Ninja
  Bug Bounty Hunter © 2025 - For ethical hacking and security research only
  By scanning this domain, you agree that you own or have permission to perform this scanning or research.
  Empowering Ethical Hackers
**************************************
"""
        print(colored(banner, "cyan"))

    def display_rek_menu(self):
        """Display the initial REK menu with colors."""
        print(colored("REK Menu", "cyan", attrs=["bold"]))
        print(colored("1. Run Recon Playbook", "green"))
        print(colored("2. Subdomain Enumeration", "green"))
        print(colored("3. HTTP Status Checking", "green"))
        print(colored("4. Directory Scanning", "green"))
        print(colored("5. REK Email Search", "green"))
        print(colored("6. REK Wordlist Generator", "green"))
        print(colored("7. Exit", "red"))
        return input(colored("Select an option (1-7): ", "yellow"))

    def display_recon_menu(self, show_examples: bool = False):
        """Display the Recon Tool menu with colors."""
        print(colored("\nRecon Tool Menu:", "cyan", attrs=["bold"]))
        if show_examples:
            print(
                colored("1. ", "green") +
                colored("Subdomain Enumeration", "light_green") + ": " +
                colored("python3 rek-beta.py ", "green") +
                colored("-d", "cyan") + " xyz.com " +
                colored("-w", "cyan") + " subdomains.txt " +
                colored("--dir-wordlist", "cyan") + " common.txt " +
                colored("-t", "cyan") + " 15 " +
                colored("-c", "cyan") + " 100 " +
                colored("--depth", "cyan") + " 5"
            )
            print(
                colored("2. ", "green") +
                colored("HTTP Status Checking", "light_green") + ": " +
                colored("python3 rek-beta.py ", "green") +
                colored("--input", "cyan") + " results.txt " +
                colored("-o", "cyan") + " http_results.csv " +
                colored("-t", "cyan") + " 15 " +
                colored("-c", "cyan") + " 100"
            )
            print(
                colored("3. ", "green") +
                colored("Directory Scanning", "light_green") + ": " +
                colored("python3 rek-beta.py ", "green") +
                colored("--input", "cyan") + " http_results.csv " +
                colored("--status", "cyan") + " 200,301 " +
                colored("--dir-wordlist", "cyan") + " common.txt " +
                colored("-t", "cyan") + " 15 " +
                colored("-c", "cyan") + " 100 " +
                colored("--depth", "cyan") + " 5"
            )
        else:
            print(colored("1. Subdomain Enumeration", "green"))
            print(colored("2. HTTP Status Checking", "green"))
            print(colored("3. Directory Scanning", "green"))
        print(colored("4. Exit", "red"))
        return input(colored("Select an option (1-4): ", "yellow"))

    def display_email_menu(self, show_examples: bool = False):
        """Display the Email Search menu with colors and emojis."""
        print(colored("\n📧 Email Search Menu:", "cyan", attrs=["bold"]))
        if show_examples:
            print(
                colored("1. ", "green") +
                colored("Search by Domain", "light_green") + ": " +
                colored("python3 rek-beta.py ", "green") +
                colored("--email-domain", "cyan") + " xyz.com " +
                colored("-o", "cyan") + " email_results.csv " +
                colored("--token", "cyan") + " ghp_xxx " +
                colored("--hibp-key", "cyan") + " hibp_xxx " +
                colored("--limit-commits", "cyan") + " 50"
            )
            print(
                colored("2. ", "green") +
                colored("Search by Username or Organization", "light_green") + ": " +
                colored("python3 rek-beta.py ", "green") +
                colored("--org", "cyan") + " microsoft " +
                colored("-o", "cyan") + " email_results.csv " +
                colored("--token", "cyan") + " ghp_xxx " +
                colored("--hibp-key", "cyan") + " hibp_xxx"
            )
        else:
            print(colored("1. 📧 Search by Domain", "green"))
            print(colored("2. 👤 Search by Username or Organization", "green"))
        print(colored("3. 🚪 Exit", "red"))
        return input(colored("Select an option (1-3): ", "yellow"))

    def prompt_subdomain_args(self):
        """Prompt for Subdomain Enumeration arguments."""
        print(colored("\nEnter arguments:", "cyan"))
        domain = input(colored("-d/--domain: Domain for subdomain enumeration (e.g., xyz.com): ", "yellow")).strip()
        output = input(colored("-o/--output: Output file (default: results.txt): ", "yellow")).strip()
        if not output:
            output = "results.txt"
            print(colored(f"No output file specified. Using default: {output}", "yellow"))
        wordlist = input(colored("-w/--subdomain-wordlist: Wordlist file for subdomain enumeration: ", "yellow")).strip() or None
        timeout = input(colored("-t/--timeout: Request timeout in seconds (default: 10): ", "yellow")).strip() or "10"
        concurrency = input(colored("-c/--concurrency: Maximum concurrent requests (default: 50): ", "yellow")).strip() or "50"
        retries = input(colored("-r/--retries: Number of retries for failed requests (default: 3): ", "yellow")).strip() or "3"
        token = input(colored("--token: GitHub Personal Access Token (optional): ", "yellow")).strip() or None
        max_commits = input(colored("--limit-commits: Max commits to scan per repo (default: 50): ", "yellow")).strip() or "50"
        skip_forks = input(colored("--skip-forks: Skip forked repositories? (y/n, default: y): ", "yellow")).strip().lower() == 'y'

        class Args:
            pass
        args = Args()
        args.domain = domain
        args.output = output
        args.subdomain_wordlist = wordlist
        args.timeout = int(timeout)
        args.concurrency = int(concurrency)
        args.retries = int(retries)
        args.token = token
        args.limit_commits = int(max_commits)
        args.skip_forks = skip_forks
        args.silent = self.silent
        return args

    def prompt_http_args(self):
        """Prompt for HTTP Status Checking arguments."""
        print(colored("\nEnter arguments:", "cyan"))
        input_file = input(colored("--input: Input file with URLs (default: results.txt, press Enter to use default): ", "yellow")).strip() or "results.txt"
        output = input(colored("-o/--output: Output file (default: http_results.csv): ", "yellow")).strip() or "http_results.csv"
        timeout = input(colored("-t/--timeout: Request timeout in seconds (default: 10): ", "yellow")).strip() or "10"
        concurrency = input(colored("-c/--concurrency: Maximum concurrent requests (default: 50): ", "yellow")).strip() or "50"

        class Args:
            pass
        args = Args()
        args.input = input_file
        args.output = output
        args.timeout = int(timeout)
        args.concurrency = int(concurrency)
        args.silent = self.silent
        return args

    def prompt_directory_args(self):
        """Prompt for Directory Scanning arguments."""
        print(colored("\nEnter arguments:", "cyan"))
        input_file = input(colored("--input: Input file with URLs (optional if --url is provided, default: http_results.csv): ", "yellow")).strip() or None
        status = input(colored("--status: Comma-separated status codes for directory scanning (e.g., 200,301): ", "yellow")).strip()
        url = input(colored("--url: Single URL for directory scanning (e.g., https://xyz.com) (optional if --input and --status are provided): ", "yellow")).strip()
        wordlist = input(colored("--dir-wordlist: Wordlist file for directory scanning: ", "yellow")).strip() or None
        timeout = input(colored("-t/--timeout: Request timeout in seconds (default: 10): ", "yellow")).strip() or "10"
        concurrency = input(colored("-c/--concurrency: Maximum concurrent requests (default: 50): ", "yellow")).strip() or "50"
        depth = input(colored("--depth: Maximum crawling depth for directory scanning (1-10, default: 5): ", "yellow")).strip() or "5"

        class Args:
            pass
        args = Args()
        ```python
# Corrected the syntax error in the WordlistGenerator class definition.
    args.input = input_file if input_file else None
        args.status = status if status else None
        args.url = url if url else None
        args.dir_wordlist = wordlist
        args.timeout = int(timeout)
        args.concurrency = int(concurrency)
        args.depth = int(depth)
        args.silent = self.silent
        return args

    def prompt_email_args(self, by_domain: bool = True):
        """Prompt for Email Search arguments."""
        print(colored("\nEnter arguments:", "cyan"))
        if by_domain:
            target = input(colored("--email-domain: Domain for email search (e.g., xyz.com): ", "yellow")).strip()
        else:
            target = input(colored("--email-username or --org: GitHub username or organization (e.g., exampleuser or exampleorg): ", "yellow")).strip()
        output = input(colored("-o/--output: Output file (default: email_results.csv): ", "yellow")).strip() or "email_results.csv"
        token = input(colored("--token: GitHub Personal Access Token (optional): ", "yellow")).strip() or None
        hibp_key = input(colored("--hibp-key: HIBP API key (optional): ", "yellow")).strip() or None
        limit_commits = input(colored("--limit-commits: Max commits to scan per repo (default: 50): ", "yellow")).strip() or "50"
        skip_forks = input(colored("--skip-forks: Skip forked repositories? (y/n, default: y): ", "yellow")).strip().lower() == 'y'
        timeout = input(colored("-t/--timeout: Request timeout in seconds (default: 10): ", "yellow")).strip() or "10"

        class Args:
            pass
        args = Args()
        if by_domain:
            args.email_domain = target
            args.email_username = None
            args.org = None
        else:
            args.email_domain = None
            args.email_username = target
            args.org = target
        args.output = output
        args.token = token
        args.hibp_key = hibp_key
        args.limit_commits = int(limit_commits)
        args.skip_forks = skip_forks
        args.timeout = int(timeout)
        args.silent = self.silent
        return args

    def list_playbooks(self):
        """List available playbook scripts in the playbook directory."""
        playbook_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "playbook")
        playbook_files = glob.glob(os.path.join(playbook_dir, "rek-playbook*.sh"))
        return sorted([os.path.basename(playbook) for playbook in playbook_files])

    def select_playbook(self):
        """Prompt user to select a playbook version."""
        playbooks = self.list_playbooks()
        if not playbooks:
            print(colored("[!] No playbook scripts found in the playbook directory", "red"))
            return None

        print(colored("\nAvailable Playbook Versions:", "cyan"))
        for i, playbook in enumerate(playbooks, 1):
            version = playbook.replace('rek-playbook', '').replace('.sh', '')
            version = 'Original' if version == '' else f'v{version[2:]}'
            print(colored(f"[{i}] {version} ({playbook})", "green"))

        while True:
            try:
                choice = input(colored(f"\nSelect a playbook version (1-{len(playbooks)}): ", "yellow")).strip()
                choice = int(choice)
                if 1 <= choice <= len(playbooks):
                    return playbooks[choice - 1]
                else:
                    print(colored(f"[!] Invalid choice. Please select a number between 1 and {len(playbooks)}", "red"))
            except ValueError:
                print(colored("[!] Invalid input. Please enter a number.", "red"))

    def run_playbook(self):
        """Execute the selected recon playbook script with real-time log streaming."""
        print(colored("[*] Preparing to run recon playbook...", "blue"))

        # Select playbook
        playbook_script = self.select_playbook()
        if not playbook_script:
            return

        # Prompt for domain and threads
        domain = input(colored("[?] Enter the target domain (e.g., example.com): ", "yellow")).strip()
        if not domain:
            print(colored("[!] No domain provided", "red"))
            return

        extracted_domain = extract(domain).domain
        if not extracted_domain:
            print(colored("[!] Invalid domain format", "red"))
            return

        threads = input(colored("[?] Enter number of threads (default: 100, press Enter to skip): ", "yellow")).strip() or "100"
        try:
            threads = int(threads)
            if threads <= 0:
                raise ValueError
        except ValueError:
            print(colored("[!] Invalid thread count. Using default: 100", "yellow"))
            threads = 100

        # Determine paths
        script_dir = os.path.dirname(os.path.abspath(__file__))
        playbook_dir = os.path.join(script_dir, "playbook")
        playbook_path = os.path.join(playbook_dir, playbook_script)
        install_script = os.path.join(playbook_dir, f"install-script{playbook_script.replace('rek-playbook', '')}")
        tools_dir = os.path.join(script_dir, "tools")
        config_path = os.path.join(script_dir, "config.conf")
        wordlists_dir = os.path.join(script_dir, "wordlists")
        recon_toolkit_dir = script_dir

        # Check if playbook directory and scripts exist
        if not os.path.isdir(playbook_dir):
            print(colored(f"[!] Error: {playbook_dir} directory not found.", "red"))
            return
        if not os.path.isfile(install_script):
            print(colored(f"[!] Error: {install_script} not found.", "red"))
            return
        if not os.path.isfile(playbook_path):
            print(colored(f"[!] Error: {playbook_path} not found.", "red"))
            return

        # Make scripts executable
        try:
            subprocess.run(["chmod", "+x", install_script], check=True, capture_output=True)
            subprocess.run(["chmod", "+x", playbook_path], check=True, capture_output=True)

        except subprocess.CalledProcessError as e:
            print(colored(f"[!] Error making scripts executable: {e.stderr.decode()}", "red"))
            return

        # Set up environment variables
        env = os.environ.copy()
        go_bin = os.path.expanduser("~/go/bin")
        env["PATH"] = f"{tools_dir}:{go_bin}:{env.get('PATH', '')}"
        env["RECON_TOOLKIT_DIR"] = recon_toolkit_dir
        env["TOOLS_DIR"] = tools_dir
        env["CONFIG_PATH"] = config_path
        env["WORDLISTS_DIR"] = wordlists_dir

        def stream_script(script_path, script_name, args=None):
            """Run a script and stream its output in real-time with combined stdout/stderr."""
            print(colored(f"[*] Running {script_name}...", "yellow"))
            cmd = [script_path]
            if args:
                cmd.extend(args)
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=env,
                    cwd=recon_toolkit_dir
                )
                error_patterns = re.compile(r'^(Warning|Error|fatal|ERROR|WARNING):', re.IGNORECASE)
                start_time = time.time()
                while process.poll() is None:
                    line = process.stdout.readline()
                    if line:
                        if error_patterns.search(line.strip()):
                            print(colored(line.rstrip(), "red"))
                        else:
                            print(line.rstrip())
                stdout, _ = process.communicate()
                if stdout:
                    for line in stdout.splitlines():
                        if error_patterns.search(line.strip()):
                            print(colored(line.rstrip(), "red"))
                        else:
                            print(line.rstrip())
                if process.returncode == 0:
                    duration = time.time() - start_time
                    print(colored(f"[✓] {script_name} completed successfully in {duration:.2f} seconds.", "green"))
                else:
                    print(colored(f"[!] Error running {script_name}: Non-zero exit code {process.returncode}", "red"))
            except Exception as e:
                print(colored(f"[!] Error running {script_name}: {str(e)}", "red"))

        # Execute install script
        stream_script(install_script, os.path.basename(install_script))

        # Execute playbook script with domain and threads
        stream_script(playbook_path, playbook_script, ["-d", domain, "-t", str(threads)])

        print(colored("[✓] Recon playbook execution completed.", "green"))

    def identify_task(self):
        """Identify which task to run based on provided arguments."""
        args = self.args
        if args.email_domain or args.email_username or args.org:
            return "email"
        if args.domain:
            return "subdomain"
        if args.input and args.output and not args.status and not args.url:
            return "http"
        if (args.input and args.status) or args.url:
            return "directory"
        return None

    def has_valid_args(self):
        """Check if the provided arguments are sufficient to run a task."""
        return self.identify_task() is not None

    def parse_and_run_command(self, command: str, recon_choice: str):
        """Parse the user-provided command and run the appropriate scan."""
        if not command.strip():
            parser = argparse.ArgumentParser(description="rek - Recon Tool for bug bounty hunting")
            parser.add_argument('-d', '--domain', help="Domain for subdomain enumeration (e.g., xyz.com)")
            parser.add_argument('--email-domain', help="Domain for email search (e.g., xyz.com)")
            parser.add_argument('--email-username', help="GitHub username for email search (e.g., exampleuser)")
            parser.add_argument('-o', '--output', help="Output file for results (default: results.txt, http_results.csv, or email_results.csv)")
            parser.add_argument('--input', help="Input file with URLs for HTTP status or directory scanning")
            parser.add_argument('--status', help="Comma-separated status codes for directory scanning (e.g., 200,301)")
            parser.add_argument('--url', help="Single URL for directory scanning (e.g., https://xyz.com)")
            parser.add_argument('-w', '--subdomain-wordlist', help="Wordlist file for subdomain enumeration")
            parser.add_argument('--dir-wordlist', help="Wordlist file for directory scanning")
            parser.add_argument('--token', help="GitHub Personal Access Token")
            parser.add_argument('--limit-commits', type=int, default=50, help="Max commits to scan per repo")
            parser.add_argument('--skip-forks', action='store_true', help="Skip forked repositories")
            parser.add_argument('-t', '--timeout', type=int, default=10, help="Request timeout in seconds")
            parser.add_argument('-c', '--concurrency', type=int, default=50, help="Maximum concurrent requests")
            parser.add_argument('-r', '--retries', type=int, default=3, help="Number of retries for failed requests")
            parser.add_argument('--depth', type=int, default=5, help="Maximum crawling depth for directory scanning (1-10)")
            parser.add_argument('--silent', action='store_true', help="Run in silent mode (only show main status messages)")

            if recon_choice == '1':
                args_list = ['-d', 'xyz.com', '-o', 'results.txt']
            elif recon_choice == '2':
                args_list = ['--input', 'results.txt', '-o', 'http_results.csv']
            elif recon_choice == '3':
                args_list = ['--input', 'http_results.csv', '--status', '200,301']
            elif recon_choice == '4':
                args_list = ['--email-domain', 'xyz.com', '-o', 'email_results.csv']
            else:
                print(colored("Invalid recon choice for default command.", "red"))
                return

            try:
                args = parser.parse_args(args_list)
            except Exception as e:
                print(colored(f"Error setting default command: {e}", "red"))
                return
        else:
            try:
                args_list = shlex.split(command)
                script_names = ["rek-beta.py", "rek.py", "recon_tool.py"]
                if args_list and args_list[0].startswith("python"):
                    args_list = args_list[1:]
                if args_list and any(script_name in args_list[0] for script_name in script_names):
                    args_list = args_list[1:]

                parser = argparse.ArgumentParser(description="rek - Recon Tool for bug bounty hunting")
                parser.add_argument('-d', '--domain', help="Domain for subdomain enumeration (e.g., xyz.com)")
                parser.add_argument('--email-domain', help="Domain for email search (e.g., xyz.com)")
                parser.add_argument('--email-username', help="GitHub username for email search (e.g., exampleuser)")
                parser.add_argument('-o', '--output', help="Output file for results (default: results.txt, http_results.csv, or email_results.csv)")
                parser.add_argument('--input', help="Input file with URLs for HTTP status or directory scanning")
                parser.add_argument('--status', help="Comma-separated status codes for directory scanning (e.g., 200,301)")
                parser.add_argument('--url', help="Single URL for directory scanning (e.g., https://xyz.com)")
                parser.add_argument('-w', '--subdomain-wordlist', help="Wordlist file for subdomain enumeration")
                parser.add_argument('--dir-wordlist', help="Wordlist file for directory scanning")
                parser.add_argument('--token', help="GitHub Personal Access Token")
                parser.add_argument('--limit-commits', type=int, default=50, help="Max commits to scan per repo")
                parser.add_argument('--skip-forks', action='store_true', help="Skip forked repositories")
                parser.add_argument('-t', '--timeout', type=int, default=10, help="Request timeout in seconds")
                parser.add_argument('-c', '--concurrency', type=int, default=50, help="Maximum concurrent requests")
                parser.add_argument('-r', '--retries', type=int, default=3, help="Number of retries for failed requests")
                parser.add_argument('--depth', type=int, default=5, help="Maximum crawling depth for directory scanning (1-10)")
                parser.add_argument('--silent', action='store_true', help="Run in silent mode (only show main status messages)")

                args = parser.parse_args(args_list)
            except Exception as e:
                print(colored(f"Error parsing command: {e}", "red"))
                return

        if args.silent:
            logging.basicConfig(level=logging.CRITICAL)
            self.silent = True
        else:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
            self.silent = False

        self.subdomain_scanner = SubdomainScanner(args.timeout, args.subdomain_wordlist, args.concurrency, args.retries, args.silent)
        self.http_checker = HTTPStatusChecker(args.timeout, args.concurrency, args.silent)
        self.dir_scanner = DirectoryScanner(args.timeout, args.concurrency, args.depth, args.silent)
        self.email_searcher = EmailSearcher(args.timeout, args.silent)

        if args.email_domain or args.email_username:
            self.run_email_search(args)
        elif args.domain:
            self.run_subdomain_scan(args)
        elif args.input and args.output and not args.status and not args.url:
            self.run_http_check(args)
        elif args.input or args.url:
            self.run_directory_scan(args)
        else:
            print(colored("Error: Invalid command. Please provide appropriate arguments.", "red"))
            self.display_example_commands()

    def display_example_commands(self):
        """Display example commands for each task."""
        print(colored("Example commands:", "yellow"))
        print(
            colored("  Subdomain Enumeration: ", "light_green") +
            colored("python3 rek-beta.py ", "green") +
            colored("-d", "cyan") + " xyz.com " +
            colored("-w", "cyan") + " subdomains.txt " +
            colored("-t", "cyan") + " 15 " +
            colored("-c", "cyan") + " 100 " +
            colored("--token", "cyan") + " ghp_xxx " +
            colored("--limit-commits", "cyan") + " 50 " +
            colored("--skip-forks", "cyan") + " "
        )
        print(
            colored("  HTTP Status Checking: ", "light_green") +
            colored("python3 rek-beta.py ", "green") +
            colored("--input", "cyan") + " results.txt " +
            colored("-o", "cyan") + " http_results.csv " +
            colored("-t", "cyan") + " 15 " +
            colored("-c", "cyan") + " 100"
        )
        print(
            colored("  Directory Scanning: ", "light_green") +
            colored("python3 rek-beta.py ", "green") +
            colored("--input", "cyan") + " http_results.csv " +
            colored("--status", "cyan") + " 200,301 " +
            colored("--dir-wordlist", "cyan") + " common.txt " +
            colored("-t", "cyan") + " 15 " +
            colored("-c", "cyan") + " 100 " +
            colored("--depth", "cyan") + " 5"
        )
        print(
            colored("  Email Search: ", "light_green") +
            colored("python3 rek-beta.py ", "green") +
            colored("--email-domain", "cyan") + " xyz.com " +
            colored("-o", "cyan") + " email_results.csv " +
            colored("--token", "cyan") + " ghp_xxx " +
            colored("--limit-commits", "cyan") + " 50 " +
            colored("--skip-forks", "cyan") + " "
        )

    def run_subdomain_scan(self, args=None):
        """Run subdomain enumeration with optional email search."""
        if not args:
            args = self.args
        if not args.domain:
            print(colored("Error: Domain is required for subdomain enumeration (use -d/--domain)", "red"))
            return
        if not self.silent:
            print(colored(f"Running Subdomain Enumeration for {args.domain}...", "green"))
        asyncio.run(self.subdomain_scanner.enumerate_subdomains(
            args.domain,
            args.output or "results.txt",
            args.token,
            args.limit_commits,
            args.skip_forks
        ))
        # Run email search if domain is provided
        email_output = f"{os.path.splitext(args.output or 'results.txt')[0]}_emails.csv"
        if not self.silent:
            print(colored(f"Running Email Search for domain: {args.domain}...", "green"))
        self.email_searcher.run(
            domain=args.domain,
            username=None,
            token=args.token,
            output_file=email_output,
            max_commits=args.limit_commits,
            skip_forks=args.skip_forks,
            hibp_key=args.hibp_key
        )
        if not self.silent:
            print(colored("Finished Subdomain Enumeration and Email Search.", "green"))

    def run_http_check(self, args=None):
        """Run HTTP status checking."""
        if not args:
            args = self.args
        if not args.input:
            print(colored("Error: Input file is required for HTTP status checking (use --input)", "red"))
            return
        self.http_checker.run(args.input, args.output or "http_results.csv")

    def run_directory_scan(self, args=None):
        """Run directory scanning."""
        if not args:
            args = self.args
        if args.status and not args.input:
            args.input = self.default_input_file
            if not self.silent:
                print(colored(f"No input file specified. Using default: {args.input}", "yellow"))
        if not (args.status or args.url):
            print(colored("Error: Must provide either status codes with input file or a URL", "red"))
            return
        if args.status:
            try:
                status_codes = [int(code.strip()) for code in args.status.split(',')]
            except ValueError:
                print(colored("Error: --status must be comma-separated integers (e.g., 200,301)", "red"))
                return
        else:
            status_codes = None
        self.dir_scanner.run(args.input, status_codes, args.url, args.dir_wordlist)

    def run_email_search(self, args=None):
        """Run email search."""
        if not args:
            args = self.args
        if not (args.email_domain or args.email_username or args.org):
            print(colored("Error: Must provide either --email-domain, --email-username, or --org", "red"))
            return
        if not self.silent:
            target = args.email_domain or args.email_username or args.org
            target_type = "domain" if args.email_domain else "username" if args.email_username else "organization"
            print(colored(f"Running Email Search for {target_type}: {target}...", "green"))
        username = args.org or args.email_username
        self.email_searcher.run(
            domain=args.email_domain,
            username=username,
            # org=args.org,
            token=args.token,
            output_file=args.output or "email_results.csv",
            max_commits=args.limit_commits,
            skip_forks=args.skip_forks,
            hibp_key=args.hibp_key
        )
        if not self.silent:
            print(colored("Finished Email Search.", "green"))

    def run(self):
        """Run the recon tool based on arguments or interactively."""
        self.display_banner()

        if self.has_valid_args():
            task = self.identify_task()
            if task == "subdomain":
                self.run_subdomain_scan()
            elif task == "http":
                self.run_http_check()
            elif task == "directory":
                self.run_directory_scan()
            elif task == "email":
                self.run_email_search()
            return

        while True:
            choice = self.display_rek_menu()
            if choice == '1':
                self.run_playbook()
            elif choice == '2':
                args = self.prompt_subdomain_args()
                self.run_subdomain_scan(args)
            elif choice == '3':
                args = self.prompt_http_args()
                self.run_http_check(args)
            elif choice == '4':
                args = self.prompt_directory_args()
                self.run_directory_scan(args)
            elif choice == '5':
                while True:
                    email_choice = self.display_email_menu(show_examples=True)
                    if email_choice == '1':
                        args = self.prompt_email_args(by_domain=True)
                        self.run_email_search(args)
                    elif email_choice == '2':
                        args = self.prompt_email_args(by_domain=False)
                        self.run_email_search(args)
                    elif email_choice == '3':
                        break
                    else:
                        print(colored("Invalid option. Please select 1-3.", "red"))
            elif choice == '6':
                self.wordlist_generator.run_interactive()
            elif choice == '7':
                print(colored("Exiting REK. Stay ethical!", "cyan"))
                break
            else:
                print(colored("Invalid option. Please select 1-7.", "red"))

def print_help():
    """Print detailed help information for REK tool."""
    help_text = """
REK - Reconnaissance Toolkit

USAGE:
    python3 rek.py [OPTIONS]

MENU OPTIONS:
    1. Run Recon Playbook    - Execute automated reconnaissance playbooks
    2. Subdomain Enumeration - Discover subdomains using multiple techniques
    3. HTTP Status Checking  - Check HTTP status of discovered domains
    4. Directory Scanning    - Scan for directories and files on web servers
    5. REK Email Search      - Search for email addresses in GitHub repositories
    6. REK Wordlist Generator- Generate and download wordlists for testing
    7. Exit                  - Exit the application

COMMAND LINE OPTIONS:

Subdomain Enumeration:
    -d, --domain DOMAIN         Target domain (e.g., example.com)
    -w, --subdomain-wordlist    Custom wordlist for subdomain enumeration
    -o, --output FILE          Output file (default: results.txt)
    --token TOKEN              GitHub Personal Access Token
    --limit-commits N          Max commits to scan per repo (default: 50)
    --skip-forks              Skip forked repositories
    -t, --timeout N           Request timeout in seconds (default: 10)
    -c, --concurrency N       Maximum concurrent requests (default: 50)
    -r, --retries N           Number of retries for failed requests (default: 3)

HTTP Status Checking:
    --input FILE              Input file with URLs to check
    -o, --output FILE         Output CSV file (default: http_results.csv)
    -t, --timeout N           Request timeout in seconds (default: 10)
    -c, --concurrency N       Maximum concurrent requests (default: 50)

Directory Scanning:
    --input FILE              Input CSV file with URLs
    --status CODES            Comma-separated status codes (e.g., 200,301,403)
    --url URL                 Single URL to scan (alternative to --input)
    --dir-wordlist FILE       Custom wordlist for directory scanning
    --depth N                 Maximum crawling depth (1-10, default: 5)
    -t, --timeout N           Request timeout in seconds (default: 10)
    -c, --concurrency N       Maximum concurrent requests (default: 50)

Email Search:
    --email-domain DOMAIN     Domain for email search
    --email-username USER     GitHub username for email search
    --org ORGANIZATION        GitHub organization for email search
    --token TOKEN             GitHub Personal Access Token
    --hibp-key KEY            Have I Been Pwned API key
    --limit-commits N         Max commits to scan per repo (default: 50)
    --skip-forks              Skip forked repositories
    -o, --output FILE         Output CSV file (default: email_results.csv)

General Options:
    --silent                  Run in silent mode (minimal output)
    -h, --help               Show this help message

EXAMPLES:
    # Interactive mode
    python3 rek.py

    # Subdomain enumeration
    python3 rek.py -d example.com -w wordlists/subdomains.txt --token ghp_xxx

    # HTTP status checking
    python3 rek.py --input results.txt -o http_results.csv -t 15 -c 100

    # Directory scanning
    python3 rek.py --input http_results.csv --status 200,301,403 --depth 3

    # Email search by domain
    python3 rek.py --email-domain example.com --token ghp_xxx --hibp-key xxx

    # Email search by organization
    python3 rek.py --org microsoft --token ghp_xxx --limit-commits 100

For more information, visit: https://github.com/your-repo/rek-toolkit
"""
    print(help_text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="rek - Recon Tool for bug bounty hunting", add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help="Show detailed help message")
    parser.add_argument('-d', '--domain', help="Domain for subdomain enumeration (e.g., xyz.com)")
    parser.add_argument('--email-domain', help="Domain for email search (e.g., xyz.com)")
    parser.add_argument('--email-username', help="GitHub username for email search (e.g., exampleuser)")
    parser.add_argument('--org', help="GitHub organization for email search (e.g., exampleorg)")
    parser.add_argument('-o', '--output', help="Output file for results (default: results.txt, http_results.csv, or email_results.csv)")
    parser.add_argument('--input', help="Input file with URLs for HTTP status or directory scanning")
    parser.add_argument('--status', help="Comma-separated status codes for directory scanning (e.g., 200,301)")
    parser.add_argument('--url', help="Single URL for directory scanning (e.g., https://xyz.com)")
    parser.add_argument('-w', '--subdomain-wordlist', help="Wordlist file for subdomain enumeration")
    parser.add_argument('--dir-wordlist', help="Wordlist file for directory scanning")
    parser.add_argument('--token', help="GitHub Personal Access Token")
    parser.add_argument('--hibp-key', help="HIBP API key for breach checks")
    parser.add_argument('--limit-commits', type=int, default=50, help="Max commits to scan per repo")
    parser.add_argument('--skip-forks', action='store_true', help="Skip forked repositories")
    parser.add_argument('-t', '--timeout', type=int, default=10, help="Request timeout in seconds")
    parser.add_argument('-c', '--concurrency', type=int, default=50, help="Maximum concurrent requests")
    parser.add_argument('-r', '--retries', type=int, default=3, help="Number of retries for failed requests")
    parser.add_argument('--depth', type=int, default=5, help="Maximum crawling depth for directory scanning (1-10)")
    parser.add_argument('--silent', action='store_true', help="Run in silent mode (only show main status messages)")

    args = parser.parse_args()

    if args.help:
        print_help()
        sys.exit(0)

    recon_tool = ReconTool(args)
    recon_tool.run()