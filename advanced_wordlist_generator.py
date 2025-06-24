
import os
import sys
import requests
import time
from typing import List, Dict, Set
from termcolor import colored
import logging

# Configure logging
logger = logging.getLogger(__name__)

class AdvancedWordlistGenerator:
    def __init__(self, silent: bool = False):
        self.silent = silent
        self.seclists_base_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
        self.wordlists_dir = "wordlists"
        self.output_dir = "generated_wordlists"
        
        # Enhanced wordlist categories with more comprehensive lists
        self.wordlist_categories = {
            "subdomains": {
                "basic": [
                    "Discovery/DNS/subdomains-top1million-5000.txt",
                    "Discovery/DNS/subdomains-top1million-20000.txt",
                    "Discovery/DNS/dns-Jhaddix.txt",
                    "Discovery/DNS/fierce-hostlist.txt",
                    "Discovery/DNS/namelist.txt"
                ],
                "advanced": [
                    "Discovery/DNS/subdomains-top1million-110000.txt",
                    "Discovery/DNS/bitquark-subdomains-top100000.txt",
                    "Discovery/DNS/deepmagic.com-prefixes-top50000.txt"
                ]
            },
            "directories": {
                "basic": [
                    "Discovery/Web-Content/directory-list-2.3-medium.txt",
                    "Discovery/Web-Content/raft-medium-directories.txt",
                    "Discovery/Web-Content/common.txt",
                    "Discovery/Web-Content/quickhits.txt"
                ],
                "advanced": [
                    "Discovery/Web-Content/directory-list-2.3-big.txt",
                    "Discovery/Web-Content/raft-large-directories.txt",
                    "Discovery/Web-Content/Apache.fuzz.txt",
                    "Discovery/Web-Content/nginx.txt"
                ]
            },
            "files": {
                "basic": [
                    "Discovery/Web-Content/raft-medium-files.txt",
                    "Discovery/Web-Content/common-extensions.txt",
                    "Discovery/Web-Content/web-extensions.txt",
                    "Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt"
                ],
                "advanced": [
                    "Discovery/Web-Content/raft-large-files.txt",
                    "Discovery/Web-Content/CommonBackdoors-ASP.fuzz.txt",
                    "Discovery/Web-Content/CommonBackdoors-JSP.fuzz.txt"
                ]
            },
            "parameters": {
                "basic": [
                    "Discovery/Web-Content/burp-parameter-names.txt",
                    "Discovery/Web-Content/raft-medium-words.txt",
                    "Fuzzing/template-engines-special-vars.txt"
                ],
                "advanced": [
                    "Discovery/Web-Content/raft-large-words.txt",
                    "Fuzzing/special-chars.txt",
                    "Fuzzing/command-injection-commix.txt"
                ]
            },
            "vulnerabilities": {
                "xss": [
                    "Fuzzing/XSS/XSS-BruteLogic.txt",
                    "Fuzzing/XSS/XSS-Jhaddix.txt",
                    "Fuzzing/XSS/XSS-payload-list.txt"
                ],
                "sqli": [
                    "Fuzzing/SQLi/Generic-SQLi.txt",
                    "Fuzzing/SQLi/MySQL-SQLi-Login-Bypass.fuzz.txt",
                    "Fuzzing/SQLi/MSSQL-Enumeration.txt"
                ],
                "lfi": [
                    "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
                    "Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
                    "Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt"
                ],
                "rce": [
                    "Fuzzing/command-injection-commix.txt",
                    "Fuzzing/Unix-commands.fuzz.txt",
                    "Fuzzing/Windows-commands.fuzz.txt"
                ]
            },
            "api": {
                "endpoints": [
                    "Discovery/Web-Content/api/api-endpoints.txt",
                    "Discovery/Web-Content/api/objects.txt",
                    "Discovery/Web-Content/api/actions-lowercase.txt"
                ],
                "methods": [
                    "Discovery/Web-Content/api/api_methods.txt",
                    "Discovery/Web-Content/api/graphql.txt"
                ]
            }
        }
        
        # Technology-specific wordlists
        self.tech_specific = {
            "wordpress": [
                "wp-admin", "wp-content", "wp-includes", "wp-login.php", "wp-config.php",
                "xmlrpc.php", "wp-load.php", "wp-settings.php", "wp-blog-header.php",
                "wp-cron.php", "wp-links-opml.php", "wp-mail.php", "wp-signup.php",
                "wp-trackback.php", "wp-activate.php", "wp-comments-post.php"
            ],
            "drupal": [
                "sites/default", "modules", "themes", "core", "install.php", "settings.php",
                "cron.php", "index.php", "update.php", "authorize.php", "web.config",
                "sites/all", "profiles", "libraries", "vendor"
            ],
            "joomla": [
                "administrator", "components", "modules", "templates", "plugins",
                "libraries", "cache", "logs", "tmp", "configuration.php",
                "htaccess.txt", "web.config.txt", "LICENSE.txt", "README.txt"
            ],
            "laravel": [
                ".env", "artisan", "storage", "vendor", "bootstrap", "routes",
                "config", "database", "resources", "public", "tests",
                "composer.json", "composer.lock", "package.json", "webpack.mix.js"
            ],
            "django": [
                "admin", "static", "media", "templates", "locale", "fixtures",
                "manage.py", "settings.py", "urls.py", "wsgi.py", "asgi.py",
                "requirements.txt", "runtime.txt", "Procfile"
            ],
            "nodejs": [
                "node_modules", "package.json", "package-lock.json", "server.js",
                "app.js", "index.js", "config", "routes", "middleware", "models",
                "views", "public", "static", "uploads", "logs", ".env"
            ],
            "php": [
                "index.php", "config.php", "admin.php", "login.php", "register.php",
                "upload.php", "search.php", "contact.php", "about.php", "phpinfo.php",
                "test.php", "info.php", "setup.php", "install.php", "upgrade.php"
            ],
            "apache": [
                ".htaccess", "server-status", "server-info", "access_log", "error_log",
                "httpd.conf", "apache2.conf", ".htpasswd", "robots.txt", "sitemap.xml"
            ],
            "nginx": [
                "nginx.conf", "sites-available", "sites-enabled", "nginx_status",
                "stub_status", "access.log", "error.log", "mime.types"
            ],
            "iis": [
                "web.config", "global.asax", "bin", "app_data", "app_code",
                "app_themes", "app_webreferences", "app_browsers", "aspnet_client"
            ]
        }

    def create_directories(self):
        """Create necessary directories."""
        try:
            os.makedirs(self.wordlists_dir, exist_ok=True)
            os.makedirs(self.output_dir, exist_ok=True)
            if not self.silent:
                logger.info(colored(f"Created directories: {self.wordlists_dir}, {self.output_dir}", "green"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error creating directories: {e}", "red"))

    def download_wordlist(self, url: str, filename: str, category: str = "") -> bool:
        """Download a wordlist from URL."""
        try:
            if not self.silent:
                category_prefix = f"[{category}] " if category else ""
                logger.info(colored(f"{category_prefix}Downloading {filename}...", "yellow"))
            
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            filepath = os.path.join(self.wordlists_dir, filename)
            with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(response.text)
            
            if not self.silent:
                lines = len(response.text.splitlines())
                logger.info(colored(f"Downloaded {filename} ({lines} entries)", "green"))
            return True
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Failed to download {filename}: {e}", "red"))
            return False

    def generate_domain_specific_wordlist(self, domain: str, wordlist_type: str = "comprehensive") -> str:
        """Generate comprehensive domain-specific wordlist."""
        domain_clean = domain.replace('.', '-').replace('_', '-')
        output_filename = f"custom-{wordlist_type}-{domain_clean}.txt"
        output_filepath = os.path.join(self.output_dir, output_filename)
        
        try:
            # Base wordlists for different types
            base_wordlists = {
                "subdomains": [
                    'www', 'api', 'app', 'blog', 'dev', 'staging', 'test', 'mail', 'admin',
                    'login', 'dashboard', 'secure', 'portal', 'vpn', 'ftp', 'support', 'shop',
                    'store', 'news', 'events', 'forum', 'community', 'docs', 'help', 'status',
                    'beta', 'demo', 'internal', 'old', 'new', 'web', 'mobile', 'cloud', 'data',
                    'auth', 'oauth', 'sso', 'my', 'user', 'account', 'profile', 'settings',
                    'signup', 'gateway', 'proxy', 'cdn', 'cache', 'backup', 'db', 'database',
                    'sql', 'mysql', 'mongo', 'redis', 'elastic', 'search', 'log', 'logs',
                    'monitor', 'metrics', 'health', 'ping', 'service', 'services', 'micro',
                    'static', 'assets', 'media', 'images', 'uploads', 'files', 'download',
                    'private', 'public', 'external', 'internal', 'local', 'remote', 'client',
                    'server', 'host', 'node', 'worker', 'job', 'queue', 'task', 'cron'
                ],
                "directories": [
                    'admin', 'login', 'dashboard', 'api', 'config', 'backup', 'test', 'dev',
                    'staging', '.env', 'config.php', 'wp-admin', 'wp-content', 'sites/default',
                    'admin/login', 'api/v1', 'api/v2', 'graphql', 'rest', 'static', 'media',
                    'uploads', '.git', '.svn', 'debug', 'trace', 'swagger', 'docs', 'robots.txt',
                    'sitemap.xml', 'web.config', 'cache', 'logs', 'tmp', 'temp', 'assets',
                    'js', 'css', 'images', 'fonts', 'vendor', 'src', 'dist', 'build', 'public',
                    'private', 'secret', 'hidden', 'internal', 'external', 'backup', 'old',
                    'new', 'archive', 'data', 'database', 'db', 'sql', 'mysql', 'mongo'
                ],
                "files": [
                    'index', 'home', 'main', 'default', 'login', 'admin', 'config', 'settings',
                    'setup', 'install', 'upgrade', 'migrate', 'backup', 'restore', 'export',
                    'import', 'download', 'upload', 'search', 'profile', 'account', 'user',
                    'users', 'member', 'members', 'client', 'clients', 'customer', 'customers',
                    'order', 'orders', 'product', 'products', 'service', 'services', 'contact',
                    'about', 'help', 'support', 'faq', 'terms', 'privacy', 'policy', 'legal'
                ]
            }
            
            # Domain parts for permutations
            domain_parts = domain.replace('.', '-').replace('_', '-').split('-')
            domain_parts = [part for part in domain_parts if len(part) > 2 and part.isalpha()]
            
            # Start with base wordlist
            if wordlist_type in base_wordlists:
                wordlist = set(base_wordlists[wordlist_type])
            else:
                wordlist = set(base_wordlists["subdomains"] + base_wordlists["directories"])
            
            # Add domain-specific permutations
            for part in domain_parts:
                part_lower = part.lower()
                # Add the part itself
                wordlist.add(part_lower)
                
                # Combine with base words
                for base_word in base_wordlists.get(wordlist_type, base_wordlists["subdomains"])[:30]:
                    wordlist.add(f"{part_lower}-{base_word}")
                    wordlist.add(f"{base_word}-{part_lower}")
                    wordlist.add(f"{part_lower}{base_word}")
                    wordlist.add(f"{base_word}{part_lower}")
                    wordlist.add(f"{part_lower}_{base_word}")
                    wordlist.add(f"{base_word}_{part_lower}")
                
                # Add numbered variations
                for i in range(1, 10):
                    wordlist.add(f"{part_lower}{i}")
                    wordlist.add(f"{part_lower}-{i}")
                    wordlist.add(f"{part_lower}_{i}")
                
                # Add common prefixes and suffixes
                prefixes = ['old', 'new', 'dev', 'test', 'beta', 'alpha', 'staging', 'prod']
                suffixes = ['old', 'new', 'bak', 'tmp', 'test', 'dev', 'prod', 'live']
                
                for prefix in prefixes:
                    wordlist.add(f"{prefix}-{part_lower}")
                    wordlist.add(f"{prefix}{part_lower}")
                
                for suffix in suffixes:
                    wordlist.add(f"{part_lower}-{suffix}")
                    wordlist.add(f"{part_lower}{suffix}")
            
            # Add technology-specific words if detected
            for tech, tech_words in self.tech_specific.items():
                if tech in domain.lower() or any(tech in part.lower() for part in domain_parts):
                    wordlist.update(tech_words)
            
            # Write to file
            with open(output_filepath, 'w') as f:
                for word in sorted(wordlist):
                    f.write(f"{word}\n")
            
            if not self.silent:
                logger.info(colored(f"Generated {output_filename} with {len(wordlist)} entries", "green"))
            
            return output_filepath
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error generating domain-specific wordlist: {e}", "red"))
            return ""

    def merge_wordlists(self, wordlist_files: List[str], output_name: str) -> str:
        """Merge multiple wordlists into one, removing duplicates."""
        try:
            merged_words = set()
            valid_files = []
            
            for wordlist_file in wordlist_files:
                filepath = os.path.join(self.wordlists_dir, wordlist_file)
                if os.path.exists(filepath):
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        words = [line.strip() for line in f if line.strip()]
                        merged_words.update(words)
                        valid_files.append(wordlist_file)
                else:
                    if not self.silent:
                        logger.warning(colored(f"File not found: {wordlist_file}", "yellow"))
            
            if not merged_words:
                if not self.silent:
                    logger.error(colored("No valid wordlists found to merge", "red"))
                return ""
            
            output_filepath = os.path.join(self.output_dir, f"merged-{output_name}.txt")
            with open(output_filepath, 'w') as f:
                for word in sorted(merged_words):
                    f.write(f"{word}\n")
            
            if not self.silent:
                logger.info(colored(f"Merged {len(valid_files)} wordlists into {output_name} ({len(merged_words)} unique entries)", "green"))
            
            return output_filepath
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error merging wordlists: {e}", "red"))
            return ""

    def run_interactive(self):
        """Run the interactive wordlist generator."""
        if not self.silent:
            print(colored("\n🔧 Advanced REK Wordlist Generator", "cyan", attrs=["bold"]))
            print(colored("Generate comprehensive wordlists for reconnaissance", "cyan"))
        
        self.create_directories()
        
        while True:
            print(colored("\n" + "="*60, "blue"))
            print(colored("Wordlist Generator Options:", "cyan", attrs=["bold"]))
            print(colored("1. 📥 Download SecLists wordlists", "green"))
            print(colored("2. 🎯 Generate domain-specific wordlist", "green"))
            print(colored("3. 🔗 Merge existing wordlists", "green"))
            print(colored("4. 📋 List available wordlists", "green"))
            print(colored("5. 🧹 Clean old wordlists", "green"))
            print(colored("6. 🚪 Exit", "red"))
            print(colored("="*60, "blue"))
            
            choice = input(colored("Select an option (1-6): ", "yellow")).strip()
            
            if choice == '1':
                self.download_seclists_interactive()
            elif choice == '2':
                self.generate_domain_specific_interactive()
            elif choice == '3':
                self.merge_wordlists_interactive()
            elif choice == '4':
                self.list_wordlists_interactive()
            elif choice == '5':
                self.clean_wordlists_interactive()
            elif choice == '6':
                if not self.silent:
                    print(colored("Exiting Advanced Wordlist Generator", "cyan"))
                break
            else:
                print(colored("Invalid choice. Please select 1-6.", "red"))

    def download_seclists_interactive(self):
        """Interactive SecLists download."""
        print(colored("\n📥 SecLists Wordlist Categories:", "cyan", attrs=["bold"]))
        
        categories = list(self.wordlist_categories.keys())
        for i, category in enumerate(categories, 1):
            print(colored(f"{i:2d}. {category.title()}", "green"))
        print(colored(f"{len(categories) + 1:2d}. All categories", "yellow"))
        
        try:
            choice = input(colored("Select category: ", "yellow")).strip()
            
            if choice == str(len(categories) + 1):
                selected_categories = categories
            else:
                choice_num = int(choice)
                if 1 <= choice_num <= len(categories):
                    selected_categories = [categories[choice_num - 1]]
                else:
                    print(colored("Invalid choice", "red"))
                    return
            
            for category in selected_categories:
                print(colored(f"\n📂 Downloading {category.title()} wordlists...", "yellow"))
                
                # Download from all subcategories
                for subcategory, wordlist_paths in self.wordlist_categories[category].items():
                    for wordlist_path in wordlist_paths:
                        url = f"{self.seclists_base_url}/{wordlist_path}"
                        filename = f"{category}-{subcategory}-{os.path.basename(wordlist_path)}"
                        self.download_wordlist(url, filename, f"{category}/{subcategory}")
                        time.sleep(0.5)  # Be respectful to GitHub
            
            if not self.silent:
                print(colored("\n✅ Download process completed!", "green"))
                
        except ValueError:
            print(colored("Invalid input. Please enter a number.", "red"))
        except KeyboardInterrupt:
            print(colored("\nDownload interrupted by user", "yellow"))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error in download process: {e}", "red"))

    def generate_domain_specific_interactive(self):
        """Interactive domain-specific wordlist generation."""
        print(colored("\n🎯 Domain-Specific Wordlist Generation", "cyan", attrs=["bold"]))
        
        domain = input(colored("Enter domain name (e.g., example.com): ", "yellow")).strip()
        if not domain:
            print(colored("Domain name is required", "red"))
            return
        
        print(colored("\nWordlist Types:", "cyan"))
        types = ["subdomains", "directories", "files", "comprehensive"]
        for i, wtype in enumerate(types, 1):
            print(colored(f"{i}. {wtype.title()}", "green"))
        
        try:
            choice = int(input(colored("Select type (1-4): ", "yellow")).strip())
            if 1 <= choice <= len(types):
                wordlist_type = types[choice - 1]
            else:
                print(colored("Invalid choice", "red"))
                return
            
            filepath = self.generate_domain_specific_wordlist(domain, wordlist_type)
            
            if filepath:
                print(colored(f"✅ Custom wordlist generated: {filepath}", "green"))
                
                # Ask if user wants to preview
                preview = input(colored("Preview first 20 entries? (y/n): ", "yellow")).strip().lower()
                if preview == 'y':
                    try:
                        with open(filepath, 'r') as f:
                            lines = f.readlines()[:20]
                        print(colored("\n📋 Preview:", "cyan"))
                        for i, line in enumerate(lines, 1):
                            print(colored(f"{i:2d}. {line.strip()}", "white"))
                        if len(lines) == 20:
                            print(colored("... (showing first 20 entries)", "yellow"))
                    except Exception as e:
                        print(colored(f"Error reading preview: {e}", "red"))
            
        except ValueError:
            print(colored("Invalid input. Please enter a number.", "red"))

    def merge_wordlists_interactive(self):
        """Interactive wordlist merging."""
        print(colored("\n🔗 Merge Wordlists", "cyan", attrs=["bold"]))
        
        available_wordlists = self.list_available_wordlists()
        if not available_wordlists:
            print(colored("No wordlists available for merging", "yellow"))
            return
        
        print(colored("Available wordlists:", "cyan"))
        for i, wordlist in enumerate(available_wordlists, 1):
            print(colored(f"{i:2d}. {wordlist}", "green"))
        
        print(colored("\nEnter wordlist numbers to merge (comma-separated, e.g., 1,3,5):", "yellow"))
        selection = input(colored("Selection: ", "yellow")).strip()
        
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            selected_wordlists = [available_wordlists[i] for i in indices if 0 <= i < len(available_wordlists)]
            
            if not selected_wordlists:
                print(colored("No valid wordlists selected", "red"))
                return
            
            output_name = input(colored("Enter output name (without .txt): ", "yellow")).strip()
            if not output_name:
                output_name = f"merged-{int(time.time())}"
            
            filepath = self.merge_wordlists(selected_wordlists, output_name)
            if filepath:
                print(colored(f"✅ Merged wordlist created: {filepath}", "green"))
                
        except (ValueError, IndexError):
            print(colored("Invalid selection format", "red"))

    def list_available_wordlists(self) -> List[str]:
        """List all available wordlists."""
        try:
            wordlists = []
            for directory in [self.wordlists_dir, self.output_dir]:
                if os.path.exists(directory):
                    files = [f for f in os.listdir(directory) if f.endswith('.txt')]
                    wordlists.extend(files)
            return sorted(list(set(wordlists)))
        except Exception as e:
            if not self.silent:
                logger.error(colored(f"Error listing wordlists: {e}", "red"))
            return []

    def list_wordlists_interactive(self):
        """Interactive wordlist listing."""
        print(colored("\n📋 Available Wordlists", "cyan", attrs=["bold"]))
        
        wordlists = self.list_available_wordlists()
        if not wordlists:
            print(colored("No wordlists found", "yellow"))
            return
        
        print(colored(f"Found {len(wordlists)} wordlists:", "cyan"))
        
        for i, wordlist in enumerate(wordlists, 1):
            # Check in both directories
            filepath1 = os.path.join(self.wordlists_dir, wordlist)
            filepath2 = os.path.join(self.output_dir, wordlist)
            
            filepath = filepath1 if os.path.exists(filepath1) else filepath2
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = sum(1 for _ in f)
                size = os.path.getsize(filepath)
                size_str = f"{size/1024:.1f}KB" if size < 1024*1024 else f"{size/(1024*1024):.1f}MB"
                
                location = "downloaded" if filepath == filepath1 else "generated"
                print(colored(f"{i:2d}. {wordlist:<40} ({line_count:>8} entries, {size_str:>8}, {location})", "green"))
            except Exception:
                print(colored(f"{i:2d}. {wordlist:<40} (error reading file)", "yellow"))

    def clean_wordlists_interactive(self):
        """Interactive wordlist cleanup."""
        print(colored("\n🧹 Clean Wordlists", "cyan", attrs=["bold"]))
        
        print(colored("Cleanup options:", "cyan"))
        print(colored("1. Remove all downloaded wordlists", "yellow"))
        print(colored("2. Remove all generated wordlists", "yellow"))
        print(colored("3. Remove duplicate wordlists", "yellow"))
        print(colored("4. Remove empty wordlists", "yellow"))
        print(colored("5. Cancel", "green"))
        
        choice = input(colored("Select cleanup option (1-5): ", "yellow")).strip()
        
        if choice == '5':
            return
        
        # Confirm action
        confirm = input(colored("Are you sure? This action cannot be undone (y/N): ", "red")).strip().lower()
        if confirm != 'y':
            print(colored("Cleanup cancelled", "yellow"))
            return
        
        cleaned_count = 0
        
        try:
            if choice == '1':
                # Remove downloaded wordlists
                if os.path.exists(self.wordlists_dir):
                    for file in os.listdir(self.wordlists_dir):
                        if file.endswith('.txt'):
                            os.remove(os.path.join(self.wordlists_dir, file))
                            cleaned_count += 1
            
            elif choice == '2':
                # Remove generated wordlists
                if os.path.exists(self.output_dir):
                    for file in os.listdir(self.output_dir):
                        if file.endswith('.txt'):
                            os.remove(os.path.join(self.output_dir, file))
                            cleaned_count += 1
            
            elif choice == '3':
                # Remove duplicate wordlists (simplified approach)
                seen_sizes = {}
                for directory in [self.wordlists_dir, self.output_dir]:
                    if os.path.exists(directory):
                        for file in os.listdir(directory):
                            if file.endswith('.txt'):
                                filepath = os.path.join(directory, file)
                                size = os.path.getsize(filepath)
                                if size in seen_sizes:
                                    os.remove(filepath)
                                    cleaned_count += 1
                                else:
                                    seen_sizes[size] = filepath
            
            elif choice == '4':
                # Remove empty wordlists
                for directory in [self.wordlists_dir, self.output_dir]:
                    if os.path.exists(directory):
                        for file in os.listdir(directory):
                            if file.endswith('.txt'):
                                filepath = os.path.join(directory, file)
                                if os.path.getsize(filepath) == 0:
                                    os.remove(filepath)
                                    cleaned_count += 1
            
            print(colored(f"✅ Cleaned {cleaned_count} wordlists", "green"))
            
        except Exception as e:
            print(colored(f"Error during cleanup: {e}", "red"))

def main():
    """Main function for standalone execution."""
    print(colored("🔧 Advanced REK Wordlist Generator", "cyan", attrs=["bold"]))
    print(colored("Standalone wordlist generation tool", "cyan"))
    
    generator = AdvancedWordlistGenerator(silent=False)
    generator.run_interactive()

if __name__ == "__main__":
    main()
