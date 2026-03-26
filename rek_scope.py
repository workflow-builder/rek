"""
REK Scope Manager
Handles in-scope and out-of-scope targets for bug bounty programs.
Supports: CIDR ranges, wildcard domains, exact domains, regex patterns.
Integrates with all REK modules to filter targets.
"""
import ipaddress
import re
import json
import os
import csv
from typing import List, Set, Optional, Dict
from urllib.parse import urlparse
from termcolor import colored
import logging

logger = logging.getLogger(__name__)

DEFAULT_SCOPE_FILE = 'scope.txt'


class ScopeManager:
    def __init__(self, scope_file: str = None, out_of_scope_file: str = None, silent: bool = False):
        self.silent = silent
        self.in_scope: List[str] = []
        self.out_of_scope: List[str] = []
        self._compiled_in: List = []
        self._compiled_out: List = []
        self._in_cidrs: List = []
        self._out_cidrs: List = []

        if scope_file and os.path.exists(scope_file):
            self.load_scope_file(scope_file, is_in_scope=True)
        if out_of_scope_file and os.path.exists(out_of_scope_file):
            self.load_scope_file(out_of_scope_file, is_in_scope=False)

    def load_scope_file(self, filepath: str, is_in_scope: bool = True):
        """Load scope from a file. Supports plain text, JSON (HackerOne/Bugcrowd format)."""
        try:
            with open(filepath) as f:
                content = f.read()

            # Try JSON format first (HackerOne program export)
            try:
                data = json.loads(content)
                entries = []
                # HackerOne format
                if 'targets' in data:
                    for scope in data.get('targets', {}).get('in_scope', []):
                        entries.append(scope.get('target', ''))
                elif isinstance(data, list):
                    entries = [str(item) for item in data]

                for entry in entries:
                    if entry:
                        if is_in_scope:
                            self.in_scope.append(entry)
                        else:
                            self.out_of_scope.append(entry)

                if not self.silent:
                    scope_type = 'in-scope' if is_in_scope else 'out-of-scope'
                    print(colored(f"[✓] Loaded {len(entries)} {scope_type} entries from {filepath} (JSON)", "green"))
                self._compile()
                return
            except (json.JSONDecodeError, KeyError):
                pass

            # Plain text format: one entry per line
            count = 0
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if is_in_scope:
                    self.in_scope.append(line)
                else:
                    self.out_of_scope.append(line)
                count += 1

            if not self.silent:
                scope_type = 'in-scope' if is_in_scope else 'out-of-scope'
                print(colored(f"[✓] Loaded {count} {scope_type} entries from {filepath}", "green"))

            self._compile()

        except Exception as e:
            print(colored(f"[!] Error loading scope file {filepath}: {e}", "red"))

    def add_scope(self, entry: str, in_scope: bool = True):
        """Add a scope entry."""
        if in_scope:
            self.in_scope.append(entry)
        else:
            self.out_of_scope.append(entry)
        self._compile()

    def _compile(self):
        """Compile scope entries into efficient matchers."""
        self._compiled_in = []
        self._compiled_out = []
        self._in_cidrs = []
        self._out_cidrs = []

        for entry_list, compiled_list, cidr_list in [
            (self.in_scope, self._compiled_in, self._in_cidrs),
            (self.out_of_scope, self._compiled_out, self._out_cidrs),
        ]:
            for entry in entry_list:
                entry = entry.strip().lstrip('*.')

                # CIDR notation
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    cidr_list.append(network)
                    continue
                except ValueError:
                    pass

                # URL - extract hostname
                if '://' in entry:
                    try:
                        entry = urlparse(entry).netloc or entry
                    except Exception:
                        pass

                # Wildcard domain: *.example.com -> regex
                if entry.startswith('*.'):
                    pattern = r'(?:.*\.)?' + re.escape(entry[2:]) + r'$'
                else:
                    pattern = r'^' + re.escape(entry) + r'$'

                try:
                    compiled_list.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    pass

    def _match_domain(self, domain: str, compiled_list: List, cidr_list: List) -> bool:
        """Check if a domain/IP matches against compiled patterns and CIDRs."""
        domain = domain.strip().lower()

        # Strip scheme/port if present
        if '://' in domain:
            try:
                domain = urlparse(domain).hostname or domain
            except Exception:
                pass
        domain = domain.split(':')[0]  # Remove port

        # Check IP/CIDR
        try:
            ip = ipaddress.ip_address(domain)
            for network in cidr_list:
                if ip in network:
                    return True
        except ValueError:
            pass

        # Check domain patterns
        for pattern in compiled_list:
            if pattern.search(domain):
                return True

        return False

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is in scope."""
        # If no scope defined, everything is in scope
        if not self.in_scope and not self.out_of_scope:
            return True

        # Check out-of-scope first
        if self._compiled_out or self._out_cidrs:
            if self._match_domain(target, self._compiled_out, self._out_cidrs):
                return False

        # If in-scope defined, check it
        if self._compiled_in or self._in_cidrs:
            return self._match_domain(target, self._compiled_in, self._in_cidrs)

        # No in-scope defined but out-of-scope defined: everything not excluded is in scope
        return True

    def filter(self, targets: List[str]) -> List[str]:
        """Filter a list of targets to only include in-scope ones."""
        if not self.in_scope and not self.out_of_scope:
            return targets

        filtered = [t for t in targets if self.is_in_scope(t)]
        excluded = len(targets) - len(filtered)

        if excluded > 0 and not self.silent:
            print(colored(f"[*] Scope filter: {len(filtered)}/{len(targets)} targets in scope ({excluded} excluded)", "yellow"))

        return filtered

    def save_scope_file(self, filepath: str, in_scope: bool = True):
        """Save current scope to a file."""
        entries = self.in_scope if in_scope else self.out_of_scope
        with open(filepath, 'w') as f:
            scope_type = 'In-Scope' if in_scope else 'Out-of-Scope'
            f.write(f"# REK {scope_type} Targets\n")
            f.write("# Supports: domains, *.wildcard.com, IP CIDRs, URLs\n\n")
            for entry in entries:
                f.write(entry + '\n')
        if not self.silent:
            print(colored(f"[✓] Scope saved to {filepath}", "green"))

    def display_scope(self):
        """Display current scope configuration."""
        print(colored("\n[*] Current Scope Configuration:", "cyan"))
        print(colored(f"  In-Scope ({len(self.in_scope)} entries):", "green"))
        for entry in self.in_scope[:20]:
            print(colored(f"    + {entry}", "green"))
        if len(self.in_scope) > 20:
            print(colored(f"    ... and {len(self.in_scope) - 20} more", "green"))

        print(colored(f"\n  Out-of-Scope ({len(self.out_of_scope)} entries):", "red"))
        for entry in self.out_of_scope[:20]:
            print(colored(f"    - {entry}", "red"))
        if len(self.out_of_scope) > 20:
            print(colored(f"    ... and {len(self.out_of_scope) - 20} more", "red"))

    def interactive_setup(self, domain: str = None):
        """Interactive scope setup."""
        print(colored("\n[*] REK Scope Setup", "cyan"))
        print(colored("Add in-scope targets (one per line, empty line to finish):", "yellow"))
        print(colored("Examples: *.example.com, example.com, 192.168.1.0/24", "cyan"))

        while True:
            entry = input(colored("  In-scope: ", "green")).strip()
            if not entry:
                break
            self.add_scope(entry, in_scope=True)

        print(colored("\nAdd out-of-scope targets (one per line, empty line to finish):", "yellow"))
        while True:
            entry = input(colored("  Out-of-scope: ", "red")).strip()
            if not entry:
                break
            self.add_scope(entry, in_scope=False)

        if self.in_scope or self.out_of_scope:
            save = input(colored("\nSave scope to file? (y/n): ", "yellow")).strip().lower()
            if save == 'y':
                filepath = input(colored("Filename (default: scope.txt): ", "yellow")).strip() or 'scope.txt'
                self.save_scope_file(filepath, in_scope=True)
                if self.out_of_scope:
                    oos_file = filepath.replace('.txt', '_oos.txt')
                    self.save_scope_file(oos_file, in_scope=False)

        self.display_scope()


if __name__ == '__main__':
    scope = ScopeManager()
    scope.interactive_setup()
