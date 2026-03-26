"""
REK Parameter Discovery
Discovers hidden parameters on web endpoints via:
1. Wordlist-based GET/POST probing (Arjun-style reflection detection)
2. Passive extraction from page source, JS files, and existing URLs
"""
import asyncio
import httpx
import re
import csv
import os
import json
import random
import string
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from termcolor import colored
import logging

logger = logging.getLogger(__name__)

# Common parameter wordlist (condensed high-value list)
DEFAULT_PARAMS = [
    'id', 'user', 'username', 'email', 'name', 'search', 'q', 'query', 'page', 'limit',
    'offset', 'token', 'key', 'api_key', 'apikey', 'secret', 'password', 'pass', 'pwd',
    'file', 'path', 'url', 'redirect', 'next', 'return', 'returnUrl', 'callback',
    'lang', 'language', 'locale', 'format', 'type', 'mode', 'action', 'method',
    'debug', 'test', 'admin', 'role', 'group', 'category', 'tag', 'filter',
    'sort', 'order', 'dir', 'asc', 'desc', 'from', 'to', 'start', 'end', 'date',
    'year', 'month', 'day', 'time', 'timestamp', 'version', 'v', 'ref', 'source',
    'origin', 'dest', 'destination', 'target', 'host', 'domain', 'site', 'uri',
    'data', 'content', 'body', 'message', 'text', 'title', 'description', 'comment',
    'code', 'error', 'status', 'state', 'hash', 'checksum', 'signature', 'nonce',
    'csrf', 'csrf_token', '_token', '__RequestVerificationToken', 'access_token',
    'refresh_token', 'auth', 'authorization', 'bearer', 'session', 'sid', 'ssid',
    'include', 'exclude', 'show', 'hide', 'enable', 'disable', 'flag', 'option',
    'config', 'setting', 'pref', 'preference', 'theme', 'skin', 'color', 'size',
    'width', 'height', 'img', 'image', 'photo', 'avatar', 'icon', 'logo',
    'download', 'export', 'import', 'upload', 'output', 'input', 'field',
    'object', 'class', 'model', 'view', 'controller', 'service', 'module',
    'plugin', 'ext', 'extension', 'format', 'encoding', 'charset', 'currency',
    'amount', 'price', 'cost', 'quantity', 'count', 'total', 'sum', 'score',
    'level', 'rank', 'weight', 'priority', 'order_id', 'product_id', 'user_id',
    'account_id', 'customer_id', 'transaction_id', 'session_id', 'request_id',
    'invoice_id', 'payment_id', 'subscription_id', 'plan_id', 'project_id',
    'report_id', 'task_id', 'ticket_id', 'issue_id', 'bug_id', 'case_id',
    'uid', 'uuid', 'guid', 'oid', 'pid', 'fid', 'cid', 'gid', 'rid',
    'parent', 'child', 'parent_id', 'child_id', 'owner', 'owner_id',
    'created', 'updated', 'deleted', 'active', 'enabled', 'visible', 'public',
    'private', 'hidden', 'locked', 'archived', 'published', 'draft',
    'template', 'layout', 'component', 'widget', 'block', 'section', 'page_id',
]

def random_string(length: int = 8) -> str:
    """Generate a random alphanumeric string for reflection detection."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def extract_params_from_url(url: str) -> Set[str]:
    """Extract existing parameter names from a URL."""
    parsed = urlparse(url)
    return set(parse_qs(parsed.query).keys())

def extract_params_from_source(content: str) -> Set[str]:
    """Extract parameter names from HTML/JS source."""
    params = set()
    # HTML form inputs
    for match in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', content, re.IGNORECASE):
        params.add(match.group(1))
    # JS fetch/XMLHttpRequest parameters
    for match in re.finditer(r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']:\s*["\']', content):
        name = match.group(1)
        if len(name) > 2 and not name.startswith('_'):
            params.add(name)
    # URL query parameters in JS
    for match in re.finditer(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', content):
        params.add(match.group(1))
    # Common patterns like param: value, param=value
    for match in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]{2,30})\s*[=:]\s*["\']', content):
        name = match.group(1)
        if name.lower() not in ('function', 'return', 'class', 'var', 'let', 'const', 'import', 'export'):
            params.add(name)
    return params

class ParamDiscovery:
    def __init__(self, timeout: int = 10, concurrency: int = 20, silent: bool = False, wordlist_path: str = None):
        self.timeout = timeout
        self.concurrency = concurrency
        self.silent = silent
        self.wordlist_path = wordlist_path
        self.findings: List[Dict] = []

    def load_wordlist(self) -> List[str]:
        """Load parameter wordlist."""
        if self.wordlist_path and os.path.exists(self.wordlist_path):
            try:
                with open(self.wordlist_path) as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception:
                pass
        return DEFAULT_PARAMS

    async def probe_params_get(self, client: httpx.AsyncClient, url: str, params: List[str], semaphore: asyncio.Semaphore) -> List[str]:
        """Probe GET parameters via reflection detection."""
        async with semaphore:
            discovered = []
            # First get baseline response
            try:
                baseline = await client.get(url, timeout=self.timeout, follow_redirects=True)
                baseline_len = len(baseline.content)
                baseline_status = baseline.status_code
            except Exception:
                return []

            # Test params in batches of 20
            batch_size = 20
            for i in range(0, len(params), batch_size):
                batch = params[i:i + batch_size]
                # Create a unique marker for each param
                markers = {p: random_string(8) for p in batch}
                query = '&'.join(f"{p}={markers[p]}" for p in batch)
                test_url = f"{url}{'&' if '?' in url else '?'}{query}"

                try:
                    r = await client.get(test_url, timeout=self.timeout, follow_redirects=True)
                    response_text = r.text

                    # Check which markers appear in the response (reflected params)
                    for param, marker in markers.items():
                        if marker in response_text:
                            discovered.append(param)
                            if not self.silent:
                                print(colored(f"    [+] Reflected param: {param} @ {url}", "green"))
                except Exception:
                    pass

                await asyncio.sleep(0.1)

            return discovered

    async def probe_params_post(self, client: httpx.AsyncClient, url: str, params: List[str], semaphore: asyncio.Semaphore) -> List[str]:
        """Probe POST parameters."""
        async with semaphore:
            discovered = []
            batch_size = 20
            for i in range(0, len(params), batch_size):
                batch = params[i:i + batch_size]
                markers = {p: random_string(8) for p in batch}
                data = {p: markers[p] for p in batch}

                try:
                    r = await client.post(url, data=data, timeout=self.timeout, follow_redirects=True)
                    response_text = r.text
                    for param, marker in markers.items():
                        if marker in response_text:
                            discovered.append(param)
                            if not self.silent:
                                print(colored(f"    [+] Reflected POST param: {param} @ {url}", "cyan"))
                except Exception:
                    pass

                await asyncio.sleep(0.1)
            return discovered

    async def discover_params(self, client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore) -> Dict:
        """Discover parameters for a single URL."""
        async with semaphore:
            wordlist = self.load_wordlist()

            # Passive: extract from page source
            passive_params = set()
            try:
                r = await client.get(url, timeout=self.timeout, follow_redirects=True)
                passive_params = extract_params_from_source(r.text)
                # Add existing URL params
                passive_params.update(extract_params_from_url(url))
            except Exception:
                pass

            # Active: probe wordlist
            active_params = await self.probe_params_get(client, url, wordlist, asyncio.Semaphore(1))

            all_params = list(set(list(passive_params) + active_params))

            if all_params and not self.silent:
                print(colored(f"[+] {url}: {len(all_params)} params ({len(passive_params)} passive, {len(active_params)} active)", "green"))

            return {
                'url': url,
                'passive_params': sorted(passive_params),
                'active_params': sorted(active_params),
                'all_params': sorted(set(all_params)),
                'param_count': len(all_params),
            }

    async def run_async(self, urls: List[str]) -> List[Dict]:
        """Run param discovery on all URLs."""
        semaphore = asyncio.Semaphore(self.concurrency)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        async with httpx.AsyncClient(verify=False, headers=headers, timeout=self.timeout) as client:
            tasks = [self.discover_params(client, url, semaphore) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    def run(self, urls: List[str] = None, input_file: str = None, output_file: str = 'params_discovered.csv') -> List[Dict]:
        """Run parameter discovery."""
        if input_file and not urls:
            try:
                with open(input_file) as f:
                    urls = [line.strip() for line in f if line.strip() and line.strip().startswith('http')]
            except Exception as e:
                print(colored(f"[!] Error reading input: {e}", "red"))
                return []

        if not urls:
            print(colored("[!] No URLs provided", "red"))
            return []

        # Focus on URLs that are likely to have parameters (prioritize endpoints, not static files)
        filtered_urls = []
        skip_exts = {'.jpg', '.jpeg', '.png', '.gif', '.css', '.woff', '.woff2', '.ico', '.svg', '.mp4'}
        for url in urls:
            ext = os.path.splitext(urlparse(url).path)[1].lower()
            if ext not in skip_exts:
                filtered_urls.append(url)

        if not self.silent:
            print(colored(f"\n[+] Parameter Discovery on {len(filtered_urls)} URLs...", "blue"))

        findings = asyncio.run(self.run_async(filtered_urls))
        findings = [f for f in findings if f.get('param_count', 0) > 0]
        self.findings = findings

        total_params = sum(f['param_count'] for f in findings)
        if not self.silent:
            print(colored(f"\n[✓] Param discovery complete. {total_params} params across {len(findings)} endpoints", "green"))

        if findings:
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['url', 'param_count', 'active_params', 'passive_params', 'all_params'])
                for r in findings:
                    writer.writerow([
                        r['url'],
                        r['param_count'],
                        ','.join(r['active_params']),
                        ','.join(r['passive_params']),
                        ','.join(r['all_params']),
                    ])
            if not self.silent:
                print(colored(f"[✓] Results saved to {output_file}", "green"))

        return findings


if __name__ == '__main__':
    import sys
    urls = sys.argv[1:] or ['https://example.com']
    disco = ParamDiscovery()
    disco.run(urls=urls)
