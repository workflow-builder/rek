"""
REK Favicon Fingerprinting - MurmurHash3 favicon hash detection
Computes favicon hashes and checks them against known vulnerable/interesting services.
Can be used with Shodan (if API key provided) to find related infrastructure.
"""
import asyncio
import httpx
import hashlib
import base64
import struct
import os
import csv
import json
from typing import List, Dict, Optional, Tuple
from termcolor import colored
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)

# Known interesting favicon hashes (hash -> service name)
# These are well-known MurmurHash3 values from public research
KNOWN_HASHES = {
    '-1380263950': 'Cobalt Strike C2',
    '1768726015': 'Default Apache Tomcat',
    '116323821': 'Jupyter Notebook',
    '-1097567045': 'Default Fortinet FortiGate',
    '999357577': 'Kibana Dashboard',
    '708578229': 'GitLab',
    '-2128577501': 'Jenkins CI',
    '-1329527640': 'Grafana',
    '1825812969': 'pfSense',
    '-783415153': 'Metabase',
    '16777216': 'Default IIS',
    '2082700781': 'Cisco IOS',
    '-1248923815': 'Jira',
    '1166408545': 'Confluence',
    '708578229': 'GitLab CE',
    '-899114948': 'Bitbucket',
    '1297307692': 'Zoom',
    '1996682687': 'Citrix ADC/NetScaler',
    '1321851801': 'Outlook Web Access',
    '-840993402': 'SharePoint',
    '1786217199': 'phpMyAdmin',
    '-1183052764': 'Webmin',
    '-1685999219': 'VMware vSphere',
    '2067705819': 'SonarQube',
    '297635771': 'RoundCube',
    '-766641445': 'Plesk Panel',
    '1898055739': 'cPanel',
    '1307191121': 'Kubernetes Dashboard',
    '-1247316503': 'HashiCorp Vault',
    '1099502839': 'Consul UI',
    '-1567256417': 'Portainer',
    '-1386115965': 'Traefik Dashboard',
    '1264552012': 'Rancher',
    '1871876988': 'Argo CD',
    '-1438851341': 'MinIO',
}

def mmh3_hash(data: bytes) -> int:
    """Pure Python MurmurHash3 32-bit implementation."""
    seed = 0
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed

    # Process 4-byte blocks
    nblocks = length // 4
    for block_start in range(0, nblocks * 4, 4):
        k1 = struct.unpack('<I', data[block_start:block_start + 4])[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    # Process tail
    tail = data[nblocks * 4:]
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= tail[2] << 16
    if tail_size >= 2:
        k1 ^= tail[1] << 8
    if tail_size >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convert to signed 32-bit
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1

def compute_favicon_hash(favicon_bytes: bytes) -> str:
    """Compute Shodan-compatible favicon hash (base64 encoded, then mmh3)."""
    b64 = base64.encodebytes(favicon_bytes).decode()
    return str(mmh3_hash(b64.encode()))

class FaviconScanner:
    def __init__(self, timeout: int = 10, concurrency: int = 30, silent: bool = False, shodan_key: str = None):
        self.timeout = timeout
        self.concurrency = concurrency
        self.silent = silent
        self.shodan_key = shodan_key
        self.findings: List[Dict] = []

    def get_favicon_urls(self, base_url: str, html: str = None) -> List[str]:
        """Extract favicon URLs from HTML or use common paths."""
        favicon_paths = [
            '/favicon.ico',
            '/favicon.png',
            '/apple-touch-icon.png',
            '/favicon-32x32.png',
            '/favicon-16x16.png',
        ]
        urls = [urljoin(base_url, p) for p in favicon_paths]

        # Try to parse from HTML if provided
        if html:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, 'html.parser')
                for link in soup.find_all('link', rel=lambda x: x and ('icon' in x or 'shortcut' in x)):
                    href = link.get('href', '')
                    if href:
                        urls.insert(0, urljoin(base_url, href))
            except Exception:
                pass

        return urls

    async def fetch_favicon(self, client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore) -> Optional[Tuple[str, bytes]]:
        """Fetch favicon bytes from URL."""
        async with semaphore:
            try:
                r = await client.get(url, timeout=self.timeout, follow_redirects=True)
                if r.status_code == 200 and len(r.content) > 0:
                    return (url, r.content)
            except Exception:
                pass
        return None

    async def scan_host(self, client: httpx.AsyncClient, host_url: str, semaphore: asyncio.Semaphore) -> Optional[Dict]:
        """Scan a single host for favicon and compute its hash."""
        async with semaphore:
            try:
                # Fetch main page to find favicon link
                r = await client.get(host_url, timeout=self.timeout, follow_redirects=True)
                html = r.text if r.status_code == 200 else None
            except Exception:
                html = None

            favicon_urls = self.get_favicon_urls(host_url, html)

            # Try each favicon URL
            for fav_url in favicon_urls[:3]:  # Try first 3
                try:
                    r = await client.get(fav_url, timeout=self.timeout, follow_redirects=True)
                    if r.status_code == 200 and len(r.content) > 100:
                        hash_val = compute_favicon_hash(r.content)
                        md5_hash = hashlib.md5(r.content).hexdigest()
                        known_service = KNOWN_HASHES.get(hash_val, '')

                        result = {
                            'host': host_url,
                            'favicon_url': fav_url,
                            'mmh3_hash': hash_val,
                            'md5_hash': md5_hash,
                            'size_bytes': len(r.content),
                            'known_service': known_service,
                            'shodan_query': f'http.favicon.hash:{hash_val}',
                        }

                        if known_service and not self.silent:
                            print(colored(f"[!] Known service via favicon: {known_service} @ {host_url} (hash: {hash_val})", "red"))
                        elif not self.silent:
                            print(colored(f"[+] Favicon hash: {hash_val} @ {host_url}", "cyan"))

                        return result
                except Exception:
                    pass
            return None

    async def scan_all(self, urls: List[str]) -> List[Dict]:
        """Scan all hosts for favicons."""
        semaphore = asyncio.Semaphore(self.concurrency)
        findings = []
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        async with httpx.AsyncClient(verify=False, headers=headers, timeout=self.timeout) as client:
            tasks = [self.scan_host(client, url, semaphore) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, dict) and r:
                    findings.append(r)
        return findings

    def shodan_search(self, hash_val: str) -> Optional[str]:
        """Return Shodan dork query for given hash."""
        return f'http.favicon.hash:{hash_val}'

    def run(self, urls: List[str] = None, input_file: str = None, output_file: str = 'favicon_hashes.csv') -> List[Dict]:
        """Run favicon scanning."""
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

        if not self.silent:
            print(colored(f"\n[+] Favicon Hash Fingerprinting on {len(urls)} hosts...", "blue"))

        findings = asyncio.run(self.scan_all(urls))
        self.findings = findings

        # Group unique hashes
        unique_hashes = {}
        for f in findings:
            h = f['mmh3_hash']
            if h not in unique_hashes:
                unique_hashes[h] = []
            unique_hashes[h].append(f['host'])

        if not self.silent:
            print(colored(f"\n[✓] Found {len(findings)} favicons, {len(unique_hashes)} unique hashes", "green"))
            known = [f for f in findings if f.get('known_service')]
            if known:
                print(colored(f"[!] {len(known)} hosts matched known service fingerprints!", "red"))

            # Show Shodan queries for unique hashes
            print(colored("\n[*] Shodan queries for unique favicon hashes:", "cyan"))
            for h, hosts in sorted(unique_hashes.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
                service = KNOWN_HASHES.get(h, 'Unknown')
                print(colored(f"    http.favicon.hash:{h}  ({len(hosts)} hosts, service: {service})", "yellow"))

        if findings:
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['host', 'favicon_url', 'mmh3_hash', 'md5_hash', 'size_bytes', 'known_service', 'shodan_query'])
                writer.writeheader()
                writer.writerows(findings)
            if not self.silent:
                print(colored(f"[✓] Results saved to {output_file}", "green"))

        return findings


if __name__ == '__main__':
    import sys
    urls = sys.argv[1:] or ['https://example.com']
    scanner = FaviconScanner()
    scanner.run(urls=urls)
