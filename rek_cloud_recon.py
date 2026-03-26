"""
REK Cloud Asset Recon - S3/Azure/GCP bucket & blob enumeration
Generates bucket name permutations from domain/org name and probes them concurrently.
"""
import asyncio
import httpx
import re
import json
import os
import csv
from typing import List, Dict, Optional
from termcolor import colored
import logging

logger = logging.getLogger(__name__)

# Bucket name permutation suffixes/prefixes
BUCKET_SUFFIXES = [
    '', '-dev', '-staging', '-prod', '-production', '-backup', '-assets', '-static',
    '-media', '-images', '-uploads', '-data', '-store', '-files', '-cdn', '-logs',
    '-archive', '-test', '-testing', '-qa', '-public', '-private', '-internal',
    '-admin', '-api', '-web', '-app', '-resources', '-content', '-downloads',
    '-build', '-release', '-artifacts', '-deploy', '-config', '-secrets',
    '-database', '-db', '-analytics', '-reports', '-email', '-mail',
    '2', '2024', '2025', '-2024', '-2025', '-new', '-old',
]

BUCKET_PREFIXES = [
    '', 'dev-', 'staging-', 'prod-', 'backup-', 'assets-', 'static-',
    'media-', 'data-', 'cdn-', 'logs-', 'test-',
]

# AWS S3 region endpoints
S3_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-central-1', 'ap-southeast-1',
    'ap-northeast-1', 'ap-south-1',
]

class CloudRecon:
    def __init__(self, timeout: int = 10, concurrency: int = 50, silent: bool = False):
        self.timeout = timeout
        self.concurrency = concurrency
        self.silent = silent
        self.findings: List[Dict] = []

    def generate_bucket_names(self, domain: str) -> List[str]:
        """Generate bucket name permutations from a domain."""
        # Extract company name from domain
        base = domain.split('.')[0]
        # Also try with dots replaced
        base_dash = domain.replace('.', '-').replace('_', '-')
        bases = list(dict.fromkeys([base, base_dash, domain]))

        names = set()
        for b in bases:
            for suffix in BUCKET_SUFFIXES:
                names.add(f"{b}{suffix}")
            for prefix in BUCKET_PREFIXES:
                if prefix:
                    names.add(f"{prefix}{b}")
        # Remove names that are too short or contain invalid chars
        valid = {n for n in names if len(n) >= 3 and re.match(r'^[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]$', n.lower())}
        return [n.lower() for n in valid]

    async def check_s3_bucket(self, client: httpx.AsyncClient, bucket: str, semaphore: asyncio.Semaphore) -> Optional[Dict]:
        """Check if an S3 bucket exists and its access level."""
        async with semaphore:
            urls_to_check = [
                (f"https://{bucket}.s3.amazonaws.com", 'us-east-1'),
                (f"https://s3.amazonaws.com/{bucket}", 'us-east-1'),
            ]
            for url, region in urls_to_check:
                try:
                    r = await client.get(url, timeout=self.timeout, follow_redirects=True)
                    if r.status_code == 200:
                        return {
                            'type': 'S3',
                            'bucket': bucket,
                            'url': url,
                            'status': 'PUBLIC_READ',
                            'http_status': r.status_code,
                            'region': region,
                        }
                    elif r.status_code == 403:
                        return {
                            'type': 'S3',
                            'bucket': bucket,
                            'url': url,
                            'status': 'EXISTS_PRIVATE',
                            'http_status': r.status_code,
                            'region': region,
                        }
                    elif r.status_code == 301 and 'x-amz-bucket-region' in r.headers:
                        region = r.headers.get('x-amz-bucket-region', region)
                        return {
                            'type': 'S3',
                            'bucket': bucket,
                            'url': f"https://{bucket}.s3.{region}.amazonaws.com",
                            'status': 'EXISTS_REDIRECT',
                            'http_status': r.status_code,
                            'region': region,
                        }
                except Exception:
                    pass
        return None

    async def check_azure_blob(self, client: httpx.AsyncClient, name: str, semaphore: asyncio.Semaphore) -> Optional[Dict]:
        """Check Azure blob storage container."""
        async with semaphore:
            # Try common Azure blob storage account names
            url = f"https://{name}.blob.core.windows.net"
            url_container = f"https://{name}.blob.core.windows.net/{name}?restype=container"
            for u in [url_container, url]:
                try:
                    r = await client.get(u, timeout=self.timeout, follow_redirects=False)
                    if r.status_code in [200, 400, 403, 409]:
                        status = 'PUBLIC' if r.status_code == 200 else 'EXISTS_PRIVATE'
                        return {
                            'type': 'Azure_Blob',
                            'bucket': name,
                            'url': u,
                            'status': status,
                            'http_status': r.status_code,
                            'region': 'azure',
                        }
                except Exception:
                    pass
        return None

    async def check_gcp_bucket(self, client: httpx.AsyncClient, bucket: str, semaphore: asyncio.Semaphore) -> Optional[Dict]:
        """Check GCP storage bucket."""
        async with semaphore:
            urls = [
                f"https://storage.googleapis.com/{bucket}",
                f"https://{bucket}.storage.googleapis.com",
            ]
            for url in urls:
                try:
                    r = await client.get(url, timeout=self.timeout, follow_redirects=False)
                    if r.status_code == 200:
                        return {
                            'type': 'GCP_Storage',
                            'bucket': bucket,
                            'url': url,
                            'status': 'PUBLIC_READ',
                            'http_status': r.status_code,
                            'region': 'gcp',
                        }
                    elif r.status_code in [403, 400]:
                        return {
                            'type': 'GCP_Storage',
                            'bucket': bucket,
                            'url': url,
                            'status': 'EXISTS_PRIVATE',
                            'http_status': r.status_code,
                            'region': 'gcp',
                        }
                except Exception:
                    pass
        return None

    async def run_async(self, domain: str) -> List[Dict]:
        """Run all cloud recon checks concurrently."""
        bucket_names = self.generate_bucket_names(domain)
        if not self.silent:
            print(colored(f"[*] Generated {len(bucket_names)} bucket name permutations for {domain}", "yellow"))

        semaphore = asyncio.Semaphore(self.concurrency)
        findings = []

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            tasks = []
            for name in bucket_names:
                tasks.append(self.check_s3_bucket(client, name, semaphore))
                tasks.append(self.check_azure_blob(client, name, semaphore))
                tasks.append(self.check_gcp_bucket(client, name, semaphore))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, dict) and r:
                    findings.append(r)
                    status_color = "red" if r['status'] == 'PUBLIC_READ' else "yellow"
                    if not self.silent:
                        print(colored(f"[+] {r['type']} {r['status']}: {r['url']}", status_color))

        self.findings = findings
        return findings

    def run(self, domain: str, output_file: str = None) -> List[Dict]:
        """Run cloud recon and save results."""
        if not self.silent:
            print(colored(f"\n[+] Starting Cloud Asset Discovery for {domain}...", "blue"))

        findings = asyncio.run(self.run_async(domain))

        if not self.silent:
            print(colored(f"\n[✓] Cloud recon complete. Found {len(findings)} cloud assets.", "green"))
            public = [f for f in findings if 'PUBLIC' in f.get('status', '')]
            if public:
                print(colored(f"[!] {len(public)} PUBLIC buckets/blobs found!", "red"))

        if output_file or findings:
            out = output_file or f"cloud_recon_{domain}.csv"
            os.makedirs(os.path.dirname(out) if os.path.dirname(out) else '.', exist_ok=True)
            with open(out, 'w', newline='') as f:
                if findings:
                    writer = csv.DictWriter(f, fieldnames=findings[0].keys())
                    writer.writeheader()
                    writer.writerows(findings)
            if not self.silent:
                print(colored(f"[✓] Results saved to {out}", "green"))

        return findings


if __name__ == '__main__':
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else 'example.com'
    recon = CloudRecon(timeout=10, concurrency=30)
    recon.run(domain, f'cloud_{domain}.csv')
