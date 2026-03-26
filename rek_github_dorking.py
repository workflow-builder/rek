"""
REK GitHub Dorking & Secret Scanner
Searches GitHub for exposed secrets, credentials, and sensitive data related to a target.
Supports: code search dorking, repo scanning for secrets, commit history analysis.
"""
import asyncio
import httpx
import re
import csv
import os
import json
import time
import base64
from typing import List, Dict, Optional, Set
from termcolor import colored
import logging

logger = logging.getLogger(__name__)

# Secret patterns for detection in code
SECRET_PATTERNS = {
    'AWS_ACCESS_KEY': r'AKIA[0-9A-Z]{16}',
    'AWS_SECRET_KEY': r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']',
    'GitHub_Token': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
    'GitHub_Token_Classic': r'ghp_[A-Za-z0-9_]{36}',
    'Google_API_Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Google_OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'Stripe_Key': r'sk_live_[0-9a-zA-Z]{24,}',
    'Stripe_Restricted': r'rk_live_[0-9a-zA-Z]{24,}',
    'Stripe_Publishable': r'pk_live_[0-9a-zA-Z]{24,}',
    'Slack_Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
    'Slack_Webhook': r'https://hooks\.slack\.com/services/[A-Za-z0-9+/]{44,}',
    'Discord_Token': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
    'Discord_Webhook': r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9._-]{60,68}',
    'JWT_Token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
    'Private_Key': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY',
    'Generic_API_Key': r'(?i)api[_\-\s]?key[_\-\s]?[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
    'Generic_Secret': r'(?i)secret[_\-\s]?key[_\-\s]?[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
    'Generic_Password': r'(?i)password\s*[=:]\s*["\'][^"\'\s]{8,}["\']',
    'Bearer_Token': r'(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}',
    'Heroku_API_Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'SendGrid_Key': r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
    'Twilio_SID': r'AC[a-z0-9]{32}',
    'Twilio_Token': r'SK[a-z0-9]{32}',
    'Mailgun_Key': r'key-[0-9a-zA-Z]{32}',
    'Mailchimp_Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
    'Shopify_Token': r'shpss_[a-fA-F0-9]{32}',
    'HubSpot_Key': r'(?i)hubspot.{0,10}["\'][a-zA-Z0-9-]{36}["\']',
    'Telegram_Bot': r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}',
    'DB_Connection': r'(?i)(mysql|postgresql|mongodb|redis)://[^\s"\'<>]{10,}',
    'SSH_Key': r'ssh-(?:rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/]{100,}',
    'Azure_Connection': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
    'Firebase_URL': r'https://[a-z0-9-]+\.firebaseio\.com',
    'Vault_Token': r's\.[a-zA-Z0-9]{24}',
}

# GitHub search dorks for finding target-related secrets
GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" apikey',
    '"{domain}" secret',
    '"{domain}" token',
    '"{domain}" private_key',
    '"{domain}" access_token',
    '"{domain}" credentials',
    '"{domain}" auth',
    'site:{domain} password',
    '"{domain}" .env',
    '"{domain}" config',
    '"{domain}" db_password',
    '"{domain}" database_url',
    '"{domain}" smtp_password',
    '"{domain}" aws_secret',
    '"{domain}" ssh_key',
    '"{domain}" BEGIN RSA PRIVATE KEY',
    '"{domain}" filename:.env',
    '"{domain}" filename:config.yml',
    '"{domain}" filename:config.json',
    '"{domain}" filename:.npmrc',
    '"{domain}" filename:.gitconfig',
    '"{domain}" filename:id_rsa',
    '"{domain}" filename:docker-compose.yml',
]

def scan_for_secrets(content: str, source_url: str = '') -> List[Dict]:
    """Scan text content for secret patterns."""
    found = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        try:
            matches = re.findall(pattern, content)
            for match in matches[:3]:  # Limit to 3 per type per file
                # Truncate long matches for display
                display_match = match[:50] + '...' if len(match) > 50 else match
                found.append({
                    'type': secret_type,
                    'match': display_match,
                    'full_match': match,
                    'source': source_url,
                })
        except Exception:
            pass
    return found

class GitHubDorker:
    def __init__(self, token: str = None, timeout: int = 15, silent: bool = False):
        self.token = token
        self.timeout = timeout
        self.silent = silent
        self.findings: List[Dict] = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/vnd.github.v3+json',
        }
        if token:
            self.headers['Authorization'] = f'token {token}'

    async def search_code(self, client: httpx.AsyncClient, query: str, page: int = 1) -> List[Dict]:
        """Search GitHub code for a given query."""
        params = {'q': query, 'per_page': 30, 'page': page}
        try:
            r = await client.get(
                'https://api.github.com/search/code',
                params=params,
                headers=self.headers,
                timeout=self.timeout,
            )

            # Handle rate limiting
            if r.status_code == 403 or r.status_code == 429:
                retry_after = int(r.headers.get('Retry-After', 60))
                if not self.silent:
                    print(colored(f"[!] GitHub rate limit hit, waiting {retry_after}s...", "yellow"))
                await asyncio.sleep(min(retry_after, 30))
                return []

            if r.status_code != 200:
                return []

            data = r.json()
            items = data.get('items', [])
            results = []

            for item in items:
                results.append({
                    'repo': item.get('repository', {}).get('full_name', ''),
                    'path': item.get('path', ''),
                    'url': item.get('html_url', ''),
                    'raw_url': item.get('url', ''),  # API URL
                    'sha': item.get('sha', ''),
                })

            return results

        except Exception as e:
            if not self.silent:
                logger.debug(f"GitHub search error: {e}")
            return []

    async def fetch_file_content(self, client: httpx.AsyncClient, api_url: str) -> Optional[str]:
        """Fetch file content from GitHub API."""
        try:
            r = await client.get(api_url, headers=self.headers, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                content_b64 = data.get('content', '')
                if content_b64:
                    return base64.b64decode(content_b64.replace('\n', '')).decode('utf-8', errors='replace')
        except Exception:
            pass
        return None

    async def scan_repo(self, client: httpx.AsyncClient, repo_full_name: str) -> List[Dict]:
        """Scan a repository's recent commits for secrets."""
        findings = []
        try:
            # Get recent commits
            r = await client.get(
                f'https://api.github.com/repos/{repo_full_name}/commits',
                params={'per_page': 10},
                headers=self.headers,
                timeout=self.timeout,
            )
            if r.status_code != 200:
                return []

            commits = r.json()
            for commit in commits[:5]:  # Check last 5 commits
                sha = commit.get('sha', '')
                if not sha:
                    continue

                # Get commit diff
                diff_r = await client.get(
                    f'https://api.github.com/repos/{repo_full_name}/commits/{sha}',
                    headers={**self.headers, 'Accept': 'application/vnd.github.v3.diff'},
                    timeout=self.timeout,
                )
                if diff_r.status_code == 200:
                    secrets = scan_for_secrets(diff_r.text, f"https://github.com/{repo_full_name}/commit/{sha}")
                    findings.extend(secrets)

                await asyncio.sleep(0.5)  # Be gentle with API

        except Exception:
            pass
        return findings

    async def run_dorks(self, domain: str) -> List[Dict]:
        """Run all GitHub dorks for a target domain."""
        all_findings = []
        base_domain = domain.split('.')[0]  # e.g. 'example' from 'example.com'

        dorks_to_run = [d.replace('{domain}', domain) for d in GITHUB_DORKS[:10]]  # Limit to avoid rate limits

        if not self.silent:
            print(colored(f"[*] Running {len(dorks_to_run)} GitHub dorks for {domain}...", "yellow"))

        seen_repos = set()

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for i, dork in enumerate(dorks_to_run):
                if not self.silent:
                    print(colored(f"  [*] Dork {i+1}/{len(dorks_to_run)}: {dork[:60]}...", "cyan"))

                results = await self.search_code(client, dork)

                for result in results:
                    repo = result['repo']

                    if repo not in seen_repos:
                        seen_repos.add(repo)

                        # Fetch file content for secret scanning
                        if result.get('raw_url') and self.token:
                            content = await self.fetch_file_content(client, result['raw_url'])
                            if content:
                                secrets = scan_for_secrets(content, result['url'])
                                for s in secrets:
                                    s['repo'] = repo
                                    s['dork'] = dork
                                    all_findings.append(s)
                                    if not self.silent:
                                        print(colored(f"  [!!!] SECRET: {s['type']} in {repo}/{result['path']}", "red"))
                        else:
                            # Just record the finding without content
                            all_findings.append({
                                'type': 'DORK_MATCH',
                                'match': result['path'],
                                'full_match': result['url'],
                                'source': result['url'],
                                'repo': repo,
                                'dork': dork,
                            })
                            if not self.silent:
                                print(colored(f"  [+] Match: {repo}/{result['path']}", "yellow"))

                # Rate limit friendly delay
                await asyncio.sleep(2 if not self.token else 1)

        return all_findings

    def run(self, domain: str, output_file: str = None) -> List[Dict]:
        """Run GitHub dorking."""
        if not self.token and not self.silent:
            print(colored("[!] No GitHub token provided. Rate limits will be strict (60 req/hr).", "yellow"))

        if not self.silent:
            print(colored(f"\n[+] GitHub Dorking for {domain}...", "blue"))

        findings = asyncio.run(self.run_dorks(domain))
        self.findings = findings

        if not self.silent:
            secrets = [f for f in findings if f.get('type') != 'DORK_MATCH']
            matches = [f for f in findings if f.get('type') == 'DORK_MATCH']
            print(colored(f"\n[✓] GitHub dorking complete. {len(secrets)} secrets, {len(matches)} dork matches", "green"))
            if secrets:
                print(colored(f"[!!!] SECRET TYPES FOUND: {', '.join(set(s['type'] for s in secrets))}", "red"))

        out = output_file or f"github_dorks_{domain}.csv"
        if findings:
            os.makedirs(os.path.dirname(out) if os.path.dirname(out) else '.', exist_ok=True)
            with open(out, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['type', 'repo', 'source', 'match', 'dork'])
                writer.writeheader()
                for item in findings:
                    writer.writerow({
                        'type': item.get('type', ''),
                        'repo': item.get('repo', ''),
                        'source': item.get('source', ''),
                        'match': item.get('match', '')[:200],
                        'dork': item.get('dork', ''),
                    })
            if not self.silent:
                print(colored(f"[✓] Results saved to {out}", "green"))

        return findings


if __name__ == '__main__':
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else 'example.com'
    token = sys.argv[2] if len(sys.argv) > 2 else None
    dorker = GitHubDorker(token=token)
    dorker.run(domain)
