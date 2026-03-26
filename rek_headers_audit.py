"""
REK Headers Audit - CORS misconfiguration and security headers analysis
Checks for: CORS wildcards, missing security headers, exposed server info, etc.
"""
import asyncio
import httpx
import csv
import os
import json
from typing import List, Dict, Optional
from termcolor import colored
import logging

logger = logging.getLogger(__name__)

# Security headers we expect to see
SECURITY_HEADERS = {
    'x-frame-options': 'Missing X-Frame-Options (Clickjacking risk)',
    'x-content-type-options': 'Missing X-Content-Type-Options',
    'x-xss-protection': 'Missing X-XSS-Protection',
    'content-security-policy': 'Missing Content-Security-Policy',
    'strict-transport-security': 'Missing HSTS',
    'referrer-policy': 'Missing Referrer-Policy',
    'permissions-policy': 'Missing Permissions-Policy',
}

# Headers that shouldn't be exposed
SENSITIVE_HEADERS = [
    'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
    'x-drupal-cache', 'x-generator', 'x-wp-nonce',
]

CORS_REFLECT_ORIGINS = [
    'https://evil.com',
    'https://attacker.com',
    'null',
]

class HeadersAuditor:
    def __init__(self, timeout: int = 10, concurrency: int = 30, silent: bool = False):
        self.timeout = timeout
        self.concurrency = concurrency
        self.silent = silent
        self.findings: List[Dict] = []

    def analyze_cors(self, url: str, headers: dict, reflected_origin: str) -> List[Dict]:
        """Analyze CORS response headers for misconfigurations."""
        issues = []
        acao = headers.get('access-control-allow-origin', '')
        acac = headers.get('access-control-allow-credentials', '').lower()

        if acao == '*':
            issues.append({
                'url': url, 'category': 'CORS', 'severity': 'Medium',
                'issue': 'Wildcard CORS origin (*)',
                'header': 'Access-Control-Allow-Origin: *',
                'detail': 'Any origin can read responses. Dangerous with credentials.',
            })
        elif acao and reflected_origin in acao:
            if acac == 'true':
                issues.append({
                    'url': url, 'category': 'CORS', 'severity': 'High',
                    'issue': 'CORS Origin Reflected + Credentials Allowed',
                    'header': f'ACAO: {acao}, ACAC: {acac}',
                    'detail': f'Origin {reflected_origin} is reflected AND credentials are allowed. Critical CORS misconfiguration.',
                })
            else:
                issues.append({
                    'url': url, 'category': 'CORS', 'severity': 'Medium',
                    'issue': 'CORS Origin Reflected without credentials',
                    'header': f'ACAO: {acao}',
                    'detail': f'Origin {reflected_origin} is reflected. May allow cross-origin reads.',
                })

        # Null origin
        if acao == 'null':
            issues.append({
                'url': url, 'category': 'CORS', 'severity': 'High',
                'issue': 'CORS null origin allowed',
                'header': 'Access-Control-Allow-Origin: null',
                'detail': 'null origin can be triggered from sandboxed iframes.',
            })
        return issues

    def analyze_security_headers(self, url: str, headers: dict) -> List[Dict]:
        """Check for missing or misconfigured security headers."""
        issues = []
        lower_headers = {k.lower(): v for k, v in headers.items()}

        for header, message in SECURITY_HEADERS.items():
            if header not in lower_headers:
                severity = 'High' if header in ('strict-transport-security', 'content-security-policy') else 'Low'
                issues.append({
                    'url': url, 'category': 'Security_Headers', 'severity': severity,
                    'issue': message, 'header': header, 'detail': f'Header {header} is not set.',
                })

        for header in SENSITIVE_HEADERS:
            if header in lower_headers:
                issues.append({
                    'url': url, 'category': 'Info_Disclosure', 'severity': 'Info',
                    'issue': f'Exposed {header} header',
                    'header': f'{header}: {lower_headers[header]}',
                    'detail': f'Technology fingerprinting: {lower_headers[header]}',
                })

        # Check HSTS details if present
        hsts = lower_headers.get('strict-transport-security', '')
        if hsts and 'max-age' in hsts:
            try:
                max_age = int(re.search(r'max-age=(\d+)', hsts).group(1))
                if max_age < 31536000:
                    issues.append({
                        'url': url, 'category': 'Security_Headers', 'severity': 'Low',
                        'issue': 'HSTS max-age too short (< 1 year)',
                        'header': f'Strict-Transport-Security: {hsts}',
                        'detail': f'max-age={max_age}. Recommend >= 31536000.',
                    })
            except Exception:
                pass

        return issues

    async def audit_url(self, client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore) -> List[Dict]:
        """Audit a single URL for CORS and security header issues."""
        async with semaphore:
            url_issues = []
            try:
                # Normal request
                r = await client.get(url, timeout=self.timeout, follow_redirects=True)
                headers = dict(r.headers)
                url_issues.extend(self.analyze_security_headers(url, headers))

                # CORS probe with evil origins
                for origin in CORS_REFLECT_ORIGINS:
                    try:
                        r2 = await client.get(
                            url,
                            headers={'Origin': origin},
                            timeout=self.timeout,
                            follow_redirects=True
                        )
                        cors_issues = self.analyze_cors(url, dict(r2.headers), origin)
                        url_issues.extend(cors_issues)
                        if cors_issues:
                            break  # Found an issue, no need to test more origins
                    except Exception:
                        pass

            except Exception as e:
                pass

            for issue in url_issues:
                sev_color = {'High': 'red', 'Medium': 'yellow', 'Low': 'cyan', 'Info': 'white'}.get(issue.get('severity', 'Info'), 'white')
                if not self.silent:
                    print(colored(f"[{issue['severity']}] {issue['issue']} @ {url}", sev_color))

            return url_issues

    async def audit_all(self, urls: List[str]) -> List[Dict]:
        """Audit all URLs concurrently."""
        semaphore = asyncio.Semaphore(self.concurrency)
        all_issues = []
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }
        async with httpx.AsyncClient(verify=False, headers=headers, timeout=self.timeout) as client:
            tasks = [self.audit_url(client, url, semaphore) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    all_issues.extend(result)
        return all_issues

    def run(self, urls: List[str] = None, input_file: str = None, output_file: str = 'headers_audit.csv') -> List[Dict]:
        """Run headers audit."""
        import re  # needed for HSTS check
        # patch re into analyze_security_headers scope
        globals()['re'] = re

        if input_file and not urls:
            try:
                with open(input_file) as f:
                    urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(colored(f"[!] Error reading input file: {e}", "red"))
                return []

        if not urls:
            print(colored("[!] No URLs provided for headers audit", "red"))
            return []

        if not self.silent:
            print(colored(f"\n[+] Starting Headers/CORS Audit on {len(urls)} URLs...", "blue"))

        findings = asyncio.run(self.audit_all(urls))
        self.findings = findings

        high = len([f for f in findings if f.get('severity') == 'High'])
        med = len([f for f in findings if f.get('severity') == 'Medium'])

        if not self.silent:
            print(colored(f"\n[✓] Headers audit complete. {len(findings)} issues found ({high} High, {med} Medium)", "green"))

        if findings:
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['url', 'category', 'severity', 'issue', 'header', 'detail'])
                writer.writeheader()
                writer.writerows(findings)
            if not self.silent:
                print(colored(f"[✓] Results saved to {output_file}", "green"))

        return findings


if __name__ == '__main__':
    import sys
    import re
    urls = sys.argv[1:] or ['https://example.com']
    auditor = HeadersAuditor()
    auditor.run(urls=urls)
