"""
REK Subdomain Takeover Detector
Checks subdomains for dangling CNAME records pointing to unclaimed cloud services.
Covers: GitHub Pages, Heroku, S3, Azure, Shopify, Fastly, Tumblr, WordPress, Pantheon, etc.
"""
import asyncio
import dns.resolver
import dns.exception
import httpx
import csv
import os
import json
from typing import List, Dict, Optional
from termcolor import colored
import logging

logger = logging.getLogger(__name__)

# Service fingerprints: CNAME pattern -> (service_name, takeover_indicator_in_body, severity)
TAKEOVER_FINGERPRINTS = {
    'github.io': ('GitHub Pages', "There isn't a GitHub Pages site here", 'High'),
    'github.com': ('GitHub', "There isn't a GitHub Pages site here", 'High'),
    'herokuapp.com': ('Heroku', 'No such app', 'High'),
    'herokudns.com': ('Heroku DNS', 'No such app', 'High'),
    'amazonws.com': ('AWS', '', 'High'),
    's3.amazonaws.com': ('AWS S3', 'NoSuchBucket', 'High'),
    'storage.googleapis.com': ('GCP Storage', 'NoSuchBucket', 'High'),
    'blob.core.windows.net': ('Azure Blob', 'BlobNotFound', 'High'),
    'cloudapp.net': ('Azure CloudApp', '404 - Web app not found', 'High'),
    'azure-api.net': ('Azure API', '', 'High'),
    'azurewebsites.net': ('Azure Websites', "404 Web Site not found", 'High'),
    'trafficmanager.net': ('Azure Traffic Manager', '', 'Medium'),
    'shopify.com': ('Shopify', "Sorry, this shop is currently unavailable", 'High'),
    'myshopify.com': ('Shopify', "Sorry, this shop is currently unavailable", 'High'),
    'fastly.net': ('Fastly CDN', 'Fastly error: unknown domain', 'High'),
    'tumblr.com': ('Tumblr', "There's nothing here.", 'High'),
    'wordpress.com': ('WordPress', "Do you want to register", 'High'),
    'wpengine.com': ('WP Engine', 'The site you were looking for', 'Medium'),
    'zendesk.com': ('Zendesk', "Help Center Closed", 'High'),
    'desk.com': ('Zendesk Desk', "Sorry, We Couldn\\'t Find That Page", 'High'),
    'freshdesk.com': ('Freshdesk', "There is no helpdesk here", 'High'),
    'statuspage.io': ('Atlassian Status', 'You are being', 'Medium'),
    'pingdom.com': ('Pingdom', 'This public report page has not been activated', 'Medium'),
    'helpjuice.com': ('Helpjuice', "We could not find what you're looking for", 'High'),
    'helpscoutdocs.com': ('Helpscout', "No settings were found for this company", 'High'),
    'ghost.io': ('Ghost', 'The thing you were looking for is no longer here', 'High'),
    'pantheonsite.io': ('Pantheon', "404 error unknown site", 'High'),
    'pantheon.io': ('Pantheon', "404 error unknown site", 'High'),
    'readthedocs.io': ('ReadTheDocs', "unknown to Read the Docs", 'High'),
    'readthedocs.org': ('ReadTheDocs', "unknown to Read the Docs", 'High'),
    'netlify.app': ('Netlify', "Not Found - Request ID", 'High'),
    'netlify.com': ('Netlify', "Not Found - Request ID", 'High'),
    'vercel.app': ('Vercel', "The deployment could not be found", 'High'),
    'now.sh': ('Vercel', "The deployment could not be found", 'High'),
    'surge.sh': ('Surge.sh', 'project not found', 'High'),
    'bitbucket.io': ('Bitbucket', 'Repository not found', 'High'),
    'launchrock.com': ('Launchrock', "It looks like you may have taken a wrong turn", 'High'),
    'uservoice.com': ('UserVoice', "This UserVoice subdomain is currently available", 'High'),
    'smugmug.com': ('SmugMug', '', 'Medium'),
    'strikingly.com': ('Strikingly', "But if you're looking to build your own website", 'High'),
    'uberflip.com': ('Uberflip', "Non-hub domain, The URL you've accessed does not provide", 'High'),
    'unbounce.com': ('Unbounce', "The requested URL was not found on this server", 'High'),
    'unbouncepages.com': ('Unbounce', "The requested URL was not found on this server", 'High'),
    'wixsite.com': ('Wix', "Error ConnectYourDomain", 'Medium'),
    'tictail.com': ('Tictail', "to target URL: https://tictail.com", 'High'),
    'createsend.com': ('Campaign Monitor', "Double check the URL or try searching", 'High'),
    'acquia-test.co': ('Acquia', "The site you are looking for could not be found", 'High'),
    'flynnhub.com': ('Flynn', "404 page not found", 'High'),
    'hatena.ne.jp': ('Hatena', "404 Blog is not found", 'Medium'),
    'hatenablog.com': ('Hatena Blog', "404 Blog is not found", 'Medium'),
    'webflow.io': ('Webflow', "The page you are looking for doesn\\'t exist", 'High'),
    'readme.io': ('Readme', "Project doesnt exist... yet", 'High'),
    'cargocollective.com': ('Cargo Collective', "404 Not Found", 'High'),
    'futurestay.com': ('Futurestay', "Error connecting to the origin", 'High'),
    'agilecrm.com': ('Agile CRM', "Sorry, this page is no longer available", 'High'),
    'jvmhost.net': ('JVM Host', "The requested hostname is not routed", 'High'),
    'ladesk.com': ('LiveAgent', "Page not found", 'High'),
    'tenderapp.com': ('Tender', "Tender is no longer available", 'High'),
    'intercom.com': ('Intercom', "Uh oh. That page doesn\\'t exist.", 'High'),
    'intercom.io': ('Intercom', "Uh oh. That page doesn\\'t exist.", 'High'),
    'moosend.com': ('Moosend', "Almost there!", 'Medium'),
    'apigee.io': ('Apigee', "Page Not Found", 'High'),
    'airee.ru': ('Airee', "Ошибка", 'High'),
    'anima.io': ('Anima', "Missing draft", 'Medium'),
    'preview.anima.io': ('Anima Preview', "Missing draft", 'Medium'),
}

class TakeoverDetector:
    def __init__(self, timeout: int = 10, concurrency: int = 50, silent: bool = False):
        self.timeout = timeout
        self.concurrency = concurrency
        self.silent = silent
        self.findings: List[Dict] = []

    def get_cname(self, hostname: str) -> Optional[str]:
        """Get CNAME record for a hostname."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(hostname, 'CNAME')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception:
            pass
        return None

    def match_service(self, cname: str) -> Optional[tuple]:
        """Match a CNAME against known takeover-vulnerable services."""
        if not cname:
            return None
        cname_lower = cname.lower()
        for pattern, info in TAKEOVER_FINGERPRINTS.items():
            if pattern in cname_lower:
                return (pattern, info[0], info[1], info[2])
        return None

    async def check_body_fingerprint(self, client: httpx.AsyncClient, url: str, fingerprint: str) -> bool:
        """Check if response body contains the takeover fingerprint string."""
        if not fingerprint:
            return True  # No body check needed, CNAME match is sufficient
        try:
            r = await client.get(url, timeout=self.timeout, follow_redirects=True)
            return fingerprint.lower() in r.text.lower()
        except Exception:
            return False

    async def check_subdomain(self, client: httpx.AsyncClient, subdomain: str, semaphore: asyncio.Semaphore) -> Optional[Dict]:
        """Check a single subdomain for takeover vulnerability."""
        async with semaphore:
            cname = self.get_cname(subdomain)
            if not cname:
                return None

            match = self.match_service(cname)
            if not match:
                return None

            pattern, service, fingerprint, severity = match

            # Verify with HTTP body check
            for scheme in ['https', 'http']:
                url = f"{scheme}://{subdomain}"
                confirmed = await self.check_body_fingerprint(client, url, fingerprint)
                if confirmed:
                    result = {
                        'subdomain': subdomain,
                        'cname': cname,
                        'service': service,
                        'severity': severity,
                        'url': url,
                        'fingerprint': fingerprint,
                        'status': 'VULNERABLE' if fingerprint else 'POSSIBLE',
                    }
                    sev_color = 'red' if severity == 'High' else 'yellow'
                    if not self.silent:
                        print(colored(
                            f"[{severity}] TAKEOVER - {subdomain} -> {cname} ({service})",
                            sev_color
                        ))
                    return result

            # CNAME matches but body doesn't confirm - still report as possible
            return {
                'subdomain': subdomain,
                'cname': cname,
                'service': service,
                'severity': 'Info',
                'url': f"https://{subdomain}",
                'fingerprint': fingerprint,
                'status': 'CNAME_MATCH_UNCONFIRMED',
            }

    async def scan_all(self, subdomains: List[str]) -> List[Dict]:
        """Scan all subdomains for takeover vulnerabilities."""
        semaphore = asyncio.Semaphore(self.concurrency)
        findings = []
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
        async with httpx.AsyncClient(verify=False, headers=headers, timeout=self.timeout) as client:
            tasks = [self.check_subdomain(client, sub, semaphore) for sub in subdomains]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, dict) and r:
                    findings.append(r)
        return findings

    def run(self, subdomains: List[str] = None, input_file: str = None, output_file: str = 'takeover.csv') -> List[Dict]:
        """Run takeover detection."""
        if input_file and not subdomains:
            try:
                with open(input_file) as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(colored(f"[!] Error reading input: {e}", "red"))
                return []

        if not subdomains:
            print(colored("[!] No subdomains provided", "red"))
            return []

        # Clean URLs to hostnames
        clean_subs = []
        for s in subdomains:
            if '://' in s:
                from urllib.parse import urlparse
                s = urlparse(s).netloc
            clean_subs.append(s.strip())

        subdomains = [s for s in clean_subs if s]

        if not self.silent:
            print(colored(f"\n[+] Subdomain Takeover Detection on {len(subdomains)} subdomains...", "blue"))

        findings = asyncio.run(self.scan_all(subdomains))
        self.findings = findings

        vuln = [f for f in findings if f.get('status') == 'VULNERABLE']
        if not self.silent:
            print(colored(f"\n[✓] Takeover scan complete. {len(vuln)} confirmed vulnerable, {len(findings)} total matches", "green"))
            if vuln:
                print(colored(f"\n[!!!] CONFIRMED TAKEOVERS:", "red"))
                for v in vuln:
                    print(colored(f"    {v['subdomain']} -> {v['cname']} ({v['service']})", "red"))

        if findings:
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['subdomain', 'cname', 'service', 'severity', 'url', 'status', 'fingerprint'])
                writer.writeheader()
                writer.writerows(findings)
            if not self.silent:
                print(colored(f"[✓] Results saved to {output_file}", "green"))

        return findings


if __name__ == '__main__':
    import sys
    subs = sys.argv[1:] or ['test.example.com']
    detector = TakeoverDetector()
    detector.run(subdomains=subs)
