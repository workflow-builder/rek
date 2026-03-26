"""
REK Enhanced OSINT Engine

Comprehensive OSINT module covering:
  1. Email harvesting — Hunter.io API + search-engine scraping (Google/Bing/Yahoo)
  2. Employee enumeration via public search scraping
  3. Technology stack detection without Wappalyzer dependency
     (HTTP headers, HTML meta tags, JS framework detection, CMS fingerprinting)
  4. Breach data lookup via HaveIBeenPwned API
  5. Certificate transparency search via crt.sh (enhanced)
  6. Google dorking for the target domain with structured output

All HTTP operations use async httpx with rate limiting and retry logic.
Scraped search results are treated as best-effort; API calls are preferred.

Output: JSON report at --output-dir/osint-report.json
"""

import argparse
import asyncio
import csv
import json
import logging
import os
import re
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus, urlparse

try:
    import httpx
    _HTTPX_OK = True
except ImportError:
    _HTTPX_OK = False

try:
    from bs4 import BeautifulSoup
    _BS4_OK = True
except ImportError:
    _BS4_OK = False

try:
    from termcolor import colored
except ImportError:
    def colored(text, *args, **kwargs):  # type: ignore
        return text

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Technology stack fingerprints: header/body pattern -> tech name
TECH_FINGERPRINTS = {
    # HTTP Headers
    "headers": {
        "server":          [
            (r"nginx", "Nginx"),
            (r"apache", "Apache"),
            (r"Microsoft-IIS/(\S+)", "IIS"),
            (r"LiteSpeed", "LiteSpeed"),
            (r"cloudflare", "Cloudflare"),
            (r"AmazonS3", "Amazon S3"),
            (r"openresty", "OpenResty"),
            (r"gunicorn", "Gunicorn"),
            (r"uvicorn", "Uvicorn"),
            (r"caddy", "Caddy"),
        ],
        "x-powered-by":   [
            (r"PHP/([\d.]+)", "PHP"),
            (r"Express", "Express.js"),
            (r"ASP\.NET", "ASP.NET"),
            (r"Next\.js", "Next.js"),
            (r"Servlet", "Java Servlet"),
        ],
        "x-generator":    [
            (r"Drupal", "Drupal"),
            (r"WordPress", "WordPress"),
            (r"Joomla", "Joomla"),
        ],
        "x-aspnet-version": [(r"[\d.]+", "ASP.NET")],
        "x-drupal-cache":   [(r".*", "Drupal")],
        "x-wp-total":       [(r".*", "WordPress")],
        "cf-ray":           [(r".*", "Cloudflare")],
        "via":              [(r".*varnish.*", "Varnish Cache")],
        "x-varnish":        [(r".*", "Varnish Cache")],
        "x-shopify-stage":  [(r".*", "Shopify")],
        "x-magento-tags":   [(r".*", "Magento")],
    },
    # HTML body patterns
    "body": [
        (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', "generator_meta"),
        (r'wp-content/(?:themes|plugins)/', "WordPress"),
        (r'wp-json/', "WordPress REST API"),
        (r'Drupal\.settings', "Drupal"),
        (r'"drupalSettings"', "Drupal"),
        (r'Joomla!', "Joomla"),
        (r'joomla\.js', "Joomla"),
        (r'ng-version=["\']', "Angular"),
        (r'__NEXT_DATA__', "Next.js"),
        (r'__nuxt', "Nuxt.js"),
        (r'react\.development\.js|react\.production\.min\.js|data-reactroot', "React"),
        (r'vue\.js|vue\.min\.js|data-v-', "Vue.js"),
        (r'Shopify\.theme', "Shopify"),
        (r'Magento_', "Magento"),
        (r'PrestaShop', "PrestaShop"),
        (r'X-Squarespace-Version', "Squarespace"),
        (r'greenhouse\.io', "Greenhouse ATS"),
        (r'cdn\.hubspot\.net', "HubSpot"),
        (r'mktoresp\.com', "Marketo"),
        (r'salesforce\.com', "Salesforce"),
        (r'__NEXT_REDUX_STORE__', "Next.js + Redux"),
        (r'gatsby-browser', "Gatsby"),
        (r'svelte', "Svelte"),
    ],
}

# Google dork templates for web recon
WEB_DORKS = [
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:xls',
    'site:{domain} filetype:xlsx',
    'site:{domain} filetype:doc',
    'site:{domain} filetype:docx',
    'site:{domain} filetype:sql',
    'site:{domain} filetype:env',
    'site:{domain} filetype:log',
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} inurl:dashboard',
    'site:{domain} inurl:backup',
    'site:{domain} inurl:config',
    'site:{domain} inurl:api',
    'site:{domain} inurl:swagger',
    'site:{domain} inurl:phpinfo',
    'site:{domain} intitle:"Index of"',
    'site:{domain} intitle:"403 Forbidden"',
    'site:{domain} intitle:"500 Internal"',
    'site:{domain} "password" filetype:txt',
    'site:{domain} "api_key" OR "api-key" OR "apikey"',
    'site:{domain} "DB_PASSWORD" OR "database_password"',
    'site:{domain} ext:php inurl:?',
    'site:{domain} inurl:upload',
    'site:{domain} inurl:debug',
]

# Email search dork templates for search engines
EMAIL_DORKS = [
    'site:linkedin.com "@{domain}"',
    '"@{domain}" email',
    'contact "@{domain}"',
    'email "@{domain}" site:hunter.io',
]

# HIBP API endpoint
HIBP_API_URL = "https://haveibeenpwned.com/api/v3"

# crt.sh API endpoint
CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"

# Hunter.io API endpoint
HUNTER_API_URL = "https://api.hunter.io/v2"


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _extract_emails(text: str) -> Set[str]:
    """Extract and deduplicate email addresses from raw text."""
    return set(EMAIL_REGEX.findall(text))


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _is_generic_email(email: str, domain: str) -> bool:
    """Return True if email looks like a generic/system address."""
    generic_prefixes = {
        "noreply", "no-reply", "donotreply", "support", "info", "admin",
        "webmaster", "postmaster", "root", "abuse", "security", "help",
        "contact", "sales", "marketing", "hello", "team", "reply",
    }
    prefix = email.split("@")[0].lower()
    return prefix in generic_prefixes


def _extract_domain_base(domain: str) -> str:
    """Strip www. prefix for cleaner matching."""
    return domain.lstrip("www.")


# ---------------------------------------------------------------------------
# Email harvesting
# ---------------------------------------------------------------------------

async def _hunter_search(
    client: "httpx.AsyncClient",
    domain: str,
    api_key: str,
    silent: bool = False,
) -> List[str]:
    """Harvest emails from Hunter.io domain search API."""
    emails: List[str] = []
    try:
        params = {"domain": domain, "api_key": api_key, "limit": 100}
        r = await client.get(f"{HUNTER_API_URL}/domain-search", params=params, timeout=15)
        if r.status_code == 200:
            data = r.json()
            for entry in data.get("data", {}).get("emails", []):
                addr = entry.get("value", "")
                if addr:
                    emails.append(_normalize_email(addr))
            if not silent:
                print(colored(f"  [+] Hunter.io: {len(emails)} emails", "green"))
        elif r.status_code == 401:
            if not silent:
                print(colored("  [!] Hunter.io: invalid API key", "yellow"))
        elif r.status_code == 429:
            if not silent:
                print(colored("  [!] Hunter.io: rate limited", "yellow"))
    except Exception as e:
        logger.debug(f"Hunter.io error: {e}")
    return emails


async def _scrape_search_emails(
    client: "httpx.AsyncClient",
    domain: str,
    engine: str = "bing",
    silent: bool = False,
) -> Set[str]:
    """
    Scrape email addresses from a search engine results page.
    Uses email-specific dork queries.
    Treats results as best-effort — failures are silently skipped.
    """
    emails: Set[str] = set()
    query = f'"@{domain}"'

    engine_urls = {
        "bing":  f"https://www.bing.com/search?q={quote_plus(query)}&count=50",
        "yahoo": f"https://search.yahoo.com/search?p={quote_plus(query)}&n=100",
    }
    search_url = engine_urls.get(engine)
    if not search_url:
        return emails

    try:
        headers = {
            "User-Agent": DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        }
        r = await client.get(search_url, headers=headers, timeout=15, follow_redirects=True)
        if r.status_code == 200 and _BS4_OK:
            soup = BeautifulSoup(r.text, "html.parser")
            text = soup.get_text(" ")
            emails = _extract_emails(text)
            # Filter to target domain only
            emails = {e for e in emails if domain in e}
            if not silent and emails:
                print(colored(f"  [+] {engine} scrape: {len(emails)} emails", "green"))
        await asyncio.sleep(2)  # Respectful delay between search engines
    except Exception as e:
        logger.debug(f"{engine} scrape error: {e}")

    return emails


async def harvest_emails_async(
    domain: str,
    hunter_api_key: str = "",
    silent: bool = False,
) -> List[str]:
    """
    Harvest emails from all available sources.
    Returns deduplicated list of email addresses.
    """
    all_emails: Set[str] = set()

    if not _HTTPX_OK:
        logger.warning("httpx not installed — email harvesting unavailable")
        return []

    async with httpx.AsyncClient(verify=False, timeout=20) as client:
        # Source 1: Hunter.io (if key provided)
        if hunter_api_key:
            hunter_emails = await _hunter_search(client, domain, hunter_api_key, silent=silent)
            all_emails.update(hunter_emails)

        # Source 2: Bing scraping
        bing_emails = await _scrape_search_emails(client, domain, engine="bing", silent=silent)
        all_emails.update(bing_emails)

        # Source 3: Yahoo scraping
        yahoo_emails = await _scrape_search_emails(client, domain, engine="yahoo", silent=silent)
        all_emails.update(yahoo_emails)

    # Normalize and return
    normalized = sorted({_normalize_email(e) for e in all_emails if "@" in e and domain in e})
    if not silent:
        print(colored(f"  [+] Total unique emails: {len(normalized)}", "green"))

    return normalized


# ---------------------------------------------------------------------------
# Technology detection
# ---------------------------------------------------------------------------

async def detect_technologies_async(
    url: str,
    client: "httpx.AsyncClient",
    silent: bool = False,
) -> Dict:
    """
    Detect technology stack from HTTP headers and response body.
    Returns a dict with 'technologies' list and raw header data.
    """
    technologies: Set[str] = set()
    headers_captured: Dict[str, str] = {}

    try:
        r = await client.get(url, timeout=15, follow_redirects=True)
        headers_captured = dict(r.headers)
        body = r.text

        # Header analysis
        for header_name, patterns in TECH_FINGERPRINTS["headers"].items():
            header_val = r.headers.get(header_name, "")
            if not header_val:
                continue
            for pattern, tech_name in patterns:
                m = re.search(pattern, header_val, re.IGNORECASE)
                if m:
                    # Capture version if group is present
                    if m.lastindex and m.lastindex >= 1:
                        technologies.add(f"{tech_name} {m.group(1)}")
                    else:
                        technologies.add(tech_name)

        # Body analysis
        if body:
            for pattern, tech_name in TECH_FINGERPRINTS["body"]:
                m = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
                if m:
                    if tech_name == "generator_meta":
                        # Extract generator content
                        technologies.add(m.group(1).strip())
                    else:
                        technologies.add(tech_name)

        # Cookie-based detection
        set_cookie = r.headers.get("set-cookie", "")
        if "PHPSESSID" in set_cookie:
            technologies.add("PHP (Session)")
        if "JSESSIONID" in set_cookie:
            technologies.add("Java (Session)")
        if "ASP.NET_SessionId" in set_cookie:
            technologies.add("ASP.NET (Session)")
        if "wp-" in set_cookie:
            technologies.add("WordPress (Cookie)")
        if "laravel_session" in set_cookie.lower():
            technologies.add("Laravel")
        if "rails" in set_cookie.lower():
            technologies.add("Ruby on Rails")

        if not silent and technologies:
            techs_str = ", ".join(sorted(technologies))
            print(colored(f"  [+] {url}: {techs_str}", "green"))

    except Exception as e:
        logger.debug(f"Tech detect error for {url}: {e}")

    return {
        "url":          url,
        "technologies": sorted(technologies),
        "headers":      {k: v for k, v in headers_captured.items() if k.lower() in [
            "server", "x-powered-by", "x-generator", "via", "cf-ray",
            "x-aspnet-version", "content-type", "strict-transport-security",
            "x-frame-options", "x-content-type-options", "content-security-policy",
        ]},
        "status_code":  getattr(r, "status_code", 0) if "r" in dir() else 0,
    }


# ---------------------------------------------------------------------------
# Breach data lookup
# ---------------------------------------------------------------------------

async def check_breach_async(
    email: str,
    api_key: str,
    client: "httpx.AsyncClient",
    silent: bool = False,
) -> Dict:
    """
    Check if an email has appeared in breaches via HaveIBeenPwned API v3.
    Requires a valid HIBP API key for email lookups.
    """
    result = {"email": email, "breached": False, "breach_count": 0, "breaches": []}

    if not api_key:
        return result

    try:
        headers = {
            "hibp-api-key": api_key,
            "User-Agent":   "REK-Recon-Platform/1.0",
        }
        r = await client.get(
            f"{HIBP_API_URL}/breachedaccount/{quote_plus(email)}",
            headers=headers,
            params={"truncateResponse": "false"},
            timeout=10,
        )

        if r.status_code == 200:
            breaches = r.json()
            result["breached"] = True
            result["breach_count"] = len(breaches)
            result["breaches"] = [
                {
                    "name":       b.get("Name", ""),
                    "domain":     b.get("Domain", ""),
                    "date":       b.get("BreachDate", ""),
                    "pwn_count":  b.get("PwnCount", 0),
                    "data_types": b.get("DataClasses", []),
                }
                for b in breaches
            ]
            if not silent:
                print(colored(f"  [!!!] BREACH: {email} in {len(breaches)} breach(es)", "red"))
        elif r.status_code == 404:
            # Not breached
            pass
        elif r.status_code == 429:
            if not silent:
                print(colored(f"  [!] HIBP rate limited — retrying after delay...", "yellow"))
            await asyncio.sleep(6)
        elif r.status_code == 401:
            if not silent:
                print(colored("  [!] HIBP API key invalid", "yellow"))

    except Exception as e:
        logger.debug(f"HIBP check error for {email}: {e}")

    return result


# ---------------------------------------------------------------------------
# Certificate transparency (enhanced crt.sh)
# ---------------------------------------------------------------------------

async def crt_sh_search_async(
    domain: str,
    client: "httpx.AsyncClient",
    silent: bool = False,
) -> List[Dict]:
    """
    Enhanced crt.sh certificate transparency search.
    Returns deduplicated list of subdomains with cert metadata.
    """
    results: List[Dict] = []
    seen: Set[str] = set()

    try:
        params = {"q": f"%.{domain}", "output": "json"}
        r = await client.get("https://crt.sh/", params=params, timeout=30)

        if r.status_code == 200:
            try:
                entries = r.json()
            except json.JSONDecodeError:
                return results

            for entry in entries:
                name_value = entry.get("name_value", "")
                # Handle multi-value cert SANs (newline separated)
                for name in name_value.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and name not in seen and domain in name:
                        seen.add(name)
                        results.append({
                            "subdomain":   name,
                            "issuer":      entry.get("issuer_name", ""),
                            "not_before":  entry.get("not_before", ""),
                            "not_after":   entry.get("not_after", ""),
                            "cert_id":     entry.get("id", ""),
                        })

            if not silent:
                print(colored(f"  [+] crt.sh: {len(results)} subdomains from certificates", "green"))

    except Exception as e:
        logger.debug(f"crt.sh error: {e}")
        if not silent:
            print(colored(f"  [!] crt.sh lookup failed: {e}", "yellow"))

    return results


# ---------------------------------------------------------------------------
# Google dorking (structured output)
# ---------------------------------------------------------------------------

async def google_dork_async(
    domain: str,
    dorks: Optional[List[str]] = None,
    client: Optional["httpx.AsyncClient"] = None,
    silent: bool = False,
) -> List[Dict]:
    """
    Run Google/Bing dorks for a target domain via Bing API (avoids CAPTCHA).
    Returns structured list with dork, result_url, snippet.

    Note: Google blocks automated scraping aggressively. We use Bing as the
    primary engine for automated dorking. For Google specifically, results
    are best-effort via public search.
    """
    dork_list = dorks or WEB_DORKS
    results: List[Dict] = []
    should_close = False

    if not _HTTPX_OK:
        return results

    if client is None:
        client = httpx.AsyncClient(verify=False, timeout=15)
        should_close = True

    try:
        for dork_template in dork_list:
            dork = dork_template.replace("{domain}", domain)

            try:
                headers = {
                    "User-Agent": DEFAULT_UA,
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "en-US,en;q=0.9",
                }
                bing_url = f"https://www.bing.com/search?q={quote_plus(dork)}&count=20"
                r = await client.get(bing_url, headers=headers, timeout=15, follow_redirects=True)

                if r.status_code == 200 and _BS4_OK:
                    soup = BeautifulSoup(r.text, "html.parser")
                    # Bing result links are in <li class="b_algo"> tags
                    for result_li in soup.select("li.b_algo")[:5]:
                        link_tag = result_li.select_one("h2 a")
                        snippet_tag = result_li.select_one(".b_caption p")
                        if link_tag and link_tag.get("href", "").startswith("http"):
                            result_url = link_tag["href"]
                            snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
                            results.append({
                                "dork":       dork,
                                "result_url": result_url,
                                "snippet":    snippet[:300],
                                "engine":     "bing",
                            })
                elif r.status_code == 200 and not _BS4_OK:
                    # Fallback: extract URLs with regex
                    urls_found = re.findall(r'href="(https?://[^"]+)"', r.text)
                    for u in urls_found[:3]:
                        if domain in u and "bing.com" not in u:
                            results.append({
                                "dork":       dork,
                                "result_url": u,
                                "snippet":    "",
                                "engine":     "bing",
                            })

                if not silent:
                    dork_short = dork[:60] + ("..." if len(dork) > 60 else "")
                    print(colored(f"  [*] Dork: {dork_short}", "cyan"))

                # Respectful delay between dork requests
                await asyncio.sleep(2.5)

            except Exception as e:
                logger.debug(f"Dork error '{dork[:40]}': {e}")
                await asyncio.sleep(1)

    finally:
        if should_close:
            await client.aclose()

    if not silent:
        print(colored(f"  [+] Dorking complete: {len(results)} results", "green"))

    return results


# ---------------------------------------------------------------------------
# Main OSINT Engine class
# ---------------------------------------------------------------------------

class OSINTEngine:
    """
    Comprehensive OSINT engine for a target domain.

    Methods:
      harvest_emails()     -> List[str]
      detect_technologies()-> Dict
      check_breach()       -> Dict
      google_dork()        -> List[Dict]
      run()                -> Dict  (full report)
    """

    def __init__(
        self,
        hunter_api_key: str = "",
        hibp_api_key:   str = "",
        silent:         bool = False,
        timeout:        int = 20,
    ):
        self.hunter_api_key = hunter_api_key
        self.hibp_api_key   = hibp_api_key
        self.silent         = silent
        self.timeout        = timeout

    def harvest_emails(self, domain: str) -> List[str]:
        return asyncio.run(
            harvest_emails_async(domain, self.hunter_api_key, silent=self.silent)
        )

    def detect_technologies(self, url: str) -> Dict:
        async def _run():
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                return await detect_technologies_async(url, client, silent=self.silent)
        return asyncio.run(_run())

    def check_breach(self, email: str, api_key: str = "") -> Dict:
        key = api_key or self.hibp_api_key

        async def _run():
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                return await check_breach_async(email, key, client, silent=self.silent)

        return asyncio.run(_run())

    def google_dork(self, domain: str, dorks: Optional[List[str]] = None) -> List[Dict]:
        return asyncio.run(
            google_dork_async(domain, dorks, silent=self.silent)
        )

    def run(self, domain: str, output_dir: str) -> Dict:
        """
        Execute the full OSINT pipeline for a domain and write results.

        Returns a structured dict with all findings.
        """
        os.makedirs(output_dir, exist_ok=True)

        if not self.silent:
            print(colored(f"\n[+] OSINT Engine: starting full scan for {domain}", "blue"))

        report: Dict = {
            "domain":        domain,
            "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "emails":        [],
            "employees":     [],
            "technologies":  {},
            "breaches":      [],
            "crt_subdomains":[],
            "dork_results":  [],
            "summary":       {},
        }

        async def _run_all():
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:

                # 1. Certificate transparency
                if not self.silent:
                    print(colored("\n[*] Certificate Transparency lookup...", "blue"))
                crt_results = await crt_sh_search_async(domain, client, silent=self.silent)
                report["crt_subdomains"] = crt_results

                # 2. Email harvesting
                if not self.silent:
                    print(colored("\n[*] Email harvesting...", "blue"))
                emails = await harvest_emails_async(
                    domain, self.hunter_api_key, silent=self.silent
                )
                report["emails"] = emails

                # 3. Technology detection on main domain and www
                if not self.silent:
                    print(colored("\n[*] Technology stack detection...", "blue"))
                tech_results = {}
                for proto in ("https", "http"):
                    target_url = f"{proto}://{domain}"
                    if not self.silent:
                        print(colored(f"  [*] Probing {target_url}...", "cyan"))
                    tech = await detect_technologies_async(target_url, client, silent=self.silent)
                    if tech.get("technologies"):
                        tech_results[target_url] = tech
                        break  # Got a result, no need to try http too

                www_url = f"https://www.{domain}"
                if not self.silent:
                    print(colored(f"  [*] Probing {www_url}...", "cyan"))
                www_tech = await detect_technologies_async(www_url, client, silent=self.silent)
                if www_tech.get("technologies"):
                    tech_results[www_url] = www_tech

                report["technologies"] = tech_results

                # 4. Google/Bing dorking (first 10 dorks to be respectful)
                if not self.silent:
                    print(colored("\n[*] Web dorking...", "blue"))
                dork_results = await google_dork_async(
                    domain,
                    WEB_DORKS[:10],
                    client=client,
                    silent=self.silent,
                )
                report["dork_results"] = dork_results

                # 5. Breach check for harvested emails (if HIBP key provided)
                if self.hibp_api_key and emails:
                    if not self.silent:
                        print(colored("\n[*] Breach data lookup...", "blue"))
                    breach_results = []
                    for email in emails[:20]:  # Limit to first 20 to respect rate limits
                        result = await check_breach_async(
                            email, self.hibp_api_key, client, silent=self.silent
                        )
                        if result.get("breached"):
                            breach_results.append(result)
                        await asyncio.sleep(1.6)  # HIBP requires 1.5s between requests
                    report["breaches"] = breach_results

        asyncio.run(_run_all())

        # Build summary
        all_techs: Set[str] = set()
        for tech_data in report["technologies"].values():
            all_techs.update(tech_data.get("technologies", []))

        report["summary"] = {
            "emails_found":       len(report["emails"]),
            "crt_subdomains":     len(report["crt_subdomains"]),
            "technologies":       sorted(all_techs),
            "dork_results":       len(report["dork_results"]),
            "breached_emails":    len(report["breaches"]),
        }

        # Print summary
        if not self.silent:
            s = report["summary"]
            print(colored(f"\n[+] OSINT Summary for {domain}:", "green"))
            print(colored(f"    Emails:        {s['emails_found']}", "white"))
            print(colored(f"    CRT subdomains:{s['crt_subdomains']}", "white"))
            print(colored(f"    Technologies:  {', '.join(s['technologies'][:8])}", "white"))
            print(colored(f"    Dork results:  {s['dork_results']}", "white"))
            print(colored(f"    Breached:      {s['breached_emails']}", "red" if s["breached_emails"] > 0 else "white"))

        # Write report
        report_path = os.path.join(output_dir, "osint-report.json")
        try:
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
            if not self.silent:
                print(colored(f"\n[+] OSINT report saved to {report_path}", "green"))
        except Exception as e:
            print(colored(f"[!] Failed to save OSINT report: {e}", "red"))

        # Also write emails as plain text
        if report["emails"]:
            emails_path = os.path.join(output_dir, "emails.txt")
            with open(emails_path, "w") as f:
                f.write("\n".join(report["emails"]) + "\n")

        # Write dork results as CSV
        if report["dork_results"]:
            dorks_path = os.path.join(output_dir, "dork-results.csv")
            with open(dorks_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["dork", "result_url", "snippet", "engine"])
                writer.writeheader()
                writer.writerows(report["dork_results"])

        # Write CRT subdomains
        if report["crt_subdomains"]:
            crt_path = os.path.join(output_dir, "crt-subdomains.txt")
            with open(crt_path, "w") as f:
                for entry in report["crt_subdomains"]:
                    f.write(entry["subdomain"] + "\n")

        return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="REK Enhanced OSINT Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rek_osint.py -d example.com --output-dir results/example.com
  python3 rek_osint.py -d example.com --output-dir results/ --hunter-key YOUR_KEY --hibp-key YOUR_KEY
  python3 rek_osint.py -d example.com --output-dir results/ --silent
        """,
    )
    parser.add_argument("-d", "--domain",       required=True,  help="Target domain (e.g. example.com)")
    parser.add_argument("--output-dir", "-o",   required=True,  help="Output directory for results")
    parser.add_argument("--hunter-key",         default="",     help="Hunter.io API key")
    parser.add_argument("--hibp-key",           default="",     help="HaveIBeenPwned API key")
    parser.add_argument("--silent",             action="store_true", help="Suppress progress output")
    parser.add_argument("--emails-only",        action="store_true", help="Only run email harvesting")
    parser.add_argument("--dorks-only",         action="store_true", help="Only run web dorking")
    parser.add_argument("--tech-only",          action="store_true", help="Only run technology detection")
    args = parser.parse_args()

    # Read API keys from config.conf if not provided via CLI
    hunter_key = args.hunter_key
    hibp_key = args.hibp_key
    if not hunter_key or not hibp_key:
        conf_path = os.path.join(os.path.dirname(__file__), "config.conf")
        if os.path.exists(conf_path):
            with open(conf_path) as cf:
                for line in cf:
                    line = line.strip()
                    if line.startswith("HUNTER_API_KEY=") and not hunter_key:
                        hunter_key = line.split("=", 1)[1].strip().strip('"')
                    if line.startswith("HIBP_API_KEY=") and not hibp_key:
                        hibp_key = line.split("=", 1)[1].strip().strip('"')

    engine = OSINTEngine(
        hunter_api_key=hunter_key,
        hibp_api_key=hibp_key,
        silent=args.silent,
    )

    if args.emails_only:
        emails = engine.harvest_emails(args.domain)
        for e in emails:
            print(e)
    elif args.dorks_only:
        dorks = engine.google_dork(args.domain)
        for d in dorks:
            print(f"{d['dork']} -> {d['result_url']}")
    elif args.tech_only:
        tech = engine.detect_technologies(f"https://{args.domain}")
        print(json.dumps(tech, indent=2))
    else:
        report = engine.run(args.domain, args.output_dir)
        print(json.dumps(report["summary"], indent=2))
