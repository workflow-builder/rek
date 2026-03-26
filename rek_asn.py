"""
REK ASN Recon - Autonomous System Number and IP range discovery
Discovers ASNs for a domain/org and enumerates all associated IP ranges.
Uses BGP/ARIN/RIPEstat APIs (no API key needed for most).
"""
import asyncio
import httpx
import csv
import os
import ipaddress
import socket
import json
from typing import List, Dict, Optional, Set
from termcolor import colored
import logging

logger = logging.getLogger(__name__)

RIPESTAT_ASN_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
RIPESTAT_SEARCH_URL = "https://stat.ripe.net/data/searchcomplete/data.json?resource={query}"
BGPVIEW_ASN_URL = "https://api.bgpview.io/asn/{asn}/prefixes"
BGPVIEW_IP_URL = "https://api.bgpview.io/ip/{ip}"
IPINFO_URL = "https://ipinfo.io/{ip}/json"
HACKTRICKS_AMASS_URL = "https://api.bgpview.io/search?query_term={query}"


class ASNRecon:
    def __init__(self, timeout: int = 15, silent: bool = False):
        self.timeout = timeout
        self.silent = silent
        self.findings: List[Dict] = []

    def resolve_domain_ips(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses."""
        ips = []
        try:
            results = socket.getaddrinfo(domain, None)
            ips = list({r[4][0] for r in results})
        except Exception:
            pass

        # Also try common subdomains
        for sub in ['www', 'api', 'mail']:
            try:
                results = socket.getaddrinfo(f"{sub}.{domain}", None)
                for r in results:
                    ips.append(r[4][0])
            except Exception:
                pass

        return list(set(ips))

    async def get_asn_for_ip(self, client: httpx.AsyncClient, ip: str) -> Optional[Dict]:
        """Get ASN information for an IP address."""
        try:
            r = await client.get(BGPVIEW_IP_URL.format(ip=ip), timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                prefixes = data.get('data', {}).get('prefixes', [])
                if prefixes:
                    p = prefixes[0]
                    asn = p.get('asn', {})
                    return {
                        'ip': ip,
                        'asn': asn.get('asn', ''),
                        'asn_name': asn.get('name', ''),
                        'asn_description': asn.get('description', ''),
                        'prefix': p.get('prefix', ''),
                        'country': asn.get('country_code', ''),
                    }
        except Exception:
            pass

        # Fallback: ipinfo.io
        try:
            r = await client.get(IPINFO_URL.format(ip=ip), timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                org = data.get('org', '')
                asn = org.split(' ')[0] if org else ''
                return {
                    'ip': ip,
                    'asn': asn,
                    'asn_name': ' '.join(org.split(' ')[1:]) if ' ' in org else org,
                    'asn_description': data.get('company', {}).get('name', '') if isinstance(data.get('company'), dict) else '',
                    'prefix': data.get('prefix', ''),
                    'country': data.get('country', ''),
                }
        except Exception:
            pass
        return None

    async def get_prefixes_for_asn(self, client: httpx.AsyncClient, asn: str) -> List[Dict]:
        """Get all IP prefixes for an ASN."""
        prefixes = []
        asn_num = asn.replace('AS', '').replace('as', '').strip()

        # Try BGPView
        try:
            r = await client.get(BGPVIEW_ASN_URL.format(asn=asn_num), timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                for p in data.get('data', {}).get('ipv4_prefixes', []):
                    prefixes.append({
                        'asn': asn,
                        'prefix': p.get('prefix', ''),
                        'ip_version': 'v4',
                        'name': p.get('name', ''),
                        'description': p.get('description', ''),
                        'country': p.get('country_code', ''),
                    })
                for p in data.get('data', {}).get('ipv6_prefixes', []):
                    prefixes.append({
                        'asn': asn,
                        'prefix': p.get('prefix', ''),
                        'ip_version': 'v6',
                        'name': p.get('name', ''),
                        'description': p.get('description', ''),
                        'country': p.get('country_code', ''),
                    })
        except Exception:
            pass

        # Fallback: RIPEstat
        if not prefixes:
            try:
                r = await client.get(RIPESTAT_ASN_URL.format(asn=asn_num), timeout=self.timeout)
                if r.status_code == 200:
                    data = r.json()
                    for p in data.get('data', {}).get('prefixes', []):
                        prefixes.append({
                            'asn': asn,
                            'prefix': p.get('prefix', ''),
                            'ip_version': 'v4' if ':' not in p.get('prefix', '') else 'v6',
                            'name': '',
                            'description': '',
                            'country': '',
                        })
            except Exception:
                pass

        return prefixes

    def count_ips_in_prefix(self, prefix: str) -> int:
        """Count the number of IPs in a CIDR prefix."""
        try:
            network = ipaddress.ip_network(prefix, strict=False)
            return network.num_addresses
        except Exception:
            return 0

    async def search_org_asns(self, client: httpx.AsyncClient, org_query: str) -> List[str]:
        """Search for ASNs belonging to an organization."""
        asns = []
        try:
            r = await client.get(
                HACKTRICKS_AMASS_URL.format(query=org_query),
                timeout=self.timeout
            )
            if r.status_code == 200:
                data = r.json()
                for asn_data in data.get('data', {}).get('asns', []):
                    asn = f"AS{asn_data.get('asn', '')}"
                    if asn not in asns:
                        asns.append(asn)
        except Exception:
            pass
        return asns

    async def run_async(self, domain: str) -> Dict:
        """Run full ASN recon for a domain."""
        results = {
            'domain': domain,
            'ips': [],
            'asns': {},
            'prefixes': [],
            'total_ips': 0,
        }

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # Step 1: Resolve domain to IPs
            ips = self.resolve_domain_ips(domain)
            results['ips'] = ips

            if not self.silent:
                print(colored(f"[*] Resolved {len(ips)} IPs for {domain}: {', '.join(ips[:5])}", "yellow"))

            if not ips:
                return results

            # Step 2: Get ASN for each IP
            asn_info_tasks = [self.get_asn_for_ip(client, ip) for ip in ips]
            asn_results = await asyncio.gather(*asn_info_tasks, return_exceptions=True)

            unique_asns = {}
            for info in asn_results:
                if isinstance(info, dict) and info.get('asn'):
                    asn = info['asn']
                    if asn not in unique_asns:
                        unique_asns[asn] = info
                        if not self.silent:
                            print(colored(f"[+] Found ASN: {asn} ({info.get('asn_name', '')}) for IP {info['ip']}", "green"))

            results['asns'] = unique_asns

            # Step 3: Get all prefixes for each ASN
            prefix_tasks = [self.get_prefixes_for_asn(client, asn) for asn in unique_asns.keys()]
            prefix_results = await asyncio.gather(*prefix_tasks, return_exceptions=True)

            all_prefixes = []
            for plist in prefix_results:
                if isinstance(plist, list):
                    all_prefixes.extend(plist)

            results['prefixes'] = all_prefixes
            results['total_ips'] = sum(self.count_ips_in_prefix(p['prefix']) for p in all_prefixes)

            if not self.silent:
                v4_count = len([p for p in all_prefixes if p.get('ip_version') == 'v4'])
                print(colored(f"[✓] Found {len(all_prefixes)} prefixes ({v4_count} IPv4) across {len(unique_asns)} ASNs", "green"))
                print(colored(f"[*] Total IP space: {results['total_ips']:,} addresses", "cyan"))

                if all_prefixes:
                    print(colored("\n[*] IPv4 Prefixes (CIDR ranges for Shodan/scanning):", "cyan"))
                    for p in sorted(all_prefixes, key=lambda x: x.get('prefix', ''))[:20]:
                        if p.get('ip_version') == 'v4':
                            n = self.count_ips_in_prefix(p['prefix'])
                            print(colored(f"    {p['prefix']} ({n:,} IPs) - {p.get('name', '')} [{p.get('country', '')}]", "yellow"))

        return results

    def run(self, domain: str, output_file: str = None) -> Dict:
        """Run ASN recon."""
        if not self.silent:
            print(colored(f"\n[+] ASN/IP Range Expansion for {domain}...", "blue"))

        results = asyncio.run(self.run_async(domain))
        self.findings = results.get('prefixes', [])

        out = output_file or f"asn_{domain}.csv"
        if results['prefixes']:
            os.makedirs(os.path.dirname(out) if os.path.dirname(out) else '.', exist_ok=True)
            with open(out, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['asn', 'prefix', 'ip_version', 'name', 'description', 'country'])
                writer.writeheader()
                writer.writerows(results['prefixes'])
            if not self.silent:
                print(colored(f"[✓] ASN/prefix data saved to {out}", "green"))

            # Also save CIDR list for tool consumption
            cidr_out = out.replace('.csv', '_cidrs.txt')
            with open(cidr_out, 'w') as f:
                for p in results['prefixes']:
                    if p.get('ip_version') == 'v4':
                        f.write(p['prefix'] + '\n')
            if not self.silent:
                print(colored(f"[✓] IPv4 CIDR ranges saved to {cidr_out}", "green"))

        return results


if __name__ == '__main__':
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else 'example.com'
    recon = ASNRecon()
    recon.run(domain)
