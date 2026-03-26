"""
REK AI-Assisted Vulnerability Scanner — nuclei + gf pattern scanning with smart
deduplication and CVSS-like scoring.

Approach:
  1. nuclei with CRITICAL/HIGH severity templates
  2. gf pattern matching (xss, sqli, ssrf, redirect, lfi, rce, ssti, idor, cors, debug)
  3. Python-based deduplication and CVSS-like scoring layer
  4. CSV output with confidence scoring

Output columns: target, url, type, severity, confidence, evidence, tool
"""

import argparse
import asyncio
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Tuple
from termcolor import colored

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring tables
# ---------------------------------------------------------------------------

SEVERITY_SCORES: Dict[str, float] = {
    "critical": 10.0,
    "high":     8.0,
    "medium":   5.0,
    "low":      2.0,
    "info":     0.5,
    "unknown":  1.0,
}

# gf pattern -> (severity, vuln_type)
GF_PATTERN_META: Dict[str, Tuple[str, str]] = {
    "xss":      ("high",     "Cross-Site Scripting"),
    "sqli":     ("high",     "SQL Injection"),
    "ssrf":     ("high",     "Server-Side Request Forgery"),
    "redirect": ("medium",   "Open Redirect"),
    "lfi":      ("high",     "Local File Inclusion"),
    "rce":      ("critical", "Remote Code Execution"),
    "idor":     ("high",     "Insecure Direct Object Reference"),
    "ssti":     ("high",     "Server-Side Template Injection"),
    "debug":    ("medium",   "Debug Endpoint Exposure"),
    "cors":     ("medium",   "CORS Misconfiguration"),
}

# Multipliers applied on top of base severity score
PATH_MULTIPLIERS = [
    (r"/admin",        2.0,  "admin path"),
    (r"/api/",         1.3,  "API endpoint"),
    (r"/graphql",      1.3,  "GraphQL endpoint"),
    (r"\?.*=",         1.4,  "parameter with reflection potential"),
    (r"\.php",         1.2,  "PHP endpoint"),
    (r"\.jsp",         1.2,  "JSP endpoint"),
    (r"\.aspx?",       1.2,  "ASP endpoint"),
    (r"login|signin",  1.5,  "authentication endpoint"),
    (r"upload|file",   1.4,  "file handling endpoint"),
    (r"password|passwd|pwd", 1.5, "credential endpoint"),
]

# Nuclei severity flags to run
NUCLEI_SEVERITIES = "critical,high,medium"

# GF patterns to run (ordered by impact)
GF_PATTERNS = ["rce", "sqli", "ssrf", "lfi", "xss", "ssti", "redirect", "idor", "cors", "debug"]


def _run_cmd(cmd: List[str], timeout: int = 120, silent: bool = False) -> Tuple[int, str, str]:
    """Run a subprocess command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        if not silent:
            print(colored(f"[!] Command timed out: {' '.join(cmd[:3])}", "yellow"))
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", f"command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _apply_path_multipliers(url: str) -> Tuple[float, List[str]]:
    """
    Examine a URL path and return the combined multiplier and reasons.
    Multipliers are multiplicative — admin API endpoint gets 2.0 * 1.3 = 2.6x.
    """
    multiplier = 1.0
    reasons: List[str] = []
    for pattern, mult, reason in PATH_MULTIPLIERS:
        if re.search(pattern, url, re.IGNORECASE):
            multiplier *= mult
            reasons.append(reason)
    return multiplier, reasons


def _score_finding(finding: Dict) -> float:
    """
    Compute a CVSS-like priority score for a finding.

    Score = base_severity_score * path_multipliers * tool_confidence_multiplier
    """
    severity = finding.get("severity", "unknown").lower()
    base = SEVERITY_SCORES.get(severity, 1.0)

    url = finding.get("url", "")
    path_mult, _ = _apply_path_multipliers(url)

    # Confidence expressed as 0.0–1.0 — tools report "high", "medium", "low"
    confidence_str = str(finding.get("confidence", "medium")).lower()
    confidence_map = {"high": 1.0, "medium": 0.7, "low": 0.4}
    confidence = confidence_map.get(confidence_str, 0.7)

    score = base * path_mult * confidence
    return round(min(score, 100.0), 2)


# ---------------------------------------------------------------------------
# Native scanner integration (placeholder for future tool support)
# ---------------------------------------------------------------------------

def is_native_scanner_available() -> bool:
    """
    Check whether a supported native AI scanner binary is on PATH.
    Currently always returns False — the nuclei+gf pipeline is the primary engine.
    Override this function to add support for future AI scanner integrations.
    """
    return False


def _parse_native_output(raw: str, target: str) -> List[Dict]:
    """
    Parse JSON-lines or plain-text output from a native scanner into normalized
    finding dicts. Handles both JSON and human-readable lines gracefully.
    """
    findings: List[Dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            findings.append({
                "target":     target,
                "url":        obj.get("url", obj.get("target", target)),
                "type":       obj.get("type", obj.get("vulnerability", "unknown")),
                "severity":   obj.get("severity", "unknown").lower(),
                "confidence": obj.get("confidence", "medium"),
                "evidence":   obj.get("evidence", obj.get("detail", ""))[:300],
                "tool":       "native-scanner",
            })
        except json.JSONDecodeError:
            # Plain text line that looks like a finding
            if any(k in line.lower() for k in ["vuln", "found", "critical", "high", "medium", "low"]):
                findings.append({
                    "target":     target,
                    "url":        target,
                    "type":       "ai-scanner-finding",
                    "severity":   _extract_severity_from_text(line),
                    "confidence": "medium",
                    "evidence":   line[:300],
                    "tool":       "native-scanner",
                })
    return findings


def _extract_severity_from_text(text: str) -> str:
    """Extract severity keyword from a free-text line."""
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in text.lower():
            return sev
    return "unknown"


def run_native_scan(targets: List[str], output_file: str, silent: bool = False) -> List[Dict]:
    """
    Placeholder entry point for native scanner execution.

    Extend this function to integrate any AI-assisted scanner that accepts a
    target URL and emits JSON-lines output. Results are aggregated and enriched
    with CVSS-like scores.
    """
    if not silent:
        print(colored(f"\n[+] Native AI scan on {len(targets)} targets...", "blue"))

    all_findings: List[Dict] = []

    # Enrich with scores
    for f in all_findings:
        f["score"] = _score_finding(f)

    all_findings.sort(key=lambda x: x.get("score", 0), reverse=True)
    return all_findings


# ---------------------------------------------------------------------------
# AI-Assisted engine (nuclei + gf)
# ---------------------------------------------------------------------------

def _run_nuclei(targets_file: str, output_dir: str, silent: bool = False) -> List[Dict]:
    """
    Run nuclei against live hosts with CRITICAL/HIGH/MEDIUM severity filter.
    Parses nuclei JSON output lines.
    """
    if not shutil.which("nuclei"):
        if not silent:
            print(colored("[!] nuclei not installed — skipping nuclei scan", "yellow"))
        return []

    nuclei_out = os.path.join(output_dir, "nuclei-ai-assisted.json")
    cmd = [
        "nuclei",
        "-l", targets_file,
        "-severity", NUCLEI_SEVERITIES,
        "-json",
        "-o", nuclei_out,
        "-silent",
        "-retries", "1",
        "-timeout", "10",
        "-rate-limit", "50",
    ]

    if not silent:
        print(colored(f"  [*] Running nuclei (severities: {NUCLEI_SEVERITIES})...", "cyan"))

    rc, stdout, stderr = _run_cmd(cmd, timeout=600, silent=silent)
    findings: List[Dict] = []

    # Parse JSON output file if it exists
    if os.path.exists(nuclei_out):
        try:
            with open(nuclei_out) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        host = obj.get("host", obj.get("url", ""))
                        info = obj.get("info", {})
                        findings.append({
                            "target":     host.split("/")[0] if "://" not in host else host.split("/")[2],
                            "url":        host,
                            "type":       obj.get("template-id", info.get("name", "nuclei-finding")),
                            "severity":   info.get("severity", "unknown").lower(),
                            "confidence": "high",  # nuclei template matches are high confidence
                            "evidence":   (obj.get("matched-at") or obj.get("matcher-name") or "")[:300],
                            "tool":       "nuclei",
                        })
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            if not silent:
                logger.debug(f"nuclei output parse error: {e}")

    if not silent:
        print(colored(f"  [+] nuclei: {len(findings)} findings", "green" if findings else "yellow"))

    return findings


def _run_gf_patterns(urls_file: str, output_dir: str, silent: bool = False) -> List[Dict]:
    """
    Run gf patterns against a URLs file and return structured findings.
    gf filters URLs that match known vulnerability patterns.
    """
    if not shutil.which("gf"):
        if not silent:
            print(colored("[!] gf not installed — skipping gf pattern matching", "yellow"))
        return []

    findings: List[Dict] = []

    for pattern in GF_PATTERNS:
        pattern_out = os.path.join(output_dir, f"gf-{pattern}.txt")
        cmd = ["gf", pattern]
        if not silent:
            print(colored(f"  [*] gf pattern: {pattern}", "cyan"))

        try:
            with open(urls_file) as urls_f:
                result = subprocess.run(
                    cmd,
                    stdin=urls_f,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            matched_urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]

            # Write gf output to file
            if matched_urls:
                with open(pattern_out, "w") as f:
                    f.write("\n".join(matched_urls) + "\n")

            meta = GF_PATTERN_META.get(pattern, ("medium", pattern.upper()))
            for url in matched_urls:
                findings.append({
                    "target":     url.split("/")[2] if "://" in url else url.split("/")[0],
                    "url":        url,
                    "type":       meta[1],
                    "severity":   meta[0],
                    "confidence": "medium",  # gf matches need manual verification
                    "evidence":   f"gf pattern '{pattern}' matched URL",
                    "tool":       "gf",
                })

        except subprocess.TimeoutExpired:
            if not silent:
                print(colored(f"  [!] gf pattern '{pattern}' timed out", "yellow"))
        except FileNotFoundError:
            if not silent:
                print(colored("[!] gf binary not found", "yellow"))
            break
        except Exception as e:
            if not silent:
                logger.debug(f"gf pattern {pattern} error: {e}")

    if not silent:
        print(colored(f"  [+] gf: {len(findings)} URL pattern matches", "green" if findings else "yellow"))

    return findings


def _deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Deduplicate findings by (url, type) pair.
    When multiple tools report the same finding, keep the highest-confidence one
    and boost its confidence score to reflect corroboration.
    """
    seen: Dict[str, Dict] = {}

    for f in findings:
        # Normalize URL (strip trailing slashes, lowercase host)
        url = f.get("url", "").rstrip("/")
        ftype = f.get("type", "unknown").lower()
        key = f"{url}||{ftype}"

        if key not in seen:
            seen[key] = f.copy()
            seen[key]["_tool_count"] = 1
        else:
            seen[key]["_tool_count"] += 1
            # Promote confidence when corroborated by multiple tools
            existing_conf = str(seen[key].get("confidence", "medium")).lower()
            if existing_conf == "medium":
                seen[key]["confidence"] = "high"
            # Keep higher severity
            existing_sev = SEVERITY_SCORES.get(seen[key].get("severity", "unknown").lower(), 1.0)
            new_sev = SEVERITY_SCORES.get(f.get("severity", "unknown").lower(), 1.0)
            if new_sev > existing_sev:
                seen[key]["severity"] = f["severity"]
            # Merge tool attribution
            seen[key]["tool"] = f"{seen[key]['tool']}+{f['tool']}"

    deduped = list(seen.values())
    # Apply corroboration bonus: +20% score per extra tool
    for f in deduped:
        tool_count = f.pop("_tool_count", 1)
        f["score"] = _score_finding(f) * (1.0 + 0.2 * (tool_count - 1))
        f["score"] = round(min(f["score"], 100.0), 2)

    deduped.sort(key=lambda x: x.get("score", 0), reverse=True)
    return deduped


def run_ai_assisted_scan(
    targets: List[str],
    urls: List[str],
    output_file: str,
    silent: bool = False,
) -> List[Dict]:
    """
    AI-assisted scan using nuclei + gf + smart scoring.

    targets: list of live hostnames/IPs (from hosts-alive.txt)
    urls:    list of crawled URLs (from urls.txt)
    output_file: path for final CSV output
    """
    if not silent:
        print(colored("\n[*] Running AI-assisted scan (nuclei + gf)...", "cyan"))

    output_dir = os.path.dirname(os.path.abspath(output_file)) or "."
    os.makedirs(output_dir, exist_ok=True)

    all_findings: List[Dict] = []

    # Write targets to temp file for nuclei
    targets_file = os.path.join(output_dir, "_ai_targets_tmp.txt")
    with open(targets_file, "w") as f:
        for t in targets:
            if not t.startswith("http"):
                f.write(f"https://{t}\n")
            else:
                f.write(f"{t}\n")

    # Write URLs to temp file for gf
    urls_file = os.path.join(output_dir, "_ai_urls_tmp.txt")
    with open(urls_file, "w") as f:
        f.write("\n".join(urls) + "\n")

    # Run nuclei
    nuclei_findings = _run_nuclei(targets_file, output_dir, silent=silent)
    all_findings.extend(nuclei_findings)

    # Run gf patterns (only if we have URLs to work with)
    if urls:
        gf_findings = _run_gf_patterns(urls_file, output_dir, silent=silent)
        all_findings.extend(gf_findings)
    elif not silent:
        print(colored("  [!] No URLs provided — skipping gf pattern scan", "yellow"))

    # Clean up temp files
    for tmp in [targets_file, urls_file]:
        try:
            os.remove(tmp)
        except Exception:
            pass

    # Deduplicate and score
    deduped = _deduplicate_findings(all_findings)

    if not silent:
        sev_counts: Dict[str, int] = {}
        for f in deduped:
            sev = f.get("severity", "unknown")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        sev_str = ", ".join(f"{v} {k}" for k, v in sorted(sev_counts.items()))
        print(colored(f"\n[+] AI-assisted scan: {len(deduped)} unique findings ({sev_str})", "green"))

    return deduped


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class AIVulnScanner:
    """
    Unified AI-assisted vulnerability scanner.

    Runs nuclei + gf pattern pipeline with smart deduplication and CVSS-like
    priority scoring. Designed to be extended with additional scanner integrations.
    """

    def __init__(self, silent: bool = False, timeout: int = 300):
        self.silent = silent
        self.timeout = timeout
        self.findings: List[Dict] = []

    def is_native_scanner_available(self) -> bool:
        return is_native_scanner_available()

    def run_native_scan(self, targets: List[str], output_file: str) -> List[Dict]:
        return run_native_scan(targets, output_file, silent=self.silent)

    def run_ai_assisted_scan(
        self,
        targets: List[str],
        urls: List[str],
        output_file: str,
    ) -> List[Dict]:
        return run_ai_assisted_scan(targets, urls, output_file, silent=self.silent)

    def run(self, input_file: str, urls_file: str, output_file: str) -> List[Dict]:
        """
        Main entry point.

        Reads targets from input_file (hosts-alive.txt) and URLs from urls_file.
        Always uses the nuclei+gf AI-assisted pipeline.
        Writes results to output_file (CSV).
        """
        # Load targets
        targets: List[str] = []
        if input_file and os.path.exists(input_file):
            try:
                with open(input_file) as f:
                    targets = [ln.strip() for ln in f if ln.strip()]
            except Exception as e:
                print(colored(f"[!] Failed to read targets file: {e}", "red"))

        # Load URLs
        urls: List[str] = []
        if urls_file and os.path.exists(urls_file):
            try:
                with open(urls_file) as f:
                    urls = [ln.strip() for ln in f if ln.strip() and ln.strip().startswith("http")]
            except Exception as e:
                if not self.silent:
                    print(colored(f"[!] Failed to read URLs file: {e}", "yellow"))

        if not targets and not urls:
            print(colored("[!] No targets or URLs provided", "red"))
            return []

        if not self.silent:
            print(colored(f"\n[+] AI Scanner: {len(targets)} hosts, {len(urls)} URLs", "blue"))

        findings = self.run_ai_assisted_scan(targets, urls, output_file)
        self.findings = findings

        # Write CSV output
        if findings:
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            fieldnames = ["target", "url", "type", "severity", "confidence", "score", "evidence", "tool"]
            try:
                with open(output_file, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(findings)
                if not self.silent:
                    print(colored(f"[+] Results saved to {output_file}", "green"))
            except Exception as e:
                print(colored(f"[!] Failed to write output: {e}", "red"))

        return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="REK AI-Assisted Vulnerability Scanner — nuclei + gf pattern scanning with smart deduplication and CVSS-like scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rek_ai_scanner.py --input results/example.com/hosts-alive.txt --urls results/example.com/urls.txt --output results/example.com/ai-scan.csv
  python3 rek_ai_scanner.py --input hosts.txt --output ai-scan.csv --silent
        """,
    )
    parser.add_argument("--input",   "-i", required=True,  help="Path to hosts-alive.txt")
    parser.add_argument("--urls",    "-u", default="",     help="Path to urls.txt (for gf patterns)")
    parser.add_argument("--output",  "-o", required=True,  help="Output CSV path")
    parser.add_argument("--silent",  "-s", action="store_true", help="Suppress progress output")
    parser.add_argument("--check",         action="store_true", help="Check scanner availability")
    args = parser.parse_args()

    if args.check:
        if is_native_scanner_available():
            print(colored("[+] Native AI scanner is available", "green"))
        else:
            print(colored("[*] No native AI scanner detected — nuclei+gf pipeline will be used", "cyan"))
        raise SystemExit(0)

    scanner = AIVulnScanner(silent=args.silent)
    results = scanner.run(
        input_file=args.input,
        urls_file=args.urls or "",
        output_file=args.output,
    )

    if results:
        # Print top 5 findings to stdout
        print(colored(f"\n[+] Top findings (score descending):", "blue"))
        for r in results[:5]:
            sev = r.get("severity", "?").upper()
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "white")
            print(colored(
                f"  [{sev}] score={r.get('score', 0):.1f} | {r.get('type', '?')} | {r.get('url', '?')[:80]}",
                sev_color,
            ))
