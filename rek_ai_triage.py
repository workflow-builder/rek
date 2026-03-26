"""
REK AI-Powered Finding Triage Engine

Reads all result files from a REK scan directory, normalizes findings across
tools, applies a priority scoring model with multipliers, detects multi-step
attack chains, and produces a structured JSON report.

Scoring model:
  base_score   = severity_score (Critical=10, High=8, Medium=5, Low=2, Info=0.5)
  * path_mult  = admin(2x), API(1.3x), auth endpoint(1.5x), file handling(1.4x),
                 parameter with reflection(1.4x), CNAME dangling(3x)
  * corroborat = +20% per additional tool reporting same finding

Output JSON structure:
  {
    "executive_summary": { "total": N, "by_severity": {...} },
    "top_findings": [ <top 10 scored findings> ],
    "attack_paths": [ { "name", "steps", "impact", "score" } ],
    "quick_wins":   [ <high impact + easy to verify findings> ]
  }
"""

import argparse
import csv
import json
import logging
import os
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from termcolor import colored
except ImportError:
    def colored(text, *args, **kwargs):  # type: ignore
        return text

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

SEVERITY_SCORES: Dict[str, float] = {
    "critical":    10.0,
    "high":         8.0,
    "medium":       5.0,
    "low":          2.0,
    "info":         0.5,
    "information":  0.5,
    "unknown":      1.0,
}

# (regex pattern on URL/path, multiplier, label)
PATH_MULTIPLIERS = [
    (r"/admin",                2.0,  "admin path"),
    (r"/api/|/v\d+/|/rest/",  1.3,  "API endpoint"),
    (r"/graphql",              1.3,  "GraphQL endpoint"),
    (r"login|signin|auth",     1.5,  "authentication endpoint"),
    (r"upload|file|attachment", 1.4, "file handling endpoint"),
    (r"password|passwd|pwd",   1.5,  "credential endpoint"),
    (r"\?[a-zA-Z].*=",         1.4,  "parameter present"),
    (r"\.php|\.asp|\.jsp",     1.2,  "dynamic server-side script"),
    (r"CNAME.*dangling|takeover", 3.0, "CNAME dangling / takeover"),
]

# Quick-win criteria: easy to verify + high impact
QUICK_WIN_TYPES = {
    "subdomain takeover",
    "open redirect",
    "cors misconfiguration",
    "debug endpoint",
    "directory listing",
    "exposed admin panel",
    "sensitive file exposure",
    "default credentials",
    "jwt none algorithm",
    "cname dangling",
    "bucket publicly accessible",
    "s3 bucket exposed",
}

# Attack chain detection patterns
ATTACK_CHAIN_PATTERNS = [
    {
        "name":    "Account Takeover Chain",
        "desc":    "Subdomain takeover + Open Redirect + XSS can chain to steal auth tokens",
        "triggers": ["subdomain takeover", "open redirect", "cross-site scripting"],
        "impact":  "Critical — attackers can steal session cookies / OAuth tokens",
        "score":   25.0,
    },
    {
        "name":    "SSRF to Internal Pivot",
        "desc":    "SSRF can be used to reach internal services, cloud metadata, and escalate",
        "triggers": ["server-side request forgery", "ssrf"],
        "impact":  "High — access to internal APIs, AWS metadata service, Kubernetes endpoints",
        "score":   22.0,
    },
    {
        "name":    "SQL Injection to Data Exfiltration",
        "desc":    "SQLi allows DB enumeration, credential theft, and potential OS command execution",
        "triggers": ["sql injection", "sqli"],
        "impact":  "Critical — full database access including user credentials",
        "score":   24.0,
    },
    {
        "name":    "LFI to Remote Code Execution",
        "desc":    "LFI can be leveraged to read source code, logs, and achieve RCE via log poisoning",
        "triggers": ["local file inclusion", "lfi"],
        "impact":  "Critical — may achieve OS-level command execution",
        "score":   23.0,
    },
    {
        "name":    "Exposed Secrets to Full Compromise",
        "desc":    "Leaked credentials or API keys found in GitHub/JS can give full service access",
        "triggers": ["secret", "api key", "credentials", "aws_access_key", "github_token"],
        "impact":  "Critical — direct service access without exploitation needed",
        "score":   26.0,
    },
    {
        "name":    "Cloud Bucket Exposure",
        "desc":    "Publicly readable/writable cloud storage can leak PII and enable supply chain attacks",
        "triggers": ["bucket", "s3", "gcs", "azure blob", "cloud storage"],
        "impact":  "High — data exposure, potential supply chain attack via writable bucket",
        "score":   18.0,
    },
    {
        "name":    "Admin Panel + Default Creds",
        "desc":    "Exposed admin panels with default or weak credentials = instant compromise",
        "triggers": ["admin panel", "exposed admin", "default credentials"],
        "impact":  "Critical — full administrative access to the application",
        "score":   24.0,
    },
]


# ---------------------------------------------------------------------------
# Result file ingestion
# ---------------------------------------------------------------------------

def _normalize_severity(raw: str) -> str:
    raw = raw.strip().lower()
    mapping = {
        "crit":   "critical",
        "critical": "critical",
        "high":   "high",
        "med":    "medium",
        "medium": "medium",
        "low":    "low",
        "info":   "info",
        "information": "info",
        "informational": "info",
        "unknown": "unknown",
        "possible": "medium",
        "vulnerable": "high",
        "confirmed": "high",
    }
    return mapping.get(raw, "unknown")


def _ingest_csv(path: str, tool_name: str) -> List[Dict]:
    """
    Generic CSV ingestion. Attempts to map columns to normalized fields:
      target, url, type, severity, confidence, evidence
    """
    findings: List[Dict] = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                row_lower = {k.lower().strip(): v for k, v in row.items() if k}

                # Map common column names across tools
                url = (
                    row_lower.get("url") or
                    row_lower.get("host") or
                    row_lower.get("subdomain") or
                    row_lower.get("target") or ""
                )
                ftype = (
                    row_lower.get("type") or
                    row_lower.get("vulnerability") or
                    row_lower.get("finding") or
                    row_lower.get("template-id") or
                    row_lower.get("name") or
                    tool_name
                )
                severity_raw = (
                    row_lower.get("severity") or
                    row_lower.get("risk") or
                    row_lower.get("status") or
                    "unknown"
                )
                evidence = (
                    row_lower.get("evidence") or
                    row_lower.get("detail") or
                    row_lower.get("fingerprint") or
                    row_lower.get("match") or
                    row_lower.get("cname") or
                    ""
                )

                if not url:
                    continue

                findings.append({
                    "url":        url,
                    "type":       ftype or tool_name,
                    "severity":   _normalize_severity(severity_raw),
                    "confidence": row_lower.get("confidence", "medium"),
                    "evidence":   str(evidence)[:300],
                    "tool":       tool_name,
                    "source_file": os.path.basename(path),
                })
    except Exception as e:
        logger.debug(f"CSV ingest error {path}: {e}")
    return findings


def _ingest_txt(path: str, tool_name: str) -> List[Dict]:
    """
    Ingest plain text result files (one URL/host per line, or nuclei-style output).
    Lines that look like URLs are treated as informational findings.
    Nuclei-style lines with severity annotations are parsed more richly.
    """
    findings: List[Dict] = []
    nuclei_line = re.compile(
        r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)"
    )
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Nuclei-style: [template-id] [severity] [matcher] URL
                m = nuclei_line.match(line)
                if m:
                    findings.append({
                        "url":        m.group(4),
                        "type":       m.group(1),
                        "severity":   _normalize_severity(m.group(2)),
                        "confidence": "high",
                        "evidence":   m.group(3),
                        "tool":       tool_name,
                        "source_file": os.path.basename(path),
                    })
                    continue

                # Plain URL or hostname
                if line.startswith("http") or re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", line):
                    findings.append({
                        "url":        line,
                        "type":       tool_name,
                        "severity":   "info",
                        "confidence": "high",
                        "evidence":   "",
                        "tool":       tool_name,
                        "source_file": os.path.basename(path),
                    })
    except Exception as e:
        logger.debug(f"TXT ingest error {path}: {e}")
    return findings


def _ingest_json(path: str, tool_name: str) -> List[Dict]:
    """
    Ingest JSON files — handles list of objects or single objects.
    Also handles OSINT report format (osint-report.json) specially.
    """
    findings: List[Dict] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        # Special handling for osint-report.json
        if isinstance(data, dict) and "domain" in data and "emails" in data:
            for email in data.get("emails", []):
                findings.append({
                    "url":        f"mailto:{email}",
                    "type":       "Email Found",
                    "severity":   "info",
                    "confidence": "high",
                    "evidence":   email,
                    "tool":       "osint-engine",
                    "source_file": os.path.basename(path),
                })
            for breach in data.get("breaches", []):
                findings.append({
                    "url":        f"mailto:{breach.get('email', '')}",
                    "type":       "Breached Email",
                    "severity":   "high",
                    "confidence": "high",
                    "evidence":   f"Found in {breach.get('breach_count', 0)} breach(es)",
                    "tool":       "osint-engine",
                    "source_file": os.path.basename(path),
                })
            for dork in data.get("dork_results", []):
                findings.append({
                    "url":        dork.get("result_url", ""),
                    "type":       f"Dork: {dork.get('dork', '')[:60]}",
                    "severity":   "info",
                    "confidence": "medium",
                    "evidence":   dork.get("snippet", "")[:200],
                    "tool":       "osint-engine",
                    "source_file": os.path.basename(path),
                })
            return findings

        # Generic JSON — list of objects
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # Try common list keys
            for key in ("findings", "results", "items", "data", "vulnerabilities"):
                if key in data and isinstance(data[key], list):
                    items = data[key]
                    break
            else:
                items = [data]
        else:
            return findings

        for item in items:
            if not isinstance(item, dict):
                continue
            url = (
                item.get("url") or item.get("host") or
                item.get("target") or item.get("subdomain") or ""
            )
            ftype = (
                item.get("type") or item.get("vulnerability") or
                item.get("template-id") or item.get("name") or tool_name
            )
            sev_raw = (
                item.get("severity") or item.get("risk") or "unknown"
            )
            findings.append({
                "url":        str(url),
                "type":       str(ftype or tool_name),
                "severity":   _normalize_severity(str(sev_raw)),
                "confidence": str(item.get("confidence", "medium")),
                "evidence":   str(item.get("evidence", item.get("detail", "")))[:300],
                "tool":       tool_name,
                "source_file": os.path.basename(path),
            })

    except Exception as e:
        logger.debug(f"JSON ingest error {path}: {e}")
    return findings


# Map file patterns to (tool_name, ingest_function)
FILE_HANDLERS = [
    (re.compile(r"takeover.*\.csv$", re.I),        "takeover-detector",  _ingest_csv),
    (re.compile(r"ai-scan.*\.csv$", re.I),          "ai-scanner",         _ingest_csv),
    (re.compile(r"nuclei.*\.(?:txt|json)$", re.I), "nuclei",             None),  # handled below
    (re.compile(r"gf-.*\.txt$", re.I),             "gf-patterns",        _ingest_txt),
    (re.compile(r"github.dorks.*\.csv$", re.I),    "github-dorking",     _ingest_csv),
    (re.compile(r"cloud.*\.csv$", re.I),           "cloud-recon",        _ingest_csv),
    (re.compile(r"favicon.*\.csv$", re.I),         "favicon-scan",       _ingest_csv),
    (re.compile(r"params.*\.csv$", re.I),          "param-discovery",    _ingest_csv),
    (re.compile(r"headers.*\.csv$", re.I),         "headers-audit",      _ingest_csv),
    (re.compile(r"asn.*\.csv$", re.I),             "asn-recon",          _ingest_csv),
    (re.compile(r"osint-report.*\.json$", re.I),   "osint-engine",       _ingest_json),
    (re.compile(r"triage.*\.json$", re.I),         None,                 None),  # skip self
    (re.compile(r"subdomains.*\.txt$", re.I),      "subdomain-enum",     _ingest_txt),
    (re.compile(r"hosts-alive.*\.txt$", re.I),     "http-probe",         _ingest_txt),
    (re.compile(r"urls.*\.txt$", re.I),            "crawler",            _ingest_txt),
    (re.compile(r"emails?.*\.txt$", re.I),         "email-harvest",      _ingest_txt),
    (re.compile(r".*\.json$", re.I),               "json-finding",       _ingest_json),
    (re.compile(r".*\.csv$", re.I),                "generic-tool",       _ingest_csv),
    (re.compile(r".*\.txt$", re.I),                "generic-output",     _ingest_txt),
]


def _detect_handler(filename: str):
    """Return (tool_name, ingest_fn) for a given filename."""
    for pattern, tool, fn in FILE_HANDLERS:
        if pattern.search(filename):
            if tool is None:
                return None, None  # Skip
            # nuclei files — choose based on extension
            if fn is None and tool == "nuclei":
                ext = os.path.splitext(filename)[1].lower()
                fn = _ingest_json if ext == ".json" else _ingest_txt
            return tool, fn
    return "generic-output", _ingest_txt


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

def _apply_path_multipliers(url: str) -> Tuple[float, List[str]]:
    multiplier = 1.0
    reasons: List[str] = []
    for pattern, mult, label in PATH_MULTIPLIERS:
        if re.search(pattern, url, re.IGNORECASE):
            multiplier *= mult
            reasons.append(label)
    return multiplier, reasons


def score_finding(finding: Dict) -> Tuple[float, List[str]]:
    """
    Compute priority score for a finding.
    Returns (score, [list of scoring reasons]).
    """
    severity = finding.get("severity", "unknown").lower()
    base = SEVERITY_SCORES.get(severity, 1.0)

    url = finding.get("url", "")
    path_mult, reasons = _apply_path_multipliers(url)

    confidence_str = str(finding.get("confidence", "medium")).lower()
    confidence_map = {"high": 1.0, "medium": 0.7, "low": 0.4, "confirmed": 1.0, "possible": 0.5}
    confidence = confidence_map.get(confidence_str, 0.7)

    # Corroboration bonus
    tool_count = finding.get("_tool_count", 1)
    corroboration = 1.0 + 0.2 * (tool_count - 1)

    score = base * path_mult * confidence * corroboration
    return round(min(score, 100.0), 2), reasons


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(findings: List[Dict]) -> List[Dict]:
    """
    Merge findings with the same (url, type) pair.
    Boosts confidence for corroborated findings.
    """
    seen: Dict[str, Dict] = {}

    for f in findings:
        url = f.get("url", "").rstrip("/").lower()
        ftype = f.get("type", "unknown").lower()
        key = f"{url}||{ftype}"

        if key not in seen:
            seen[key] = f.copy()
            seen[key]["_tool_count"] = 1
        else:
            seen[key]["_tool_count"] += 1
            # Promote severity to highest
            old_sev = SEVERITY_SCORES.get(seen[key].get("severity", "unknown"), 1.0)
            new_sev = SEVERITY_SCORES.get(f.get("severity", "unknown"), 1.0)
            if new_sev > old_sev:
                seen[key]["severity"] = f["severity"]
            # Merge tool names
            existing_tool = seen[key].get("tool", "")
            new_tool = f.get("tool", "")
            if new_tool and new_tool not in existing_tool:
                seen[key]["tool"] = f"{existing_tool}+{new_tool}"
            # Promote confidence when corroborated
            if seen[key]["_tool_count"] >= 2:
                if seen[key].get("confidence", "medium") in ("low", "medium"):
                    seen[key]["confidence"] = "high"

    deduped = list(seen.values())
    return deduped


# ---------------------------------------------------------------------------
# Attack chain detection
# ---------------------------------------------------------------------------

def detect_attack_chains(findings: List[Dict]) -> List[Dict]:
    """
    Detect multi-step attack chains from the set of normalized findings.
    Returns list of chain objects sorted by score descending.
    """
    # Build a set of finding types (normalized, lowercase)
    finding_types_lower = {f.get("type", "").lower() for f in findings}
    finding_types_str = " ".join(finding_types_lower)

    chains: List[Dict] = []

    for chain_def in ATTACK_CHAIN_PATTERNS:
        trigger_count = sum(
            1 for trigger in chain_def["triggers"]
            if trigger in finding_types_str
        )
        if trigger_count >= 1:
            # Find specific matching findings to include in chain context
            matching: List[Dict] = []
            for trigger in chain_def["triggers"]:
                for f in findings:
                    if trigger in f.get("type", "").lower():
                        matching.append(f)
                        break

            chain = {
                "name":         chain_def["name"],
                "description":  chain_def["desc"],
                "impact":       chain_def["impact"],
                "score":        chain_def["score"] * (1.0 + 0.1 * (trigger_count - 1)),
                "trigger_count": trigger_count,
                "matched_findings": [
                    {
                        "type":     m.get("type"),
                        "url":      m.get("url"),
                        "severity": m.get("severity"),
                        "tool":     m.get("tool"),
                    }
                    for m in matching[:5]
                ],
                "steps": _generate_chain_steps(chain_def["name"], matching),
            }
            chains.append(chain)

    chains.sort(key=lambda x: x["score"], reverse=True)
    return chains


def _generate_chain_steps(chain_name: str, matching_findings: List[Dict]) -> List[str]:
    """Generate human-readable exploitation steps for a chain."""
    steps_map = {
        "Account Takeover Chain": [
            "1. Identify dangling CNAME subdomain from takeover findings",
            "2. Register the unclaimed service (GitHub Pages, Heroku, etc.) to claim the subdomain",
            "3. Host a malicious page that captures cookies or performs phishing",
            "4. Use open redirect on main domain to redirect victims to the claimed subdomain",
            "5. Combine with XSS to steal active session tokens or perform CSRF",
        ],
        "SSRF to Internal Pivot": [
            "1. Identify SSRF-vulnerable parameter from gf/nuclei findings",
            "2. Probe internal network: http://169.254.169.254 (AWS metadata)",
            "3. Enumerate internal services: http://localhost:PORT for common services",
            "4. Extract cloud credentials from metadata service",
            "5. Use retrieved credentials for lateral movement to other cloud services",
        ],
        "SQL Injection to Data Exfiltration": [
            "1. Confirm SQLi parameter from scan findings",
            "2. Identify DBMS type via error messages or timing attacks",
            "3. Enumerate databases, tables, and columns",
            "4. Extract user credentials table (hashes)",
            "5. Attempt OS command execution via xp_cmdshell (MSSQL) or INTO OUTFILE (MySQL)",
        ],
        "LFI to Remote Code Execution": [
            "1. Confirm LFI in identified parameter",
            "2. Read /etc/passwd, /etc/hosts to confirm file read",
            "3. Read application source code or configuration files for credentials",
            "4. Poison access/error log files by injecting PHP code via User-Agent",
            "5. Include poisoned log file to achieve code execution",
        ],
        "Exposed Secrets to Full Compromise": [
            "1. Extract found credentials/API keys from GitHub/JS findings",
            "2. Validate discovered credentials against live services",
            "3. Escalate access using found AWS/GCP/Azure keys",
            "4. Enumerate accessible cloud resources (S3, EC2, GCS, etc.)",
            "5. Pivot to production databases and internal services",
        ],
        "Cloud Bucket Exposure": [
            "1. Enumerate publicly accessible buckets from cloud recon findings",
            "2. List bucket contents for sensitive files",
            "3. Download credentials, backups, or PII data",
            "4. If writable: test supply chain attack by overwriting JS/assets",
            "5. Report exposed data with proof (file listing, downloaded sample)",
        ],
        "Admin Panel + Default Creds": [
            "1. Access identified admin panel URL",
            "2. Try common default credentials (admin/admin, admin/password, etc.)",
            "3. If credentials work, document full administrative access",
            "4. Enumerate users, configuration, and sensitive data",
            "5. Attempt privilege escalation or remote code execution via admin features",
        ],
    }
    return steps_map.get(chain_name, ["1. Investigate matched findings", "2. Develop exploitation proof-of-concept"])


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _identify_quick_wins(findings: List[Dict]) -> List[Dict]:
    """
    Identify easy-to-verify, high-impact findings (quick wins).
    These are findings where an attacker can immediately verify impact
    without complex exploitation chains.
    """
    quick_wins: List[Dict] = []

    for f in findings:
        ftype_lower = f.get("type", "").lower()
        sev = f.get("severity", "unknown").lower()
        score = f.get("score", 0)

        is_quick_win = False

        # Check against known quick-win types
        for qw_type in QUICK_WIN_TYPES:
            if qw_type in ftype_lower:
                is_quick_win = True
                break

        # High/Critical + high confidence = quick win
        if sev in ("critical", "high") and f.get("confidence", "").lower() == "high":
            is_quick_win = True

        # Very high score findings are worth investigating quickly
        if score >= 15.0:
            is_quick_win = True

        if is_quick_win:
            quick_wins.append(f)

    quick_wins.sort(key=lambda x: x.get("score", 0), reverse=True)
    return quick_wins[:10]  # Top 10 quick wins


# ---------------------------------------------------------------------------
# Main AITriage class
# ---------------------------------------------------------------------------

class AITriage:
    """
    AI-powered finding triage engine.

    Usage:
        triage = AITriage()
        triage.ingest_results("/path/to/scan/results/")
        report = triage.generate_report("/path/to/triage-report.json")
    """

    def __init__(self, silent: bool = False):
        self.silent = silent
        self.raw_findings: List[Dict] = []
        self.scored_findings: List[Dict] = []
        self._ingested = False

    def ingest_results(self, result_dir: str) -> None:
        """
        Walk a scan result directory and ingest all known result file formats.
        Normalizes findings across tools and deduplicates.
        """
        if not os.path.isdir(result_dir):
            print(colored(f"[!] Result directory not found: {result_dir}", "red"))
            return

        raw: List[Dict] = []
        files_processed = 0

        if not self.silent:
            print(colored(f"\n[+] AI Triage: ingesting results from {result_dir}", "blue"))

        for fname in sorted(os.listdir(result_dir)):
            fpath = os.path.join(result_dir, fname)
            if not os.path.isfile(fpath):
                continue

            tool_name, ingest_fn = _detect_handler(fname)
            if tool_name is None or ingest_fn is None:
                continue  # Skip files (e.g., triage output itself)

            try:
                findings = ingest_fn(fpath, tool_name)
                if findings:
                    raw.extend(findings)
                    files_processed += 1
                    if not self.silent:
                        print(colored(
                            f"  [+] {fname}: {len(findings)} findings ({tool_name})",
                            "cyan"
                        ))
            except Exception as e:
                logger.debug(f"Ingest error for {fname}: {e}")

        if not self.silent:
            print(colored(f"\n[+] Ingested {len(raw)} raw findings from {files_processed} files", "green"))

        # Deduplicate
        deduped = _deduplicate(raw)

        # Score all findings
        for f in deduped:
            s, reasons = score_finding(f)
            f["score"] = s
            f["score_reasons"] = reasons

        # Sort by score descending
        deduped.sort(key=lambda x: x.get("score", 0), reverse=True)

        self.raw_findings = raw
        self.scored_findings = deduped
        self._ingested = True

        if not self.silent:
            print(colored(f"[+] After deduplication: {len(deduped)} unique findings", "green"))

    def score_finding(self, finding: Dict) -> float:
        s, _ = score_finding(finding)
        return s

    def detect_attack_chains(self) -> List[Dict]:
        if not self._ingested:
            return []
        return detect_attack_chains(self.scored_findings)

    def generate_report(self, output_file: str) -> Dict:
        """
        Generate the structured triage report and write it to output_file.
        """
        if not self._ingested:
            print(colored("[!] No results ingested. Call ingest_results() first.", "red"))
            return {}

        # Executive summary
        sev_counts: Dict[str, int] = defaultdict(int)
        for f in self.scored_findings:
            sev = f.get("severity", "unknown")
            sev_counts[sev] += 1

        executive_summary = {
            "total_findings":    len(self.scored_findings),
            "raw_findings":      len(self.raw_findings),
            "by_severity":       dict(sev_counts),
            "tools_seen":        sorted({f.get("tool", "?").split("+")[0] for f in self.scored_findings}),
        }

        # Top 10 findings
        top_findings = [
            {k: v for k, v in f.items() if not k.startswith("_")}
            for f in self.scored_findings[:10]
        ]

        # Attack chains
        chains = self.detect_attack_chains()

        # Quick wins
        quick_wins = _identify_quick_wins(self.scored_findings)
        quick_wins_clean = [
            {k: v for k, v in f.items() if not k.startswith("_")}
            for f in quick_wins
        ]

        # Group by host for per-host attack surface
        host_groups: Dict[str, List[Dict]] = defaultdict(list)
        for f in self.scored_findings:
            url = f.get("url", "")
            from urllib.parse import urlparse
            host = urlparse(url).netloc or url.split("/")[0]
            host_groups[host].append(f)

        # Top hosts by cumulative score
        host_scores = {
            host: sum(f.get("score", 0) for f in flist)
            for host, flist in host_groups.items()
            if host
        }
        top_hosts = sorted(host_scores.items(), key=lambda x: x[1], reverse=True)[:10]

        report = {
            "generated_at":      __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
            "executive_summary": executive_summary,
            "top_findings":      top_findings,
            "attack_paths":      chains,
            "quick_wins":        quick_wins_clean,
            "top_hosts":         [{"host": h, "cumulative_score": round(s, 2)} for h, s in top_hosts],
            "all_findings":      [
                {k: v for k, v in f.items() if not k.startswith("_")}
                for f in self.scored_findings
            ],
        }

        # Print summary
        if not self.silent:
            print(colored("\n[+] Triage Report Summary:", "green"))
            print(colored(f"    Total unique findings: {executive_summary['total_findings']}", "white"))
            for sev in ("critical", "high", "medium", "low", "info"):
                count = sev_counts.get(sev, 0)
                if count > 0:
                    sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan"}.get(sev, "white")
                    print(colored(f"    {sev.capitalize():10}: {count}", sev_color))
            print(colored(f"    Attack chains: {len(chains)}", "magenta"))
            print(colored(f"    Quick wins:    {len(quick_wins)}", "yellow"))

            if top_findings:
                print(colored("\n[+] Top 5 prioritized findings:", "blue"))
                for f in top_findings[:5]:
                    sev = f.get("severity", "?").upper()
                    score = f.get("score", 0)
                    url = f.get("url", "?")[:70]
                    print(colored(
                        f"  [{sev}] score={score:.1f} | {f.get('type', '?')[:40]} | {url}",
                        "red" if sev in ("CRITICAL", "HIGH") else "yellow",
                    ))

        # Write report
        try:
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)
            if not self.silent:
                print(colored(f"\n[+] Triage report saved to {output_file}", "green"))
        except Exception as e:
            print(colored(f"[!] Failed to write triage report: {e}", "red"))

        return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="REK AI-Powered Finding Triage Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rek_ai_triage.py --result-dir results/example.com --output results/example.com/triage-report.json
  python3 rek_ai_triage.py --result-dir results/example.com --output triage.json --silent
        """,
    )
    parser.add_argument("--result-dir",  "-r", required=True,  help="Scan result directory to analyze")
    parser.add_argument("--output",      "-o", required=True,  help="Output JSON report path")
    parser.add_argument("--silent",      "-s", action="store_true", help="Suppress progress output")
    parser.add_argument("--top",               type=int, default=10, help="Number of top findings to display (default: 10)")
    args = parser.parse_args()

    triage = AITriage(silent=args.silent)
    triage.ingest_results(args.result_dir)

    if not triage._ingested or not triage.scored_findings:
        print(colored("[!] No findings found in result directory", "yellow"))
        raise SystemExit(0)

    report = triage.generate_report(args.output)

    # Print top-N findings to stdout
    if not args.silent and report.get("top_findings"):
        print(colored(f"\n[+] Top {args.top} findings:", "blue"))
        for f in report["top_findings"][:args.top]:
            sev = f.get("severity", "?").upper()
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "white")
            print(colored(
                f"  [{sev}] score={f.get('score', 0):.1f} | {f.get('type', '?')[:40]} | "
                f"{f.get('url', '?')[:70]} ({f.get('tool', '?')})",
                sev_color,
            ))

    if not args.silent and report.get("attack_paths"):
        print(colored(f"\n[+] Attack Chains Detected:", "magenta"))
        for chain in report["attack_paths"][:5]:
            print(colored(f"  [{chain['score']:.1f}] {chain['name']} — {chain['impact'][:80]}", "magenta"))
