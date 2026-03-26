---
name: REK Platform Architecture
description: Core architectural patterns, module interfaces, pipeline structure, and tool conventions for the REK reconnaissance platform
type: project
---

## Platform Overview

REK is a full-stack reconnaissance platform at `/Users/jagadeeshvasireddy/Desktop/Projects/rek/`.
Entry points: `rek.py` (CLI), `web_ui.py` (Flask dashboard on port 8080 by default).

## Module Pattern

Every REK Python module follows this pattern:
- Main class (e.g., `GitHubDorker`, `TakeoverDetector`, `ParamDiscovery`) with `silent: bool` parameter
- `run()` method as the primary entry point — reads from file, writes CSV/JSON output
- Async internals via `asyncio.run()` called from sync `run()`
- HTTP via `httpx.AsyncClient` with `verify=False` for scanning contexts
- Output: `colored()` from `termcolor` for terminal feedback
- `if __name__ == '__main__':` CLI entry with `argparse`
- Graceful import pattern in `rek.py`: `try: from rek_X import Y; _X_AVAILABLE = True except ImportError: _X_AVAILABLE = False`

## Module Registry (as of 2026-03-18)

| File | Class | Input | Output | Key feature |
|------|-------|-------|--------|-------------|
| rek.py | SubdomainScanner | domain | subdomains.txt | Main CLI, orchestrates all modules |
| rek_github_dorking.py | GitHubDorker | domain | github_dorks_*.csv | GitHub code search + secret patterns |
| rek_takeover.py | TakeoverDetector | subdomains list/file | takeover.csv | CNAME dangling detection |
| rek_param_discovery.py | ParamDiscovery | URLs file | params_discovered.csv | Reflection-based param detection |
| rek_cloud_recon.py | CloudRecon | domain | cloud*.csv | S3/GCS/Azure bucket enumeration |
| rek_email_search.py | EmailSearcher | domain | emails*.txt | Email harvesting |
| rek_favicon.py | FaviconScanner | hosts file | favicon.csv | MurmurHash3 fingerprinting |
| rek_headers_audit.py | HeadersAuditor | hosts file | headers*.csv | Security header analysis |
| rek_asn.py | ASNRecon | domain | asn.csv | ASN/IP range enumeration |
| rek_scope.py | ScopeManager | domain | scope management | In-scope filtering |
| rek_notify.py | NotificationManager | - | - | Slack/Discord webhooks |
| rek_monitor.py | ContinuousMonitor | - | - | Continuous scanning daemon |
| rek_wordlist_generator.py | REKWordlistGenerator | domain | wordlist | Domain-specific wordlists |
| rek_xbow.py | XBOWScanner | hosts-alive.txt + urls.txt | xbow.csv | XBOW native or nuclei+gf fallback |
| rek_osint.py | OSINTEngine | domain | osint-report.json | Email/tech/breach/dorking |
| rek_ai_triage.py | AITriage | result_dir | triage-report.json | Cross-tool finding prioritization |

## Web UI Structure (web_ui.py ~2427 lines)

- `TOOL_CATALOG` (JS array, line ~1048): builder toolbox items — each has `id`, `label`, `cat`, `color`, `type`, `desc`, `inFile`, `outFile`
- `_TOOL_CMD_TEMPLATES` (Python dict, line ~2273): maps tool IDs to shell command templates using `{D}` (domain), `{O}` (output dir), `{F}` (flags)
- `api_prerequisites()`: checks CLI tools + Python packages; CLI tools list includes xbow, subfinder, httpx, nuclei, gf, etc.
- `api_llm_analyze()`: `action_prompts` dict maps action names to LLM prompt templates
- `renderConfigPanel()` (JS): reads `fields` array of `{k, label}` to build config UI
- Result dirs: `RESULTS_ROOT = ROOT_DIR / "results"`, run state in `RUNS_DIR = ROOT_DIR / "ui_runs"`
- SSE streaming log viewer for real-time scan output
- Intelligence tab: LLM chat with scan context injection; action buttons call `runAction(action)`

## Config System

- `config.conf`: flat KEY="VALUE" format
- Keys: CHAOS_API_KEY, GITHUB_API_TOKEN, GITLAB_API_TOKEN, SHODAN_API_KEY, HIBP_API_KEY, SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL, THREADS, MONITOR_INTERVAL, SCOPE_FILE, OUT_OF_SCOPE_FILE, REK_API_HOST, REK_API_PORT, RATE_LIMIT_MS, NUCLEI_TEMPLATES_PATH, XBOW_API_KEY, HUNTER_API_KEY

## Result File Conventions

Results are stored under `results/{domain}/`:
- `subdomains.txt` — one subdomain per line
- `hosts-alive.txt` — live HTTP(S) hosts (httpx output)
- `urls.txt` — crawled URLs
- `takeover.csv` — columns: subdomain, cname, service, severity, url, status, fingerprint
- `github-dorks.csv` — columns: type, repo, source, match, dork
- `params_discovered.csv` — columns: url, param_count, active_params, passive_params, all_params
- `xbow.csv` — columns: target, url, type, severity, confidence, score, evidence, tool
- `osint-report.json` — structured: domain, emails, technologies, breaches, crt_subdomains, dork_results, summary
- `triage-report.json` — structured: executive_summary, top_findings, attack_paths, quick_wins, all_findings

## Secret Patterns (rek_github_dorking.py)

`SECRET_PATTERNS` dict covers: AWS keys, GitHub tokens, Google API/OAuth, Stripe, Slack, Discord, JWT, private keys, DB connection strings, SSH keys, Azure, Firebase, Vault, and 15+ more services.

## Takeover Fingerprints (rek_takeover.py)

`TAKEOVER_FINGERPRINTS` dict: ~65 cloud services covered including GitHub Pages, Heroku, AWS S3, GCP, Azure, Shopify, Fastly, Netlify, Vercel, Surge, Bitbucket, Zendesk, Freshdesk, Ghost, Pantheon, ReadTheDocs, and more.

## AI Triage Scoring Model (rek_ai_triage.py)

Score = base_severity * path_multipliers * confidence_factor * corroboration_bonus
- Critical=10, High=8, Medium=5, Low=2, Info=0.5
- Admin path: 2x, Auth endpoint: 1.5x, API: 1.3x, File handling: 1.4x, Param present: 1.4x, CNAME dangling: 3x
- Corroboration: +20% per additional tool reporting same (url, type) pair
- 7 attack chain patterns: Account Takeover, SSRF pivot, SQLi, LFI→RCE, Secret exposure, Cloud bucket, Admin+DefaultCreds

**Why:** Core reference for all future development on this platform.
**How to apply:** When adding new modules, follow the class/run()/CLI pattern and register in web_ui.py TOOL_CATALOG + _TOOL_CMD_TEMPLATES.
