---
name: REK Project Overview
description: Core purpose, architecture, data flows, key files, result directory structure, and UI implementation details for the REK reconnaissance toolkit
type: project
---

REK is a Python-based reconnaissance toolkit for bug bounty hunting and security research.

**Why:** Built for ethical hackers to automate multi-phase recon against target domains.

**How to apply:** All UI work should understand the scan pipeline, result file formats, and job management model.

## Core Modules (rek.py)
- SubdomainScanner: DNS Dumpster, crt.sh, brute-force
- HTTPStatusChecker: Async HTTP probing via httpx
- DirectoryScanner: Directory/file enumeration with Wappalyzer tech detection
- EmailSearcher: Email harvesting from GitHub repos and other sources
- LLMAssistant: Local (Ollama) and remote (OpenAI-compatible) LLM integration
- WordlistGeneratorWrapper: Custom wordlist generation
- ReconTool: Main orchestrator with interactive CLI menu (8 options)

## Playbook Scripts (playbook/)
- v1 (rek-playbook-v1.sh): Full 8-step pipeline -- subfinder, assetfinder, httpx, naabu, gospider, katana, gau, gf patterns, cariddi, nuclei
- v2 (rek-playbook-v2.sh): Streamlined Katana -> HTTPX -> Nuclei pipeline
- standard (rek-playbook.sh): Similar to v1

## Result Directory Structure (from v1 playbook)
```
results/<domain>-<timestamp>/
  subdomains/sorted-subdomains.txt, sorted-subs.txt, subs-alive.txt, subs-portscanned.txt
  probed/httpx-output.txt
  endpoints/spider-output.txt
  urls/katana-output.txt
  vulnerabilities/checkfor-xss.txt, checkfor-sqli.txt, checkfor-ssrf.txt, etc.
  js/js-secrets.txt
  recon-report.md
```

Python module scans output: results.txt, http_results.csv, dirs.csv, email_results.csv

## Web UI (web_ui.py) - Rewritten 2026-03-16
- Single-file Flask app, no external templates, fully offline-capable
- SSE for live log streaming, job stop capability
- Job model: id, domain, scan_type, status, log_path, result_dir, command, pid
- State persisted to ui_runs/jobs.json; logs in ui_runs/logs/
- Tabs: Dashboard, New Scan, Live Terminal, Results, History, LLM Assistant
- Dark terminal theme, responsive, ANSI-aware log colorization
- Port 8080 default

## Removed Files
- ui_app.py: Old HTTP server-based UI (removed 2026-03-16, superseded by web_ui.py)

## Terminal output patterns
Uses termcolor.colored() -- green (success), red (error), yellow (warning), cyan (headers), blue (steps). Playbook scripts use ANSI escape codes.

## Key Dependencies
flask, requests, httpx, dnspython, beautifulsoup4, pandas, selenium, python-wappalyzer, termcolor, aiohttp, tldextract, tqdm
