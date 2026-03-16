#!/usr/bin/env python3
"""
REK Web UI -- Production-quality reconnaissance dashboard.

A self-contained Flask application that wraps the REK toolkit with:
  - Dashboard with summary metrics and quick-links
  - Scan launcher (playbooks + individual Python modules)
  - Real-time streaming log viewer via Server-Sent Events
  - Structured results explorer with parsed CSV/TXT/MD/JSON display
  - Per-scan result pages with tabbed sections
  - Scan history with status, stats, and links
  - LLM assistant chat interface

Run:
    python3 web_ui.py [--port 8080] [--host 0.0.0.0]

Dependencies (already in requirements.txt):
    pip install flask
"""

from __future__ import annotations

import argparse
import csv
import html as html_mod
import io
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Flask setup
# ---------------------------------------------------------------------------
try:
    from flask import (
        Flask,
        Response,
        jsonify,
        redirect,
        render_template_string,
        request,
        url_for,
    )
except ImportError:
    print("Flask is required. Install it with:  pip install flask")
    sys.exit(1)

ROOT_DIR = Path(__file__).resolve().parent
RUNS_DIR = ROOT_DIR / "ui_runs"
LOGS_DIR = RUNS_DIR / "logs"
STATE_FILE = RUNS_DIR / "jobs.json"
RESULTS_ROOT = ROOT_DIR / "results"

RUNS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

PLAYBOOKS = {
    "v1": ROOT_DIR / "playbook" / "rek-playbook-v1.sh",
    "v2": ROOT_DIR / "playbook" / "rek-playbook-v2.sh",
    "standard": ROOT_DIR / "playbook" / "rek-playbook.sh",
}

SCAN_MODULES = ["subdomain", "http", "directory", "email"]

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Job model & persistence
# ---------------------------------------------------------------------------


@dataclass
class Job:
    id: str
    domain: str
    scan_type: str  # playbook-v1, playbook-v2, subdomain, http, directory, email, install-*
    status: str = "queued"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    log_path: str = ""
    result_dir: str = ""
    command: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    return_code: Optional[int] = None
    pid: Optional[int] = None
    # If set, this job will be started automatically after `depends_on` job succeeds
    depends_on: Optional[str] = None


_jobs: Dict[str, Job] = {}
_lock = threading.Lock()
_sse_subscribers: Dict[str, list] = {}
_processes: Dict[str, subprocess.Popen] = {}

# ---------------------------------------------------------------------------
# Prerequisite tool requirements per playbook
# ---------------------------------------------------------------------------

_PLAYBOOK_TOOLS: Dict[str, List[str]] = {
    "v2":       ["katana", "httpx", "nuclei"],
    "v1":       ["subfinder", "httpx", "naabu", "nuclei", "gospider", "gau", "puredns", "gotator", "gf"],
    "standard": ["subfinder", "httpx", "naabu", "nuclei", "gospider", "gau", "puredns", "gotator", "gf"],
}

_INSTALL_SCRIPTS: Dict[str, Path] = {
    "v2":       ROOT_DIR / "playbook" / "install-script-v2.sh",
    "v1":       ROOT_DIR / "playbook" / "install-script-v1.sh",
    "standard": ROOT_DIR / "playbook" / "install-script.sh",
}


def _missing_tools(playbook: str) -> List[str]:
    """Return list of CLI tools required by *playbook* that are not on PATH."""
    import shutil
    tools_dir = str(ROOT_DIR / "tools")
    go_bin = os.path.expanduser("~/go/bin")
    search_path = f"{tools_dir}:{go_bin}:{os.environ.get('PATH', '')}"
    return [
        t for t in _PLAYBOOK_TOOLS.get(playbook, [])
        if not shutil.which(t, path=search_path)
    ]


def _ensure_config_file() -> None:
    """Create config.conf with safe defaults so install scripts skip interactive prompts."""
    config_path = ROOT_DIR / "config.conf"
    if config_path.exists():
        return
    config_path.write_text(
        'CHAOS_API_KEY=""\n'
        'GITHUB_API_TOKEN=""\n'
        'GITLAB_API_TOKEN=""\n'
        'THREADS="100"\n'
        'RATE_LIMIT="25"\n',
        encoding="utf-8",
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _save_state() -> None:
    with _lock:
        data = []
        for j in _jobs.values():
            d = asdict(j)
            d.pop("pid", None)
            data.append(d)
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_state() -> None:
    if not STATE_FILE.exists():
        return
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        for row in data:
            if "scan_type" not in row and "playbook" in row:
                row["scan_type"] = f"playbook-{row.pop('playbook')}"
            if "threads" in row and "options" not in row:
                row["options"] = {"threads": row.pop("threads")}
            elif "threads" in row:
                row.pop("threads", None)
            row.pop("pid", None)
            known = {f.name for f in Job.__dataclass_fields__.values()}
            row = {k: v for k, v in row.items() if k in known}
            job = Job(**row)
            # Mark previously-running jobs as failed on restart
            if job.status in ("running", "queued"):
                job.status = "failed"
                job.return_code = -9
                if not job.ended_at:
                    job.ended_at = _now()
            _jobs[job.id] = job
    except Exception:
        pass


def _sorted_jobs() -> List[Job]:
    with _lock:
        return sorted(_jobs.values(), key=lambda j: j.created_at, reverse=True)


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------


def _broadcast_sse(job_id: str, data: str, event: str = "log") -> None:
    subs = _sse_subscribers.get(job_id, [])
    dead = []
    for i, q in enumerate(subs):
        try:
            q.put_nowait((event, data))
        except Exception:
            dead.append(i)
    for i in reversed(dead):
        subs.pop(i)


def _run_job(job_id: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = _now()
    _save_state()
    _broadcast_sse(
        job_id, json.dumps({"status": "running"}), "status"
    )

    log_path = Path(job.log_path)
    code = -1
    with log_path.open("a", encoding="utf-8") as log_file:
        header = f"[{_now()}] Starting: {' '.join(job.command)}\n"
        log_file.write(header)
        log_file.flush()
        _broadcast_sse(job_id, header)

        try:
            extra_env = job.options.get("_env") or {}
            process = subprocess.Popen(
                job.command,
                cwd=str(ROOT_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=_build_env(extra_env),
            )
            with _lock:
                _processes[job_id] = process
                if job_id in _jobs:
                    _jobs[job_id].pid = process.pid

            if process.stdout:
                for line in process.stdout:
                    log_file.write(line)
                    log_file.flush()
                    _broadcast_sse(job_id, line.rstrip("\n"))

            code = process.wait()
        except Exception as exc:
            code = -1
            err_msg = f"[ERROR] {exc}\n"
            log_file.write(err_msg)
            _broadcast_sse(job_id, err_msg)
        finally:
            with _lock:
                _processes.pop(job_id, None)

        ended = _now()
        with _lock:
            current = _jobs.get(job_id)
            if current:
                current.status = "completed" if code == 0 else "failed"
                current.return_code = code
                current.ended_at = ended
                current.pid = None

        footer = f"\n[{ended}] Finished with exit code {code}.\n"
        log_file.write(footer)
        log_file.flush()
        _broadcast_sse(job_id, footer)

    _save_state()
    _broadcast_sse(
        job_id,
        json.dumps(
            {"status": "completed" if code == 0 else "failed", "code": code}
        ),
        "status",
    )

    # Start any jobs that were waiting on this one to succeed
    if code == 0:
        with _lock:
            waiting = [
                j for j in _jobs.values()
                if j.depends_on == job_id and j.status == "queued"
            ]
        for dep_job in waiting:
            _broadcast_sse(
                dep_job.id,
                f"[REK] Prerequisites installed. Starting scan for {dep_job.domain}...\n",
            )
            threading.Thread(target=_run_job, args=(dep_job.id,), daemon=True).start()
    else:
        # Cancel any jobs waiting on a failed install
        with _lock:
            waiting = [
                j for j in _jobs.values()
                if j.depends_on == job_id and j.status == "queued"
            ]
        for dep_job in waiting:
            dep_job.status = "failed"
            dep_job.return_code = -1
            dep_job.ended_at = _now()
        if waiting:
            _save_state()


def _build_env(extra: Optional[Dict] = None) -> dict:
    env = os.environ.copy()
    tools_dir = str(ROOT_DIR / "tools")
    go_bin = os.path.expanduser("~/go/bin")
    env["PATH"] = f"{tools_dir}:{go_bin}:{env.get('PATH', '')}"
    env["RECON_TOOLKIT_DIR"] = str(ROOT_DIR)
    env["TOOLS_DIR"] = tools_dir
    env["CONFIG_PATH"] = str(ROOT_DIR / "config.conf")
    env["WORDLISTS_DIR"] = str(ROOT_DIR / "wordlists")
    if extra:
        env.update(extra)
    return env


def _create_and_start_job(
    domain: str,
    scan_type: str,
    command: List[str],
    options: Optional[Dict] = None,
    result_dir: Optional[Path] = None,
    depends_on: Optional[str] = None,
) -> Job:
    job_id = uuid.uuid4().hex[:8]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if result_dir is None:
        result_dir = RESULTS_ROOT / f"ui-{domain.replace('.', '_')}-{ts}"
    result_dir.mkdir(parents=True, exist_ok=True)
    log_path = LOGS_DIR / f"{job_id}.log"

    job = Job(
        id=job_id,
        domain=domain,
        scan_type=scan_type,
        log_path=str(log_path),
        result_dir=str(result_dir.relative_to(ROOT_DIR)),
        command=command,
        options=options or {},
        depends_on=depends_on,
    )
    with _lock:
        _jobs[job.id] = job
    _save_state()
    # Only start immediately if not waiting on another job
    if depends_on is None:
        threading.Thread(target=_run_job, args=(job.id,), daemon=True).start()
    return job


def _stop_job(job_id: str) -> bool:
    with _lock:
        proc = _processes.get(job_id)
        job = _jobs.get(job_id)
    if proc and job and job.status == "running":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            try:
                proc.terminate()
            except Exception:
                pass
        with _lock:
            if job_id in _jobs:
                _jobs[job_id].status = "failed"
                _jobs[job_id].return_code = -15
                _jobs[job_id].ended_at = _now()
        _save_state()
        _broadcast_sse(
            job_id,
            json.dumps({"status": "failed", "code": -15}),
            "status",
        )
        return True
    return False


# ---------------------------------------------------------------------------
# Result discovery & parsing helpers
# ---------------------------------------------------------------------------


def _discover_result_dirs() -> List[dict]:
    if not RESULTS_ROOT.exists():
        return []
    dirs = []
    for rd in sorted(
        [p for p in RESULTS_ROOT.iterdir() if p.is_dir()], reverse=True
    ):
        files = []
        for f in sorted(rd.rglob("*")):
            if f.is_file() and f.suffix.lower() in {
                ".txt", ".csv", ".md", ".json", ".log", ".html",
            }:
                files.append(
                    {
                        "name": str(f.relative_to(rd)),
                        "path": str(f.relative_to(ROOT_DIR)),
                        "abs_path": str(f),
                        "size": f.stat().st_size,
                        "ext": f.suffix.lower(),
                    }
                )
        dirs.append(
            {
                "name": rd.name,
                "files": files,
                "path": str(rd.relative_to(ROOT_DIR)),
            }
        )
    return dirs


def _parse_csv_file(filepath: str) -> Optional[Dict]:
    try:
        p = Path(filepath) if os.path.isabs(filepath) else ROOT_DIR / filepath
        if not p.exists():
            return None
        with p.open("r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            rows = list(reader)
        if not rows:
            return None
        return {"headers": rows[0], "rows": rows[1:], "total": len(rows) - 1}
    except Exception:
        return None


def _read_text_file(filepath: str, max_lines: int = 2000) -> str:
    try:
        p = Path(filepath) if os.path.isabs(filepath) else ROOT_DIR / filepath
        if not p.exists():
            return ""
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[:max_lines])
    except Exception:
        return ""


def _count_lines(fp: Path) -> int:
    if fp.exists():
        return sum(
            1
            for line in fp.read_text(errors="replace").splitlines()
            if line.strip()
        )
    return 0


def _build_scan_summary(result_dir_rel: str) -> Dict:
    rd = ROOT_DIR / result_dir_rel
    summary: Dict[str, Any] = {
        "subdomains": 0,
        "live_hosts": 0,
        "endpoints": 0,
        "vulnerabilities": {},
        "ports": 0,
        "js_secrets": 0,
        "emails": 0,
        "has_report": False,
    }

    # Subdomains
    for name in [
        "subdomains/sorted-subs.txt",
        "subdomains/sorted-subdomains.txt",
        "results.txt",
    ]:
        c = _count_lines(rd / name)
        if c:
            summary["subdomains"] = max(summary["subdomains"], c)

    # Live hosts
    for name in [
        "subdomains/subs-alive.txt",
        "probed/httpx-output.txt",
        "http_results.csv",
    ]:
        c = _count_lines(rd / name)
        if c:
            summary["live_hosts"] = max(summary["live_hosts"], c)

    # Endpoints
    for name in ["endpoints/spider-output.txt", "urls/katana-output.txt"]:
        c = _count_lines(rd / name)
        if c:
            summary["endpoints"] = max(summary["endpoints"], c)

    # Port scan
    summary["ports"] = _count_lines(rd / "subdomains/subs-portscanned.txt")

    # Vulnerabilities
    vuln_dir = rd / "vulnerabilities"
    if vuln_dir.exists():
        for vf in vuln_dir.glob("checkfor-*.txt"):
            vtype = vf.stem.replace("checkfor-", "").upper()
            cnt = _count_lines(vf)
            if cnt > 0:
                summary["vulnerabilities"][vtype] = cnt

    # JS secrets
    summary["js_secrets"] = _count_lines(rd / "js/js-secrets.txt")

    # Emails
    for name in ["email_results.csv", "results_emails.csv"]:
        c = _count_lines(rd / name)
        if c > 1:
            summary["emails"] = max(summary["emails"], c - 1)

    # Report
    for name in ["recon-report.md"]:
        if (rd / name).exists():
            summary["has_report"] = True

    return summary


def _find_subdomain_results(domain: str) -> Optional[str]:
    """Return path to the most recent subdomain results file for a domain, or None."""
    if not RESULTS_ROOT.exists():
        return None
    domain_slug = domain.replace(".", "_")
    candidates = []
    for rd in RESULTS_ROOT.iterdir():
        if not rd.is_dir():
            continue
        if domain_slug not in rd.name and domain not in rd.name:
            continue
        for fname in ["results.txt", "subdomains/sorted-subs.txt", "subdomains/sorted-subdomains.txt"]:
            fp = rd / fname
            if fp.exists() and fp.stat().st_size > 0:
                candidates.append((fp.stat().st_mtime, str(fp)))
    if candidates:
        candidates.sort(reverse=True)
        return candidates[0][1]
    return None


def _create_install_job(playbook: str, domain: str) -> Job:
    """Create and immediately start an install job for the given playbook variant."""
    _ensure_config_file()
    script = _INSTALL_SCRIPTS[playbook]
    job_id = uuid.uuid4().hex[:8]
    log_path = LOGS_DIR / f"{job_id}.log"
    # Install jobs don't produce a results directory
    install_dir = RUNS_DIR / "installs"
    install_dir.mkdir(exist_ok=True)

    job = Job(
        id=job_id,
        domain=domain,
        scan_type=f"install-{playbook}",
        log_path=str(log_path),
        result_dir=str(install_dir.relative_to(ROOT_DIR)),
        command=["bash", str(script)],
        options={"_env": {}},
    )
    with _lock:
        _jobs[job.id] = job
    _save_state()
    threading.Thread(target=_run_job, args=(job.id,), daemon=True).start()
    return job


def _ensure_prereqs_then_scan(
    playbook: str,
    domain: str,
    scan_command: List[str],
    scan_options: Dict,
    scan_result_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Check prerequisites for *playbook*. If any tools are missing:
      1. Run the correct install script as a separate job.
      2. Queue the scan job to start after install succeeds.
    Returns a dict with job info for the API response.
    """
    missing = _missing_tools(playbook)
    if not missing:
        # All tools present — start scan directly
        scan_job = _create_and_start_job(
            domain, f"playbook-{playbook}", scan_command, scan_options, scan_result_dir
        )
        return {
            "job_id": scan_job.id,
            "status": "queued",
            "install_job_id": None,
            "prereqs_ok": True,
        }

    # Tools missing — install first, then scan
    install_job = _create_install_job(playbook, domain)
    scan_job = _create_and_start_job(
        domain,
        f"playbook-{playbook}",
        scan_command,
        scan_options,
        scan_result_dir,
        depends_on=install_job.id,
    )
    return {
        "job_id": scan_job.id,
        "status": "queued",
        "install_job_id": install_job.id,
        "prereqs_ok": False,
        "missing_tools": missing,
    }


# ---------------------------------------------------------------------------
# HTML Template -- single-file SPA
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>REK Dashboard</title>
<style>
/* ===== CSS Reset & Variables ===== */
:root {
  --bg-primary: #0a0e1a;
  --bg-secondary: #0f1629;
  --bg-card: #131b30;
  --bg-card-hover: #172040;
  --bg-input: #0c1124;
  --bg-terminal: #020510;
  --border: #1e2d4a;
  --border-light: #2a3d62;
  --border-accent: #1a3a6a;
  --text: #e2e8f0;
  --text-secondary: #b8c5d9;
  --text-muted: #6b7fa0;
  --accent: #0ea5e9;
  --accent-hover: #38bdf8;
  --accent-dim: #0c4a6e;
  --success: #22c55e;
  --success-dim: #14532d;
  --warning: #f59e0b;
  --warning-dim: #78350f;
  --error: #ef4444;
  --error-dim: #7f1d1d;
  --info: #3b82f6;
  --info-dim: #1e3a5f;
  --purple: #a78bfa;
  --purple-dim: #3b1d8e;
  --cyan: #06b6d4;
  --orange: #f97316;
  --radius: 10px;
  --radius-sm: 6px;
  --shadow: 0 4px 24px rgba(0,0,0,0.4);
  --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg-primary); color: var(--text); min-height: 100vh; line-height: 1.5; }
a { color: var(--accent); text-decoration: none; transition: color 0.15s; }
a:hover { color: var(--accent-hover); }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--border-light); border-radius: 3px; }

/* ===== App Shell ===== */
.app-header {
  background: linear-gradient(135deg, #0c1020 0%, #162240 100%);
  border-bottom: 1px solid var(--border);
  padding: 0 1.5rem;
  height: 52px;
  display: flex; align-items: center; justify-content: space-between;
  position: sticky; top: 0; z-index: 100;
  backdrop-filter: blur(12px);
}
.app-header h1 { font-size: 1.15rem; font-weight: 700; letter-spacing: 0.08em; }
.app-header h1 .rek { color: var(--accent); font-family: var(--font-mono); }
.header-right { display: flex; align-items: center; gap: 1rem; }
.header-badge { background: var(--accent-dim); color: var(--accent); font-size: 0.7rem; padding: 0.2rem 0.6rem; border-radius: 999px; font-weight: 600; letter-spacing: 0.03em; }
.header-meta { color: var(--text-muted); font-size: 0.78rem; }

.main-nav {
  display: flex; gap: 0; border-bottom: 1px solid var(--border);
  background: var(--bg-secondary); overflow-x: auto;
  -webkit-overflow-scrolling: touch;
}
.main-nav button {
  background: none; border: none; color: var(--text-muted);
  padding: 0.7rem 1.25rem; font-size: 0.84rem; cursor: pointer;
  border-bottom: 2px solid transparent; white-space: nowrap;
  transition: all 0.15s; font-weight: 500;
}
.main-nav button:hover { color: var(--text-secondary); background: rgba(255,255,255,0.02); }
.main-nav button.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }

.tab-content { display: none; padding: 1.25rem; max-width: 1480px; margin: 0 auto; animation: fadeIn 0.2s ease; }
.tab-content.active { display: block; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

/* ===== Cards ===== */
.card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.25rem; margin-bottom: 1rem;
  transition: border-color 0.15s;
}
.card:hover { border-color: var(--border-light); }
.card h2 { font-size: 0.95rem; margin-bottom: 0.75rem; color: var(--text); display: flex; align-items: center; gap: 0.5rem; font-weight: 600; }
.card h3 { font-size: 0.88rem; margin-bottom: 0.5rem; color: var(--accent); }

/* ===== Grids ===== */
.grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 1rem; }
.grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; }
.grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; }
.grid-5 { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.75rem; }

/* ===== Metric Cards ===== */
.metric {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1rem 1.25rem; text-align: center;
  position: relative; overflow: hidden;
}
.metric::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
  background: var(--accent); opacity: 0.5;
}
.metric .value { font-size: 1.75rem; font-weight: 700; color: var(--accent); line-height: 1.2; font-family: var(--font-mono); }
.metric .label { font-size: 0.72rem; color: var(--text-muted); margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 500; }
.metric.success::before { background: var(--success); }
.metric.success .value { color: var(--success); }
.metric.warning::before { background: var(--warning); }
.metric.warning .value { color: var(--warning); }
.metric.error::before { background: var(--error); }
.metric.error .value { color: var(--error); }
.metric.info::before { background: var(--info); }
.metric.info .value { color: var(--info); }
.metric.purple::before { background: var(--purple); }
.metric.purple .value { color: var(--purple); }
.metric.cyan::before { background: var(--cyan); }
.metric.cyan .value { color: var(--cyan); }

/* ===== Forms ===== */
.form-group { margin-bottom: 0.75rem; }
.form-group label { display: block; font-size: 0.78rem; color: var(--text-muted); margin-bottom: 0.3rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }
.form-group input, .form-group select, .form-group textarea {
  width: 100%; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: var(--radius-sm); color: var(--text); padding: 0.55rem 0.75rem;
  font-size: 0.86rem; outline: none; transition: border-color 0.15s;
  font-family: inherit;
}
.form-group input:focus, .form-group select:focus, .form-group textarea:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(14,165,233,0.15); }
.form-group input::placeholder, .form-group textarea::placeholder { color: var(--text-muted); opacity: 0.6; }
.form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0.75rem; }

.checkbox-group { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem; }
.checkbox-group label {
  display: flex; align-items: center; gap: 0.4rem;
  background: var(--bg-input); border: 1px solid var(--border);
  border-radius: var(--radius-sm); padding: 0.4rem 0.75rem;
  font-size: 0.8rem; cursor: pointer; transition: all 0.15s;
  text-transform: none; font-weight: 500; color: var(--text-secondary);
}
.checkbox-group label:hover { border-color: var(--accent); }
.checkbox-group input[type="checkbox"] { accent-color: var(--accent); }

.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 0.4rem;
  padding: 0.6rem 1.25rem; border-radius: var(--radius-sm); font-size: 0.86rem;
  font-weight: 600; cursor: pointer; border: 1px solid transparent;
  transition: all 0.15s; font-family: inherit;
}
.btn-primary { background: var(--accent); color: #fff; border-color: var(--accent); }
.btn-primary:hover { background: var(--accent-hover); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(14,165,233,0.3); }
.btn-danger { background: var(--error); color: #fff; border-color: var(--error); }
.btn-danger:hover { background: #dc2626; }
.btn-secondary { background: transparent; color: var(--text-muted); border-color: var(--border); }
.btn-secondary:hover { color: var(--text); border-color: var(--text-muted); }
.btn-sm { padding: 0.3rem 0.7rem; font-size: 0.76rem; }
.btn-ghost { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 0.3rem 0.5rem; font-size: 0.82rem; }
.btn-ghost:hover { color: var(--accent); }

/* ===== Pills / Badges ===== */
.pill {
  display: inline-flex; align-items: center; gap: 0.25rem;
  padding: 0.15rem 0.6rem; border-radius: 999px;
  font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;
}
.pill-queued { background: #334155; color: #94a3b8; }
.pill-running { background: var(--info-dim); color: #60a5fa; animation: pulse 2s infinite; }
.pill-completed { background: var(--success-dim); color: #4ade80; }
.pill-failed { background: var(--error-dim); color: #fca5a5; }
.pill-stopped { background: #44403c; color: #a8a29e; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.6; } }

.severity-critical { background: var(--error-dim); color: #fca5a5; }
.severity-high { background: #7c2d12; color: #fdba74; }
.severity-medium { background: var(--warning-dim); color: #fcd34d; }
.severity-low { background: var(--info-dim); color: #93c5fd; }
.severity-info { background: #1e293b; color: #94a3b8; }

/* ===== Tables ===== */
.tbl-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
th {
  text-align: left; padding: 0.6rem 0.75rem; border-bottom: 2px solid var(--border);
  color: var(--text-muted); font-weight: 600; font-size: 0.72rem;
  text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap;
  position: sticky; top: 0; background: var(--bg-card); z-index: 1;
}
td { padding: 0.45rem 0.75rem; border-bottom: 1px solid rgba(30,45,74,0.5); vertical-align: top; }
tr:hover td { background: rgba(255,255,255,0.015); }
.http-2xx { color: var(--success); font-weight: 600; font-family: var(--font-mono); }
.http-3xx { color: var(--cyan); font-weight: 600; font-family: var(--font-mono); }
.http-4xx { color: var(--warning); font-weight: 600; font-family: var(--font-mono); }
.http-5xx { color: var(--error); font-weight: 600; font-family: var(--font-mono); }

/* ===== Log Viewer ===== */
.log-box {
  background: var(--bg-terminal); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 0.75rem 1rem;
  font-family: var(--font-mono); font-size: 0.76rem; line-height: 1.65;
  white-space: pre-wrap; word-break: break-all; overflow-y: auto;
  max-height: 60vh; color: #94a3b8; position: relative;
}
.log-box .ansi-red, .log-line-error { color: var(--error); }
.log-box .ansi-yellow, .log-line-warning { color: var(--warning); }
.log-box .ansi-green, .log-line-success { color: var(--success); }
.log-box .ansi-blue, .log-line-info { color: var(--info); }
.log-box .ansi-cyan, .log-line-step { color: var(--cyan); font-weight: 600; }
.log-box .ansi-bold { font-weight: 700; }

/* ===== Inner Tabs ===== */
.inner-tabs { display: flex; gap: 0; margin-bottom: 0.75rem; border-bottom: 1px solid var(--border); overflow-x: auto; }
.inner-tabs button { background: none; border: none; color: var(--text-muted); padding: 0.5rem 1rem; font-size: 0.8rem; cursor: pointer; border-bottom: 2px solid transparent; white-space: nowrap; font-weight: 500; transition: all 0.15s; }
.inner-tabs button:hover { color: var(--text-secondary); }
.inner-tabs button.active { color: var(--accent); border-bottom-color: var(--accent); }
.inner-panel { display: none; }
.inner-panel.active { display: block; }

/* ===== Chat ===== */
.chat-messages { max-height: 450px; overflow-y: auto; margin-bottom: 0.75rem; padding: 0.5rem 0; }
.chat-msg { padding: 0.65rem 0.85rem; margin-bottom: 0.5rem; border-radius: 10px; font-size: 0.84rem; line-height: 1.6; }
.chat-msg.user { background: var(--info-dim); margin-left: 3rem; border-bottom-right-radius: 3px; }
.chat-msg.assistant { background: var(--bg-input); border: 1px solid var(--border); margin-right: 3rem; border-bottom-left-radius: 3px; }
.chat-msg .role { font-size: 0.68rem; color: var(--text-muted); margin-bottom: 0.25rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em; }

/* ===== Details/Accordion ===== */
details { margin-bottom: 0.5rem; }
summary { cursor: pointer; padding: 0.6rem 0.85rem; background: rgba(255,255,255,0.02); border-radius: var(--radius-sm); font-size: 0.86rem; font-weight: 500; transition: background 0.15s; list-style: none; display: flex; justify-content: space-between; align-items: center; }
summary::-webkit-details-marker { display: none; }
summary::after { content: '+'; color: var(--text-muted); font-size: 1rem; font-weight: 300; }
details[open] summary::after { content: '-'; }
summary:hover { background: rgba(255,255,255,0.04); }
details[open] summary { margin-bottom: 0.5rem; }

/* ===== File List ===== */
.file-list { list-style: none; padding-left: 0; }
.file-list li { padding: 0.35rem 0.6rem; border-bottom: 1px solid rgba(30,45,74,0.3); display: flex; justify-content: space-between; align-items: center; font-size: 0.82rem; }
.file-list li:hover { background: rgba(255,255,255,0.02); }
.file-size { color: var(--text-muted); font-size: 0.72rem; font-family: var(--font-mono); }

/* ===== Architecture Pipeline ===== */
.pipeline-step {
  padding: 0.6rem 0.85rem; border-radius: var(--radius-sm);
  border-left: 3px solid var(--accent); margin-bottom: 0.5rem;
  background: rgba(14,165,233,0.05);
}
.pipeline-step strong { font-size: 0.84rem; display: block; margin-bottom: 0.15rem; }
.pipeline-step p { font-size: 0.76rem; color: var(--text-muted); margin: 0; }

/* ===== File Viewer Modal ===== */
.modal-overlay {
  display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
  background: rgba(0,0,0,0.75); z-index: 200; padding: 1.5rem;
  backdrop-filter: blur(4px);
}
.modal-inner {
  max-width: 1200px; margin: 0 auto; height: 100%;
  display: flex; flex-direction: column;
}
.modal-header {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 0.75rem; flex-shrink: 0;
}
.modal-body { flex: 1; overflow: auto; }

/* ===== Empty State ===== */
.empty-state { text-align: center; padding: 3rem 1.5rem; color: var(--text-muted); }
.empty-state .icon { font-size: 2.5rem; margin-bottom: 0.75rem; opacity: 0.3; }
.empty-state p { font-size: 0.88rem; max-width: 360px; margin: 0 auto; }

/* ===== Utility ===== */
.text-muted { color: var(--text-muted); }
.text-secondary { color: var(--text-secondary); }
.text-sm { font-size: 0.82rem; }
.text-xs { font-size: 0.74rem; }
.mt-05 { margin-top: 0.25rem; }
.mt-1 { margin-top: 0.5rem; }
.mt-2 { margin-top: 1rem; }
.mb-05 { margin-bottom: 0.25rem; }
.mb-1 { margin-bottom: 0.5rem; }
.mb-2 { margin-bottom: 1rem; }
.flex-between { display: flex; justify-content: space-between; align-items: center; }
.flex-center { display: flex; align-items: center; gap: 0.5rem; }
.gap-05 { gap: 0.25rem; }
.gap-1 { gap: 0.5rem; }
.hidden { display: none !important; }
code { font-family: var(--font-mono); font-size: 0.82em; background: rgba(255,255,255,0.05); padding: 0.1rem 0.35rem; border-radius: 3px; }
.truncate { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 240px; display: inline-block; vertical-align: bottom; }

/* ===== Responsive ===== */
@media (max-width: 768px) {
  .grid-2, .grid-3, .grid-4, .grid-5 { grid-template-columns: 1fr; }
  .form-row { grid-template-columns: 1fr; }
  .tab-content { padding: 0.75rem; }
  .modal-overlay { padding: 0.5rem; }
}
</style>
</head>
<body>

<header class="app-header">
  <h1><span class="rek">REK</span> Dashboard</h1>
  <div class="header-right">
    <span class="header-badge" id="activeCount">0 active</span>
    <span class="header-meta" id="headerClock"></span>
  </div>
</header>

<nav class="main-nav" id="mainNav">
  <button class="active" data-tab="dashboard">Dashboard</button>
  <button data-tab="scan">New Scan</button>
  <button data-tab="live">Live Terminal</button>
  <button data-tab="results">Results</button>
  <button data-tab="history">History</button>
  <button data-tab="llm">LLM Assistant</button>
</nav>

<!-- ==================== DASHBOARD ==================== -->
<div class="tab-content active" id="tab-dashboard">
  <div class="grid-5 mb-2" id="dashMetrics">
    <div class="metric info"><div class="value" id="mTotal">--</div><div class="label">Total Scans</div></div>
    <div class="metric cyan"><div class="value" id="mRunning">--</div><div class="label">Active</div></div>
    <div class="metric success"><div class="value" id="mCompleted">--</div><div class="label">Completed</div></div>
    <div class="metric error"><div class="value" id="mFailed">--</div><div class="label">Failed</div></div>
    <div class="metric purple"><div class="value" id="mResults">--</div><div class="label">Result Sets</div></div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>Recent Scans</h2>
      <div class="tbl-wrap" style="max-height:320px;overflow-y:auto;">
        <table id="dashJobsTable">
          <thead><tr><th>ID</th><th>Domain</th><th>Type</th><th>Status</th><th>When</th><th></th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="mt-1 text-xs text-muted flex-between">
        <span>Showing latest 10</span>
        <a href="#" onclick="switchTab('history');return false;">View all</a>
      </div>
    </div>

    <div class="card">
      <h2>Recon Pipeline</h2>
      <div class="pipeline-step" style="border-color:var(--accent);">
        <strong>1. Subdomain Discovery</strong>
        <p>DNS Dumpster, crt.sh, brute-force, dnsgen, gotator, ripgen, puredns</p>
      </div>
      <div class="pipeline-step" style="border-color:var(--success);">
        <strong>2. Live Host Probing</strong>
        <p>HTTPX fingerprinting, naabu port scanning, service detection</p>
      </div>
      <div class="pipeline-step" style="border-color:var(--warning);">
        <strong>3. Endpoint Crawling</strong>
        <p>Gospider, Katana, GAU -- URL discovery, JS extraction, secret scanning</p>
      </div>
      <div class="pipeline-step" style="border-color:var(--error);">
        <strong>4. Vulnerability Analysis</strong>
        <p>GF patterns (XSS, SQLi, SSRF, LFI, RCE, SSTI, IDOR), Nuclei templates</p>
      </div>
    </div>
  </div>

  <div class="card" id="dashResultsCard">
    <h2>Latest Result Sets</h2>
    <div id="dashResultsList" class="text-sm text-muted">Loading...</div>
  </div>
</div>

<!-- ==================== NEW SCAN ==================== -->
<div class="tab-content" id="tab-scan">
  <div class="grid-2">
    <div class="card">
      <h2>Playbook Scan</h2>
      <p class="text-sm text-muted mb-1">Run a multi-step automated recon playbook against a target domain.</p>
      <form id="formPlaybook">
        <div class="form-group">
          <label>Target Domain</label>
          <input name="domain" placeholder="example.com" required autocomplete="off" spellcheck="false">
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Playbook Version</label>
            <select name="playbook">
              <option value="v1">v1 -- Full 8-step pipeline</option>
              <option value="v2">v2 -- Katana / HTTPX / Nuclei</option>
              <option value="standard">Standard</option>
            </select>
          </div>
          <div class="form-group">
            <label>Threads</label>
            <input name="threads" type="number" value="100" min="1" max="500">
          </div>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;margin-top:0.25rem;">Launch Playbook</button>
      </form>
    </div>

    <div class="card">
      <h2>Module Scan</h2>
      <p class="text-sm text-muted mb-1">Run individual REK modules for focused reconnaissance.</p>
      <form id="formModule">
        <div class="form-group">
          <label>Target Domain / Input</label>
          <input name="domain" placeholder="example.com" required autocomplete="off" spellcheck="false">
        </div>
        <div class="form-group">
          <label>Modules</label>
          <div class="checkbox-group">
            <label><input type="checkbox" name="modules" value="subdomain" checked> Subdomain Enum</label>
            <label><input type="checkbox" name="modules" value="http"> HTTP Check</label>
            <label><input type="checkbox" name="modules" value="directory"> Dir Scan</label>
            <label><input type="checkbox" name="modules" value="email"> Email Harvest</label>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Timeout (s)</label>
            <input name="timeout" type="number" value="10" min="1">
          </div>
          <div class="form-group">
            <label>Concurrency</label>
            <input name="concurrency" type="number" value="50" min="1">
          </div>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;margin-top:0.25rem;">Start Module Scan</button>
      </form>
    </div>
  </div>
</div>

<!-- ==================== LIVE TERMINAL ==================== -->
<div class="tab-content" id="tab-live">
  <div class="card" id="liveNoJob">
    <div class="empty-state">
      <div class="icon">&gt;_</div>
      <p>No active scan selected. Start a new scan or pick a running job from the dashboard.</p>
    </div>
  </div>
  <div class="hidden" id="livePanel">
    <div class="card">
      <div class="flex-between mb-1">
        <div class="flex-center">
          <h2 style="margin:0;">Terminal</h2>
          <code id="liveJobId" class="text-xs">--</code>
          <span id="liveStatus" class="pill pill-queued">--</span>
        </div>
        <div class="flex-center gap-1">
          <span id="liveDomain" class="text-sm text-secondary"></span>
          <button class="btn btn-danger btn-sm" id="btnStop" onclick="stopCurrentJob()" style="display:none;">Stop</button>
          <button class="btn btn-secondary btn-sm" onclick="closeLivePanel()">Close</button>
        </div>
      </div>
      <div class="log-box" id="liveLog" style="max-height:70vh;min-height:300px;"></div>
      <div class="flex-between mt-05">
        <span class="text-xs text-muted" id="liveLineCount">0 lines</span>
        <label class="text-xs text-muted flex-center gap-05"><input type="checkbox" id="liveAutoScroll" checked> Auto-scroll</label>
      </div>
    </div>
  </div>
</div>

<!-- ==================== RESULTS ==================== -->
<div class="tab-content" id="tab-results">
  <div id="resultsBrowser"></div>
</div>

<!-- ==================== HISTORY ==================== -->
<div class="tab-content" id="tab-history">
  <div class="card">
    <div class="flex-between mb-1">
      <h2 style="margin:0;">Scan History</h2>
      <button class="btn btn-secondary btn-sm" onclick="refreshHistory()">Refresh</button>
    </div>
    <div class="tbl-wrap">
      <table id="historyTable">
        <thead><tr><th>ID</th><th>Domain</th><th>Type</th><th>Status</th><th>Started</th><th>Duration</th><th>Exit</th><th>Actions</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ==================== LLM ASSISTANT ==================== -->
<div class="tab-content" id="tab-llm">
  <div class="grid-2">
    <div class="card">
      <h2>LLM Assistant</h2>
      <p class="text-sm text-muted mb-1">Ask the REK LLM assistant for recon guidance, finding prioritization, or analysis help.</p>
      <form id="formLLM">
        <div class="form-row">
          <div class="form-group">
            <label>Provider</label>
            <select name="provider">
              <option value="local">Local (Ollama)</option>
              <option value="remote">Remote (OpenAI-compatible)</option>
            </select>
          </div>
          <div class="form-group">
            <label>Model</label>
            <input name="model" placeholder="llama3.1 / gpt-4o-mini">
          </div>
        </div>
        <div class="form-group">
          <label>API Key (remote only)</label>
          <input name="api_key" type="password" placeholder="sk-...">
        </div>
        <div class="form-group">
          <label>Prompt</label>
          <textarea name="prompt" rows="3" placeholder="e.g., Analyze these subdomains and suggest priority targets..." style="resize:vertical;"></textarea>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;">Ask LLM</button>
      </form>
    </div>
    <div class="card">
      <h2>Conversation</h2>
      <div class="chat-messages" id="chatMessages">
        <div class="chat-msg assistant">
          <div class="role">Assistant</div>
          Ready. Ask me about recon strategies, finding analysis, or tool usage.
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ==================== FILE VIEWER MODAL ==================== -->
<div class="modal-overlay" id="fileModal">
  <div class="modal-inner">
    <div class="modal-header">
      <h2 id="fileModalTitle" style="font-size:0.9rem;color:var(--text);font-family:var(--font-mono);"></h2>
      <button class="btn btn-secondary btn-sm" onclick="closeFileModal()">Close (Esc)</button>
    </div>
    <div class="card modal-body" style="padding:0;" id="fileModalBody"></div>
  </div>
</div>

<script>
// =====================================================================
//  State
// =====================================================================
let currentSSE = null;
let currentJobId = null;
let liveLineCount = 0;

// =====================================================================
//  Tab Navigation
// =====================================================================
document.querySelectorAll('.main-nav button').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

function switchTab(tab) {
  document.querySelectorAll('.main-nav button').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  const btn = document.querySelector(`[data-tab="${tab}"]`);
  if (btn) btn.classList.add('active');
  const el = document.getElementById('tab-' + tab);
  if (el) el.classList.add('active');
  if (tab === 'results') loadResults();
  if (tab === 'history') refreshHistory();
}

// =====================================================================
//  API helper
// =====================================================================
async function api(url, opts) {
  try {
    const r = await fetch(url, opts);
    return await r.json();
  } catch(e) {
    console.error('API error:', e);
    return {};
  }
}

// =====================================================================
//  Dashboard
// =====================================================================
async function loadDashboard() {
  const data = await api('/api/jobs');
  const jobs = data.jobs || [];
  const running = jobs.filter(j => j.status === 'running').length;
  const completed = jobs.filter(j => j.status === 'completed').length;
  const failed = jobs.filter(j => j.status === 'failed').length;

  document.getElementById('mTotal').textContent = jobs.length;
  document.getElementById('mRunning').textContent = running;
  document.getElementById('mCompleted').textContent = completed;
  document.getElementById('mFailed').textContent = failed;
  document.getElementById('activeCount').textContent = running + ' active';

  const tbody = document.querySelector('#dashJobsTable tbody');
  tbody.innerHTML = jobs.slice(0, 10).map(j => `
    <tr>
      <td><code>${j.id}</code></td>
      <td class="truncate">${esc(j.domain)}</td>
      <td class="text-muted text-xs">${esc(j.scan_type)}</td>
      <td><span class="pill pill-${j.status}">${j.status}</span></td>
      <td class="text-muted text-xs">${timeAgo(j.created_at)}</td>
      <td>
        <a href="#" onclick="openLive('${j.id}');return false;" class="btn-ghost">Logs</a>
        ${j.result_dir ? `<a href="#" onclick="viewResultDir('${esc(j.result_dir)}');return false;" class="btn-ghost">Results</a>` : ''}
      </td>
    </tr>
  `).join('') || '<tr><td colspan="6" class="text-muted" style="text-align:center;padding:1.5rem;">No scans yet. Start one from the New Scan tab.</td></tr>';

  // Results count
  const rData = await api('/api/results');
  const dirs = rData.dirs || [];
  document.getElementById('mResults').textContent = dirs.length;

  const rDiv = document.getElementById('dashResultsList');
  if (dirs.length === 0) {
    rDiv.innerHTML = '<div class="empty-state" style="padding:1.5rem;"><p>No results yet. Run a scan to generate results.</p></div>';
  } else {
    rDiv.innerHTML = dirs.slice(0, 6).map(d => `
      <div style="padding:0.5rem 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
        <div>
          <span class="text-sm">${esc(d.name)}</span>
          <span class="text-xs text-muted" style="margin-left:0.5rem;">${d.files.length} files</span>
        </div>
        <a href="#" onclick="viewResultDir('${esc(d.path)}');return false;" class="btn btn-secondary btn-sm">Explore</a>
      </div>
    `).join('');
  }
}

// =====================================================================
//  Live Terminal
// =====================================================================
function addTerminalNotice(msg) {
  const box = document.getElementById('liveLog');
  if (!box) return;
  const div = document.createElement('div');
  div.style.cssText = 'color:#f59e0b;background:#1a1400;border-left:3px solid #f59e0b;padding:0.4rem 0.75rem;margin:0.25rem 0;font-family:var(--font-mono);font-size:0.82rem;';
  div.textContent = msg;
  box.appendChild(div);
  if (document.getElementById('liveAutoScroll').checked) box.scrollTop = box.scrollHeight;
}

// openLive(jobId, thenJobId?)
// If thenJobId is set, automatically switch to that job's stream when this one completes
function openLive(jobId, thenJobId) {
  switchTab('live');
  document.getElementById('liveNoJob').classList.add('hidden');
  document.getElementById('livePanel').classList.remove('hidden');
  document.getElementById('liveJobId').textContent = jobId;
  const box = document.getElementById('liveLog');
  box.innerHTML = '';
  liveLineCount = 0;
  currentJobId = jobId;

  if (currentSSE) { currentSSE.close(); currentSSE = null; }

  fetch(`/api/log?id=${jobId}&lines=2000`).then(r => r.json()).then(data => {
    if (data.log) {
      box.innerHTML = colorizeLog(data.log);
      liveLineCount = data.log.split('\n').length;
      updateLineCount();
      if (document.getElementById('liveAutoScroll').checked) box.scrollTop = box.scrollHeight;
    }
    if (data.domain) document.getElementById('liveDomain').textContent = data.domain;
    updateLiveStatus(data.status);

    if (data.status === 'running' || data.status === 'queued') {
      document.getElementById('btnStop').style.display = '';
      currentSSE = new EventSource(`/api/stream?id=${jobId}`);
      currentSSE.addEventListener('log', e => {
        box.innerHTML += colorizeLog(e.data) + '\n';
        liveLineCount++;
        updateLineCount();
        if (document.getElementById('liveAutoScroll').checked) box.scrollTop = box.scrollHeight;
      });
      currentSSE.addEventListener('status', e => {
        try {
          const s = JSON.parse(e.data);
          updateLiveStatus(s.status);
          if (s.status !== 'running' && s.status !== 'queued') {
            document.getElementById('btnStop').style.display = 'none';
            currentSSE.close(); currentSSE = null;
            loadDashboard();
            // Auto-switch to dependent scan job if one was queued
            if (thenJobId && s.status === 'completed') {
              addTerminalNotice('✓ Prerequisites installed. Switching to scan job…');
              setTimeout(() => openLive(thenJobId), 1200);
            }
          }
        } catch(ex) {}
      });
      currentSSE.onerror = () => { if (currentSSE) { currentSSE.close(); currentSSE = null; } };
    } else {
      document.getElementById('btnStop').style.display = 'none';
    }
  });
}

function updateLiveStatus(status) {
  const el = document.getElementById('liveStatus');
  el.className = 'pill pill-' + status;
  el.textContent = status;
}

function updateLineCount() {
  document.getElementById('liveLineCount').textContent = liveLineCount + ' lines';
}

function closeLivePanel() {
  document.getElementById('livePanel').classList.add('hidden');
  document.getElementById('liveNoJob').classList.remove('hidden');
  if (currentSSE) { currentSSE.close(); currentSSE = null; }
  currentJobId = null;
}

async function stopCurrentJob() {
  if (!currentJobId) return;
  if (!confirm('Stop this scan?')) return;
  await api(`/api/scan/stop`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({job_id: currentJobId})
  });
  updateLiveStatus('failed');
  document.getElementById('btnStop').style.display = 'none';
  loadDashboard();
}

function colorizeLog(text) {
  return text.split('\n').map(line => {
    let l = line.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    // Strip ANSI escape codes but try to preserve semantics
    const clean = l.replace(/\x1b\[[0-9;]*m/g, '');
    if (/\[!]|error|failed|fatal|traceback/i.test(clean)) return `<span class="log-line-error">${clean}</span>`;
    if (/warning|\[!\]|skipping|deprecated/i.test(clean)) return `<span class="log-line-warning">${clean}</span>`;
    if (/\[✓]|\[v\]|completed|successfully|found \d+|saved \d+/i.test(clean)) return `<span class="log-line-success">${clean}</span>`;
    if (/\[\+]|step \d+|running|starting|setting up|installing/i.test(clean)) return `<span class="log-line-step">${clean}</span>`;
    if (/\[\*]|checking|scanning|querying|loading|resolving/i.test(clean)) return `<span class="log-line-info">${clean}</span>`;
    return clean;
  }).join('\n');
}

// =====================================================================
//  Results Browser
// =====================================================================
async function loadResults() {
  const data = await api('/api/results');
  const dirs = data.dirs || [];
  const container = document.getElementById('resultsBrowser');

  if (dirs.length === 0) {
    container.innerHTML = '<div class="card"><div class="empty-state"><div class="icon">[ ]</div><p>No result directories found. Run a scan to generate results.</p></div></div>';
    return;
  }

  container.innerHTML = dirs.map(d => {
    const fileRows = d.files.map(f => `
      <li>
        <a href="#" onclick="viewFile('${esc(f.path)}');return false;">${esc(f.name)}</a>
        <span class="file-size">${formatSize(f.size)}</span>
      </li>
    `).join('');
    const safeId = 'summary-' + d.path.replace(/[^a-zA-Z0-9]/g, '_');
    return `
      <div class="card">
        <details>
          <summary>
            <span class="flex-center gap-1">${esc(d.name)} <span class="text-xs text-muted">${d.files.length} files</span></span>
          </summary>
          <div class="mt-1">
            <div id="${safeId}" class="mb-1"></div>
            <ul class="file-list">${fileRows || '<li class="text-muted">No supported files.</li>'}</ul>
          </div>
        </details>
      </div>
    `;
  }).join('');

  dirs.forEach(d => loadResultSummary(d.path));
}

async function loadResultSummary(dirPath) {
  try {
    const data = await api(`/api/summary?dir=${encodeURIComponent(dirPath)}`);
    const s = data.summary;
    if (!s) return;
    const divId = 'summary-' + dirPath.replace(/[^a-zA-Z0-9]/g, '_');
    const el = document.getElementById(divId);
    if (!el) return;

    let metrics = '';
    if (s.subdomains > 0) metrics += metric(s.subdomains, 'Subdomains', 'info');
    if (s.live_hosts > 0) metrics += metric(s.live_hosts, 'Live Hosts', 'success');
    if (s.endpoints > 0) metrics += metric(s.endpoints, 'Endpoints', 'cyan');
    if (s.ports > 0) metrics += metric(s.ports, 'Open Ports', 'purple');
    if (s.emails > 0) metrics += metric(s.emails, 'Emails', 'warning');

    const vulnEntries = Object.entries(s.vulnerabilities || {});
    const totalVulns = vulnEntries.reduce((a, [,v]) => a + v, 0);
    if (totalVulns > 0) metrics += metric(totalVulns, 'Vuln Patterns', 'error');
    if (s.js_secrets > 0) metrics += metric(s.js_secrets, 'JS Secrets', 'error');

    let html = '';
    if (metrics) html += `<div class="grid-5" style="margin-bottom:0.75rem;">${metrics}</div>`;
    if (vulnEntries.length > 0) {
      html += `<div class="text-sm mb-05">${vulnEntries.map(([k,v]) =>
        `<span class="pill severity-high" style="margin:0 0.2rem 0.2rem 0;">${k}: ${v}</span>`
      ).join('')}</div>`;
    }
    if (s.has_report) {
      html += `<div class="mt-05"><span class="pill severity-info">Report available</span></div>`;
    }
    el.innerHTML = html;
  } catch(e) {}
}

function metric(value, label, color) {
  return `<div class="metric ${color}"><div class="value">${value}</div><div class="label">${label}</div></div>`;
}

function viewResultDir(dirPath) {
  switchTab('results');
  setTimeout(() => {
    const safeId = 'summary-' + dirPath.replace(/[^a-zA-Z0-9]/g, '_');
    const el = document.getElementById(safeId);
    if (el) {
      const details = el.closest('details');
      if (details) details.open = true;
      el.scrollIntoView({behavior:'smooth', block:'center'});
    }
  }, 300);
}

// =====================================================================
//  File Viewer Modal
// =====================================================================
async function viewFile(relPath) {
  document.getElementById('fileModal').style.display = 'block';
  document.getElementById('fileModalTitle').textContent = relPath;
  const body = document.getElementById('fileModalBody');
  body.innerHTML = '<div style="padding:2rem;text-align:center;" class="text-muted">Loading...</div>';

  const ext = relPath.split('.').pop().toLowerCase();

  if (ext === 'csv') {
    const data = await api(`/api/file/csv?path=${encodeURIComponent(relPath)}`);
    if (data.error) { body.innerHTML = `<div style="padding:1rem;" class="text-muted">${esc(data.error)}</div>`; return; }
    const d = data.data;
    body.innerHTML = `
      <div style="padding:0.75rem;">
        <p class="text-sm text-muted mb-1">${d.total} rows</p>
        <div class="tbl-wrap" style="max-height:70vh;overflow-y:auto;">
          <table>
            <thead><tr>${d.headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead>
            <tbody>${d.rows.slice(0, 500).map(r => `<tr>${r.map((c, i) => {
              let cls = '';
              const hdr = (d.headers[i] || '').toLowerCase();
              if (hdr.includes('status')) {
                const n = parseInt(c);
                if (n >= 200 && n < 300) cls = 'http-2xx';
                else if (n >= 300 && n < 400) cls = 'http-3xx';
                else if (n >= 400 && n < 500) cls = 'http-4xx';
                else if (n >= 500) cls = 'http-5xx';
              }
              return `<td class="${cls}">${esc(c)}</td>`;
            }).join('')}</tr>`).join('')}</tbody>
          </table>
        </div>
        ${d.total > 500 ? '<p class="text-xs text-muted mt-1">Showing first 500 of ' + d.total + ' rows.</p>' : ''}
      </div>`;
  } else if (ext === 'json') {
    const data = await api(`/api/file/text?path=${encodeURIComponent(relPath)}`);
    try {
      const pretty = JSON.stringify(JSON.parse(data.text), null, 2);
      body.innerHTML = `<pre class="log-box" style="max-height:none;border:none;border-radius:0;margin:0;">${esc(pretty)}</pre>`;
    } catch(e) {
      body.innerHTML = `<pre class="log-box" style="max-height:none;border:none;border-radius:0;margin:0;">${esc(data.text)}</pre>`;
    }
  } else if (ext === 'md') {
    const data = await api(`/api/file/text?path=${encodeURIComponent(relPath)}`);
    body.innerHTML = `<div style="padding:1.25rem;font-size:0.88rem;line-height:1.7;">${renderMarkdown(data.text)}</div>`;
  } else {
    const data = await api(`/api/file/text?path=${encodeURIComponent(relPath)}`);
    body.innerHTML = `<pre class="log-box" style="max-height:none;border:none;border-radius:0;margin:0;">${colorizeLog(data.text || '')}</pre>`;
  }
}

function closeFileModal() { document.getElementById('fileModal').style.display = 'none'; }
document.getElementById('fileModal').addEventListener('click', e => { if (e.target.id === 'fileModal') closeFileModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeFileModal(); });

// =====================================================================
//  History
// =====================================================================
async function refreshHistory() {
  const data = await api('/api/jobs');
  const jobs = data.jobs || [];
  const tbody = document.querySelector('#historyTable tbody');
  tbody.innerHTML = jobs.map(j => {
    let dur = '--';
    if (j.started_at && j.ended_at) {
      const s = (new Date(j.ended_at) - new Date(j.started_at)) / 1000;
      dur = s < 60 ? `${s.toFixed(0)}s` : s < 3600 ? `${(s/60).toFixed(1)}m` : `${(s/3600).toFixed(1)}h`;
    } else if (j.started_at && j.status === 'running') {
      const s = (Date.now() - new Date(j.started_at)) / 1000;
      dur = `${(s/60).toFixed(0)}m (running)`;
    }
    return `<tr>
      <td><code>${j.id}</code></td>
      <td class="truncate">${esc(j.domain)}</td>
      <td class="text-muted text-xs">${esc(j.scan_type)}</td>
      <td><span class="pill pill-${j.status}">${j.status}</span></td>
      <td class="text-muted text-xs">${formatDate(j.created_at)}</td>
      <td class="text-xs">${dur}</td>
      <td class="text-xs" style="font-family:var(--font-mono);">${j.return_code !== null && j.return_code !== undefined ? j.return_code : '--'}</td>
      <td>
        <a href="#" onclick="openLive('${j.id}');return false;" class="btn-ghost">Logs</a>
        ${j.result_dir ? ` <a href="#" onclick="viewResultDir('${esc(j.result_dir)}');return false;" class="btn-ghost">Results</a>` : ''}
      </td>
    </tr>`;
  }).join('') || '<tr><td colspan="8" class="text-muted" style="text-align:center;padding:1.5rem;">No scans in history.</td></tr>';
}

// =====================================================================
//  Scan Forms
// =====================================================================
document.getElementById('formPlaybook').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const domain = fd.get('domain').trim();
  if (!domain) return;
  const res = await api('/api/scan/playbook', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      domain: domain,
      playbook: fd.get('playbook'),
      threads: parseInt(fd.get('threads')) || 100,
    })
  });
  if (res.error) { alert(res.error); return; }
  if (res.install_job_id) {
    // Show install first; scan job auto-starts after install succeeds
    switchTab('live');
    openLive(res.install_job_id, res.job_id);
    addTerminalNotice(`⚙ Missing tools detected: ${(res.missing_tools||[]).join(', ')}. Running install script first — scan will start automatically when done.`);
  } else if (res.job_id) {
    switchTab('live');
    openLive(res.job_id);
  }
  loadDashboard();
});

document.getElementById('formModule').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const domain = fd.get('domain').trim();
  if (!domain) return;
  const modules = fd.getAll('modules');
  if (modules.length === 0) { alert('Select at least one module.'); return; }

  for (const mod of modules) {
    const res = await api('/api/scan/module', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        module: mod,
        domain: domain,
        timeout: parseInt(fd.get('timeout')) || 10,
        concurrency: parseInt(fd.get('concurrency')) || 50,
      })
    });
    if (res.job_id && modules.indexOf(mod) === 0) {
      openLive(res.job_id);
    }
  }
  loadDashboard();
});

// =====================================================================
//  LLM
// =====================================================================
document.getElementById('formLLM').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const prompt = fd.get('prompt');
  if (!prompt.trim()) return;

  const chat = document.getElementById('chatMessages');
  chat.innerHTML += `<div class="chat-msg user"><div class="role">You</div>${esc(prompt)}</div>`;
  chat.scrollTop = chat.scrollHeight;
  chat.innerHTML += `<div class="chat-msg assistant" id="llmPending"><div class="role">Assistant</div><span class="text-muted">Thinking...</span></div>`;

  try {
    const res = await api('/api/llm', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        prompt: prompt,
        provider: fd.get('provider'),
        model: fd.get('model'),
        api_key: fd.get('api_key'),
      })
    });
    const pending = document.getElementById('llmPending');
    if (pending) {
      pending.removeAttribute('id');
      const content = res.response || res.error || 'No response received.';
      pending.innerHTML = `<div class="role">Assistant</div>${renderMarkdown(content)}`;
    }
  } catch(err) {
    const pending = document.getElementById('llmPending');
    if (pending) {
      pending.removeAttribute('id');
      pending.innerHTML = `<div class="role">Assistant</div><span class="log-line-error">Error: ${esc(err.message)}</span>`;
    }
  }
  chat.scrollTop = chat.scrollHeight;
  e.target.querySelector('[name="prompt"]').value = '';
});

// =====================================================================
//  Utilities
// =====================================================================
function esc(s) { if (s == null) return ''; const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }

function formatDate(iso) {
  if (!iso) return '--';
  try { return new Date(iso).toLocaleString(undefined, {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}); } catch(e) { return iso; }
}

function timeAgo(iso) {
  if (!iso) return '--';
  try {
    const diff = (Date.now() - new Date(iso)) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff/60) + 'm ago';
    if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
    return Math.floor(diff/86400) + 'd ago';
  } catch(e) { return iso; }
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/1048576).toFixed(1) + ' MB';
}

function renderMarkdown(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/^### (.+)$/gm, '<h4 style="color:var(--accent);margin:0.75rem 0 0.3rem;font-size:0.92rem;">$1</h4>')
    .replace(/^## (.+)$/gm, '<h3 style="color:var(--text);margin:1rem 0 0.3rem;font-size:1rem;">$1</h3>')
    .replace(/^# (.+)$/gm, '<h2 style="color:var(--text);margin:1.25rem 0 0.5rem;font-size:1.1rem;">$1</h2>')
    .replace(/^- (.+)$/gm, '<div style="padding:0.15rem 0 0.15rem 1rem;">&#8226; $1</div>')
    .replace(/^(\d+)\. (.+)$/gm, '<div style="padding:0.15rem 0 0.15rem 1rem;">$1. $2</div>')
    .replace(/```([\s\S]*?)```/gm, '<pre class="log-box" style="margin:0.5rem 0;font-size:0.78rem;">$1</pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/\n\n/g, '<br><br>')
    .replace(/\n/g, '<br>');
}

// Clock
function updateClock() {
  document.getElementById('headerClock').textContent = new Date().toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});
}
updateClock();
setInterval(updateClock, 30000);

// =====================================================================
//  Init & polling
// =====================================================================
loadDashboard();
refreshHistory();
loadResults();
setInterval(loadDashboard, 12000);
setInterval(() => {
  const histTab = document.getElementById('tab-history');
  if (histTab && histTab.classList.contains('active')) refreshHistory();
}, 10000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/jobs")
def api_jobs():
    jobs = _sorted_jobs()
    return jsonify({"jobs": [asdict(j) for j in jobs]})


@app.route("/api/log")
def api_log():
    job_id = request.args.get("id", "")
    lines = min(int(request.args.get("lines", "500")), 5000)
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    log_path = Path(job.log_path)
    text = ""
    if log_path.exists():
        all_lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        text = "\n".join(all_lines[-lines:])
    return jsonify({
        "job_id": job_id,
        "status": job.status,
        "log": text,
        "domain": job.domain,
    })


@app.route("/api/stream")
def api_stream():
    """Server-Sent Events endpoint for live log streaming."""
    job_id = request.args.get("id", "")
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404

    q: queue.Queue = queue.Queue()
    subs = _sse_subscribers.setdefault(job_id, [])
    subs.append(q)

    def generate():
        try:
            while True:
                try:
                    event, data = q.get(timeout=30)
                    yield f"event: {event}\ndata: {data}\n\n"
                    if event == "status":
                        try:
                            s = json.loads(data)
                            if s.get("status") not in ("running", "queued"):
                                break
                        except Exception:
                            pass
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            try:
                subs.remove(q)
            except ValueError:
                pass

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/results")
def api_results():
    return jsonify({"dirs": _discover_result_dirs()})


@app.route("/api/summary")
def api_summary():
    dir_path = request.args.get("dir", "")
    if not dir_path:
        return jsonify({"error": "missing dir param"}), 400
    summary = _build_scan_summary(dir_path)
    return jsonify({"summary": summary})


@app.route("/api/file/csv")
def api_file_csv():
    rel = request.args.get("path", "")
    # Security: ensure path stays within ROOT_DIR
    target = (ROOT_DIR / rel).resolve()
    if ROOT_DIR not in target.parents and target != ROOT_DIR:
        return jsonify({"error": "invalid path"}), 403
    data = _parse_csv_file(str(target))
    if data is None:
        return jsonify({"error": "Could not parse CSV"}), 404
    return jsonify({"data": data})


@app.route("/api/file/text")
def api_file_text():
    rel = request.args.get("path", "")
    target = (ROOT_DIR / rel).resolve()
    if ROOT_DIR not in target.parents and target != ROOT_DIR:
        return jsonify({"error": "invalid path"}), 403
    text = _read_text_file(str(target))
    return jsonify({"text": text})


@app.route("/api/scan/playbook", methods=["POST"])
def api_scan_playbook():
    data = request.get_json()
    domain = (data.get("domain") or "").strip().lower()
    playbook = data.get("playbook", "v1")
    threads = data.get("threads", 100)

    if not domain:
        return jsonify({"error": "domain required"}), 400
    if playbook not in PLAYBOOKS:
        return jsonify({"error": f"unknown playbook: {playbook}"}), 400

    script = PLAYBOOKS[playbook]

    # v2 playbook does not parse -d/-t flags — pass TARGET_URL via env instead
    if playbook == "v2":
        target_url = f"https://{domain}" if not domain.startswith("http") else domain
        command = ["bash", str(script)]
        options = {"threads": threads, "_env": {"TARGET_URL": target_url, "THREADS": str(threads)}}
    else:
        command = ["bash", str(script), "-d", domain, "-t", str(threads)]
        options = {"threads": threads}

    result = _ensure_prereqs_then_scan(playbook, domain, command, options)
    return jsonify(result)


@app.route("/api/scan/module", methods=["POST"])
def api_scan_module():
    data = request.get_json()
    module = data.get("module", "subdomain")
    domain = (data.get("domain") or "").strip().lower()
    timeout = data.get("timeout", 10)
    concurrency = data.get("concurrency", 50)

    if not domain:
        return jsonify({"error": "domain required"}), 400
    if module not in SCAN_MODULES:
        return jsonify({"error": f"unknown module: {module}"}), 400

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    result_dir = RESULTS_ROOT / f"ui-{domain.replace('.', '_')}-{ts}"
    result_dir.mkdir(parents=True, exist_ok=True)

    command = [sys.executable, str(ROOT_DIR / "rek.py"), "--silent"]

    if module == "subdomain":
        output_file = str(result_dir / "results.txt")
        command += [
            "-d", domain, "-o", output_file,
            "-t", str(timeout), "-c", str(concurrency),
        ]
    elif module == "http":
        # HTTPStatusChecker expects a file containing URLs/hosts, not a domain
        # string. Look for an existing subdomain results file for this domain;
        # if none exists, create a seed file with just the bare domain so the
        # checker probes both http:// and https:// variants.
        input_file = _find_subdomain_results(domain)
        if input_file is None:
            seed_file = result_dir / "http_input.txt"
            seed_file.write_text(f"{domain}\n", encoding="utf-8")
            input_file = str(seed_file)
        command += [
            "--input", input_file,
            "-o", str(result_dir / "http_results.csv"),
            "-t", str(timeout), "-c", str(concurrency),
        ]
    elif module == "directory":
        command += [
            "--url", f"https://{domain}",
            "-t", str(timeout), "-c", str(concurrency), "--depth", "3",
        ]
    elif module == "email":
        command += [
            "--email-domain", domain,
            "-o", str(result_dir / "email_results.csv"),
            "-t", str(timeout),
        ]

    job = _create_and_start_job(
        domain, module, command,
        {"timeout": timeout, "concurrency": concurrency},
        result_dir=result_dir,
    )
    return jsonify({"job_id": job.id, "status": "queued"})


@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    data = request.get_json()
    job_id = data.get("job_id", "")
    if not job_id:
        return jsonify({"error": "job_id required"}), 400
    if _stop_job(job_id):
        return jsonify({"stopped": True})
    return jsonify({"stopped": False, "error": "job not running"}), 404


@app.route("/api/prerequisites")
def api_prerequisites():
    """Check which CLI tools and Python packages are available."""
    import shutil
    cli_tools = [
        "subfinder", "httpx", "naabu", "nuclei",
        "katana", "gospider", "gau", "dnsgen",
        "puredns", "gotator", "ripgen", "gf",
    ]
    # Build PATH exactly as _build_env() does so we find tools in ~/go/bin
    tools_dir = str(ROOT_DIR / "tools")
    go_bin = os.path.expanduser("~/go/bin")
    search_path = f"{tools_dir}:{go_bin}:{os.environ.get('PATH', '')}"
    env_copy = os.environ.copy()
    env_copy["PATH"] = search_path

    def which_in_path(name: str) -> bool:
        return shutil.which(name, path=search_path) is not None

    tools_status = {t: which_in_path(t) for t in cli_tools}

    python_pkgs = ["flask", "httpx", "dnspython", "pandas", "selenium",
                   "bs4", "tldextract", "aiohttp", "termcolor", "tqdm"]
    pkg_status = {}
    for pkg in python_pkgs:
        try:
            __import__(pkg)
            pkg_status[pkg] = True
        except ImportError:
            pkg_status[pkg] = False

    # Wappalyzer needs pkg_resources (removed in Python 3.12+)
    try:
        import importlib
        importlib.import_module("Wappalyzer")
        pkg_status["Wappalyzer"] = True
    except Exception:
        pkg_status["Wappalyzer"] = False

    install_scripts = {
        name: (ROOT_DIR / "playbook" / f"install-script{'-' + name if name != 'standard' else ''}.sh").exists()
        for name in ["standard", "v1", "v2"]
    }

    # Per-playbook readiness
    playbook_ready = {
        pb: {"ready": not bool(_missing_tools(pb)), "missing": _missing_tools(pb)}
        for pb in ["v1", "v2", "standard"]
    }

    return jsonify({
        "cli_tools": tools_status,
        "python_packages": pkg_status,
        "install_scripts": install_scripts,
        "playbook_ready": playbook_ready,
        "python_version": sys.version,
    })


@app.route("/api/install", methods=["POST"])
def api_install():
    """Manually trigger an install script for a given playbook variant."""
    data = request.get_json()
    playbook = (data.get("playbook") or "v1").strip()
    domain = (data.get("domain") or "install").strip()

    if playbook not in _INSTALL_SCRIPTS:
        return jsonify({"error": f"unknown playbook: {playbook}"}), 400

    script = _INSTALL_SCRIPTS[playbook]
    if not script.exists():
        return jsonify({"error": f"install script not found: {script}"}), 404

    # Check if an install for this playbook is already running
    with _lock:
        already = [
            j for j in _jobs.values()
            if j.scan_type == f"install-{playbook}" and j.status == "running"
        ]
    if already:
        return jsonify({"job_id": already[0].id, "status": "already_running"})

    install_job = _create_install_job(playbook, domain)
    return jsonify({"job_id": install_job.id, "status": "queued"})


@app.route("/api/llm", methods=["POST"])
def api_llm():
    data = request.get_json()
    prompt = data.get("prompt", "")
    provider = data.get("provider", "local")
    model = data.get("model", "")
    api_key = data.get("api_key", "")

    if not prompt.strip():
        return jsonify({"error": "prompt required"}), 400

    try:
        sys.path.insert(0, str(ROOT_DIR))
        from rek import LLMAssistant

        assistant = LLMAssistant(silent=True, timeout=60)
        response = assistant.ask(
            prompt=prompt,
            provider=provider or None,
            model=model or None,
            api_key=api_key or None,
        )
        return jsonify({"response": response})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="REK Web Dashboard")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    _load_state()

    banner = f"""
    ____  ______ __ __
   / __ \\/ ____// //_/
  / /_/ / __/  / ,<
 / _, _/ /___ / /| |
/_/ |_/_____//_/ |_|  Dashboard

  Running at http://{args.host}:{args.port}
  Press Ctrl+C to stop.
"""
    print(banner)
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
