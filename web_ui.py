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
                stdin=subprocess.PIPE,
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
<title>REK — Recon Toolkit</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e1a;--bg2:#0f1629;--card:#131b30;--card2:#172040;
  --border:#1e2d4a;--border2:#2a3d62;
  --text:#e2e8f0;--text2:#8892a4;--text3:#4a5568;
  --cyan:#00d4ff;--green:#00ff88;--red:#ff4444;--orange:#ff8c00;--yellow:#ffd700;--purple:#a855f7;
  --terminal:#060c18;
  --font:'JetBrains Mono',monospace;
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;line-height:1.5;overflow:hidden}

/* ── Header ── */
#header{display:flex;align-items:center;gap:16px;padding:8px 16px;background:var(--bg2);border-bottom:1px solid var(--border);height:48px;flex-shrink:0}
#header .logo{font-size:20px;font-weight:700;letter-spacing:.1em;color:var(--cyan);white-space:nowrap}
#header .logo span{color:var(--green)}
#tabs{display:flex;gap:2px;flex:1;margin:0 16px}
.tab-btn{padding:6px 14px;border:1px solid transparent;border-radius:4px;cursor:pointer;background:transparent;color:var(--text2);font:inherit;font-size:12px;font-weight:500;letter-spacing:.05em;transition:.15s}
.tab-btn:hover{color:var(--text);border-color:var(--border2)}
.tab-btn.active{background:var(--card);color:var(--cyan);border-color:var(--border2)}
#hdr-status{font-size:11px;color:var(--text2);white-space:nowrap}

/* ── Main layout ── */
#app{display:flex;flex-direction:column;height:calc(100vh - 48px);overflow:hidden}
.tab-panel{display:none;flex:1;overflow:hidden;flex-direction:column}
.tab-panel.active{display:flex}

/* ── Pipeline tab ── */
#panel-pipeline{flex-direction:column}
#pipeline-controls{padding:12px 16px;background:var(--bg2);border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-wrap:wrap;flex-shrink:0}
#pipeline-controls input,#pipeline-controls select{background:var(--card);border:1px solid var(--border2);color:var(--text);font:inherit;font-size:12px;padding:5px 8px;border-radius:4px;outline:none}
#pipeline-controls input:focus{border-color:var(--cyan)}
.btn{padding:6px 12px;border-radius:4px;border:none;cursor:pointer;font:inherit;font-size:12px;font-weight:600;transition:.15s;white-space:nowrap}
.btn-primary{background:var(--cyan);color:#000}
.btn-primary:hover{background:#00b8e0}
.btn-danger{background:var(--red);color:#fff}
.btn-sm{padding:3px 8px;font-size:11px}
.btn-outline{background:transparent;border:1px solid var(--border2);color:var(--text2)}
.btn-outline:hover{border-color:var(--cyan);color:var(--cyan)}
.btn-install{background:#7c3aed22;border:1px solid #7c3aed;color:#a855f7;padding:2px 7px;font-size:10px;border-radius:3px}
.btn-install:hover{background:#7c3aed44}
.sep{width:1px;height:20px;background:var(--border);margin:0 4px}

#config-toggle{cursor:pointer;display:flex;align-items:center;gap:5px;color:var(--text2);font-size:11px;border:1px solid var(--border);border-radius:4px;padding:4px 8px;transition:.15s}
#config-toggle:hover{border-color:var(--border2);color:var(--text)}

#config-panel{padding:12px 16px;background:#0b1220;border-bottom:1px solid var(--border);display:none;flex-wrap:wrap;gap:8px 16px}
#config-panel.open{display:flex}
.cfg-field{display:flex;flex-direction:column;gap:3px;min-width:180px}
.cfg-field label{font-size:10px;color:var(--text2);letter-spacing:.05em}
.cfg-field input{background:var(--card);border:1px solid var(--border);color:var(--text);font:inherit;font-size:11px;padding:4px 7px;border-radius:3px}
.cfg-save-row{display:flex;align-items:flex-end;padding-bottom:2px}
.cfg-save-row .btn{padding:4px 10px;font-size:11px}

/* ── Flow canvas ── */
#flow-wrap{flex:1;overflow-x:auto;overflow-y:auto;padding:24px 16px;position:relative;background:var(--terminal)}
#flow-canvas{position:relative;display:inline-flex;flex-direction:row;align-items:center;gap:0;min-height:300px}
#flow-svg{position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;overflow:visible}

/* ── Phase node ── */
.phase-node{position:relative;width:200px;flex-shrink:0;background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden;transition:.2s;cursor:pointer}
.phase-node:hover{border-color:var(--border2);box-shadow:0 4px 20px #00000066}
.phase-node.running{border-color:var(--cyan);animation:pulse-border 1.5s infinite}
.phase-node.done{border-color:#00ff8844}
.phase-node.skipped{opacity:.45}
@keyframes pulse-border{0%,100%{box-shadow:0 0 6px var(--cyan)}50%{box-shadow:0 0 16px var(--cyan)}}
.node-header{padding:8px 10px;display:flex;align-items:center;gap:6px}
.phase-badge{font-size:9px;font-weight:700;padding:2px 5px;border-radius:3px;background:#ffffff11;white-space:nowrap}
.node-title{font-size:12px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.node-desc{padding:0 10px 6px;font-size:10px;color:var(--text2);line-height:1.4}
.node-tools{padding:6px 10px;border-top:1px solid var(--border)}
.tool-row{display:flex;align-items:center;gap:5px;padding:2px 0}
.tool-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.tool-dot.ok{background:var(--green)}
.tool-dot.missing{background:var(--red)}
.tool-dot.python{background:var(--purple)}
.tool-name{font-size:10px;color:var(--text2);flex:1;overflow:hidden;text-overflow:ellipsis}
.tool-hint{font-size:9px;color:var(--text3);cursor:help;margin-left:3px;flex-shrink:0}
.tool-hint:hover{color:var(--cyan)}
.tool-row .btn-install{margin-left:auto;flex-shrink:0}
.node-keys{padding:6px 10px;border-top:1px solid var(--border);display:none}
.node-keys.open{display:block}
.node-keys-toggle{font-size:10px;color:var(--text2);cursor:pointer;margin-top:4px;padding:0 10px 6px}
.node-keys-toggle:hover{color:var(--cyan)}
.key-field{margin-bottom:4px}
.key-field label{font-size:9px;color:var(--text3);display:block}
.key-field input{background:var(--bg2);border:1px solid var(--border);color:var(--text);font:inherit;font-size:10px;padding:2px 5px;border-radius:3px;width:100%}

/* Phase connector arrow */
.phase-arrow{width:32px;flex-shrink:0;display:flex;align-items:center;justify-content:center;color:var(--border2);font-size:18px;user-select:none}

/* ── Console tab ── */
#panel-console{flex-direction:column}
#console-toolbar{padding:8px 16px;background:var(--bg2);border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-shrink:0}
#console-toolbar select{background:var(--card);border:1px solid var(--border2);color:var(--text);font:inherit;font-size:12px;padding:5px 8px;border-radius:4px}
#console-label{font-size:11px;color:var(--text2);flex:1}
#console-body{flex:1;overflow-y:auto;background:var(--terminal);padding:12px;font-size:12px;line-height:1.6}
#console-body .line{white-space:pre-wrap;word-break:break-all}
#console-body .line.success{color:var(--green)}
#console-body .line.error{color:var(--red)}
#console-body .line.warn{color:var(--yellow)}
#console-body .line.info{color:var(--cyan)}
#console-body .line.phase{color:var(--cyan);font-weight:700;margin-top:8px}
#console-body .line.plain{color:#7a8c9e}

/* ── Results tab ── */
#panel-results{flex-direction:row}
#results-tree{width:260px;flex-shrink:0;overflow-y:auto;border-right:1px solid var(--border);padding:8px 0;background:var(--bg2)}
#results-tree .dir-header{padding:6px 12px;font-size:11px;font-weight:600;color:var(--text2);cursor:pointer;display:flex;align-items:center;gap:5px}
#results-tree .dir-header:hover{background:var(--card)}
#results-tree .file-item{padding:4px 12px 4px 22px;font-size:11px;color:var(--text2);cursor:pointer;display:flex;align-items:center;gap:5px}
#results-tree .file-item:hover{background:var(--card);color:var(--cyan)}
#results-tree .file-item.active{color:var(--cyan);background:var(--card)}
#results-preview{flex:1;overflow-y:auto;padding:16px;background:var(--bg)}
#results-preview h4{margin-bottom:10px;color:var(--cyan);font-size:13px}
#results-preview table{border-collapse:collapse;font-size:11px;width:100%}
#results-preview th{background:var(--card);padding:5px 8px;text-align:left;border:1px solid var(--border);font-weight:600;color:var(--text2);font-size:10px}
#results-preview td{padding:4px 8px;border:1px solid var(--border);color:var(--text);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#results-preview tr:hover td{background:var(--card)}
#results-preview pre{background:var(--terminal);padding:12px;border-radius:4px;font-size:11px;white-space:pre-wrap;color:#7fdfb4;border:1px solid var(--border);max-height:600px;overflow-y:auto}
.placeholder{color:var(--text3);font-size:12px;padding:40px;text-align:center}

/* ── Intelligence tab ── */
#panel-intel{flex-direction:column}
#intel-top{display:flex;gap:16px;padding:12px 16px;background:var(--bg2);border-bottom:1px solid var(--border);flex-wrap:wrap;flex-shrink:0;align-items:flex-end}
#intel-top .cfg-field{min-width:160px}
#intel-context{padding:10px 16px;background:#060c18;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;flex-shrink:0;flex-wrap:wrap}
.context-badge{font-size:10px;padding:3px 8px;border-radius:3px;background:var(--card);border:1px solid var(--border2);color:var(--text2)}
.action-btns{display:flex;gap:6px;flex-wrap:wrap}
.action-btn{padding:4px 10px;font-size:11px;border-radius:4px;cursor:pointer;border:1px solid;font:inherit;font-weight:500;transition:.15s}
.action-btn.report{border-color:#f59e0b;color:#f59e0b;background:transparent}
.action-btn.report:hover{background:#f59e0b22}
.action-btn.summarize{border-color:var(--cyan);color:var(--cyan);background:transparent}
.action-btn.summarize:hover{background:#00d4ff22}
.action-btn.prioritize{border-color:var(--green);color:var(--green);background:transparent}
.action-btn.prioritize:hover{background:#00ff8822}
.action-btn.critical{border-color:var(--red);color:var(--red);background:transparent}
.action-btn.critical:hover{background:#ff444422}
#intel-chat{flex:1;overflow-y:auto;padding:16px;background:var(--terminal);display:flex;flex-direction:column;gap:12px}
.chat-msg{padding:10px 14px;border-radius:6px;font-size:12px;line-height:1.7;max-width:90%}
.chat-msg.user{align-self:flex-end;background:var(--card2);border:1px solid var(--border2)}
.chat-msg.bot{align-self:flex-start;background:#0a1f1a;border:1px solid #004d3322;color:var(--green);white-space:pre-wrap;max-width:100%}
.chat-msg.error{border-color:var(--red);color:var(--red);background:#1a0505}
.chat-spinner{align-self:center;color:var(--cyan);font-size:11px;animation:blink 1s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
#intel-input{padding:12px 16px;background:var(--bg2);border-top:1px solid var(--border);display:flex;gap:8px;flex-shrink:0}
#intel-input textarea{flex:1;background:var(--card);border:1px solid var(--border2);color:var(--text);font:inherit;font-size:12px;padding:8px 10px;border-radius:4px;resize:none;height:44px;outline:none}
#intel-input textarea:focus{border-color:var(--cyan)}

/* ── History tab ── */
#panel-history{flex-direction:column}
#history-body{flex:1;overflow-y:auto;padding:16px}
#history-body table{border-collapse:collapse;width:100%}
#history-body th{background:var(--card);padding:8px 10px;text-align:left;border:1px solid var(--border);font-size:11px;color:var(--text2);font-weight:600}
#history-body td{padding:7px 10px;border:1px solid var(--border);font-size:11px}
.badge{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:600}
.badge.running{background:#00d4ff22;color:var(--cyan);border:1px solid var(--cyan)}
.badge.completed{background:#00ff8822;color:var(--green);border:1px solid var(--green)}
.badge.failed{background:#ff444422;color:var(--red);border:1px solid var(--red)}
.badge.queued{background:#ffd70022;color:var(--yellow);border:1px solid var(--yellow)}
.lnk{color:var(--cyan);cursor:pointer;text-decoration:none}
.lnk:hover{text-decoration:underline}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}

/* ── Toast ── */
#toast{position:fixed;bottom:20px;right:20px;background:var(--card2);border:1px solid var(--border2);border-radius:6px;padding:10px 14px;font-size:12px;z-index:9999;display:none;max-width:300px}
#toast.ok{border-color:var(--green);color:var(--green)}
#toast.err{border-color:var(--red);color:var(--red)}
#toast.info{border-color:var(--cyan);color:var(--cyan)}

/* ── Builder tab ── */
#panel-builder{flex-direction:row}
#builder-toolbox{width:220px;flex-shrink:0;overflow-y:auto;border-right:1px solid var(--border);background:var(--bg2)}
#builder-main{flex:1;display:flex;flex-direction:column;overflow:hidden}
#builder-controls{padding:10px 14px;background:var(--bg2);border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-shrink:0;flex-wrap:wrap}
#builder-canvas-wrap{flex:1;overflow-x:auto;overflow-y:auto;padding:24px 16px;background:var(--terminal)}
#builder-canvas{display:inline-flex;flex-direction:row;align-items:flex-start;gap:0;min-height:200px;min-width:100%}
#builder-empty{color:var(--text3);font-size:12px;padding:40px;text-align:center;width:100%}
.tb-cat{padding:8px 12px 4px;font-size:10px;font-weight:700;letter-spacing:.08em;color:var(--text3);text-transform:uppercase;margin-top:4px}
.tb-tool{padding:5px 12px 5px 16px;font-size:11px;color:var(--text2);cursor:grab;display:flex;align-items:center;gap:6px;user-select:none}
.tb-tool:hover{background:var(--card);color:var(--text)}
.tb-tool.unavail{opacity:.45}
.bn{width:180px;flex-shrink:0;background:var(--card);border:1px solid var(--border);border-radius:6px;overflow:hidden;cursor:grab;transition:.15s;position:relative}
.bn:hover{border-color:var(--border2)}
.bn.drag-over{border-color:var(--cyan)!important;box-shadow:0 0 10px #00d4ff44}
.bn-header{padding:6px 8px;display:flex;align-items:center;gap:5px}
.bn-title{flex:1;font-size:11px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bn-rm{background:transparent;border:none;color:var(--text3);cursor:pointer;font-size:16px;line-height:1;padding:0 2px;flex-shrink:0}
.bn-rm:hover{color:var(--red)}
.bn-meta{padding:2px 8px 4px;font-size:9px;color:var(--text3);line-height:1.4}
.bn-warn{padding:0 8px 4px;font-size:9px;color:var(--red)}
.bn-flags{padding:4px 8px 6px;border-top:1px solid var(--border)}
.bn-flags-label{font-size:9px;color:var(--text3);margin-bottom:2px}
.bn-flags input{background:var(--bg2);border:1px solid var(--border);color:var(--text2);font:inherit;font-size:10px;padding:2px 5px;border-radius:3px;width:100%;outline:none}
.bn-flags input:focus{border-color:var(--cyan)}
/* Console stdin */
#stdin-row{padding:8px 12px;background:#0a1a0a;border-top:2px solid #00ff8833;display:none;align-items:center;gap:6px;flex-shrink:0;flex-wrap:wrap}
#stdin-row.visible{display:flex}
#stdin-prompt-label{font-size:11px;color:var(--yellow);white-space:nowrap;max-width:200px;overflow:hidden;text-overflow:ellipsis}
#stdin-input{flex:1;min-width:100px;background:var(--card);border:1px solid #00ff8866;color:var(--text);font:inherit;font-size:12px;padding:5px 8px;border-radius:3px;outline:none}
#stdin-input:focus{border-color:var(--green)}
.btn-yn{padding:4px 10px;font-size:11px;border-radius:3px;cursor:pointer;font:inherit;font-weight:700;border:1px solid}
.btn-yes{background:transparent;border-color:var(--green);color:var(--green)}
.btn-yes:hover{background:#00ff8822}
.btn-no{background:transparent;border-color:var(--red);color:var(--red)}
.btn-no:hover{background:#ff444422}
</style>
</head>
<body>

<div id="header">
  <div class="logo">⚡ RE<span>K</span></div>
  <div id="tabs">
    <button class="tab-btn active" onclick="switchTab('pipeline')">Pipeline</button>
    <button class="tab-btn" onclick="switchTab('console')">Console</button>
    <button class="tab-btn" onclick="switchTab('builder')">Builder</button>
    <button class="tab-btn" onclick="switchTab('results')">Results</button>
    <button class="tab-btn" onclick="switchTab('intel')">Intelligence</button>
    <button class="tab-btn" onclick="switchTab('history')">History</button>
  </div>
  <div id="hdr-status">● No active scan</div>
</div>

<div id="app">

<!-- ── PIPELINE ── -->
<div id="panel-pipeline" class="tab-panel active">
  <div id="pipeline-controls">
    <input id="domainInput" type="text" placeholder="target.com" style="width:200px">
    <input id="threadsInput" type="number" value="100" style="width:70px">
    <div class="sep"></div>
    <button class="btn btn-primary" onclick="launchPipeline()">▶ Launch Pipeline</button>
    <button class="btn btn-outline" onclick="stopScan()">■ Stop</button>
    <div class="sep"></div>
    <label style="font-size:11px;color:var(--text2);display:flex;align-items:center;gap:5px;cursor:pointer">
      <input type="checkbox" id="bb-mode-toggle" onchange="toggleBBMode(this.checked)"> BB Mode
    </label>
    <div id="bb-scope-row" style="display:none;align-items:center;gap:6px">
      <input id="bb-scope" type="text" placeholder="*.example.com, !internal.*" style="width:200px;background:var(--card);border:1px solid var(--border2);color:var(--text);font:inherit;font-size:11px;padding:4px 7px;border-radius:3px">
      <select id="bb-severity" style="background:var(--card);border:1px solid var(--border2);color:var(--text);font:inherit;padding:4px 6px;border-radius:3px;font-size:11px">
        <option value="all">All findings</option>
        <option value="critical_high">Critical + High only</option>
        <option value="critical">Critical only</option>
      </select>
    </div>
    <div class="sep"></div>
    <div id="config-toggle" onclick="toggleConfig()">⚙ API Keys &amp; Config ▾</div>
    <div id="scan-status" style="font-size:11px;color:var(--text2)"></div>
  </div>

  <div id="config-panel">
    <!-- Fields populated by JS from /api/config/get -->
    <div class="cfg-save-row">
      <button class="btn btn-outline" onclick="saveConfig()">💾 Save Config</button>
    </div>
  </div>

  <div id="flow-wrap">
    <div id="flow-canvas">
      <svg id="flow-svg"></svg>
      <!-- Phase nodes rendered by JS -->
    </div>
  </div>
</div>

<!-- ── CONSOLE ── -->
<div id="panel-console" class="tab-panel">
  <div id="console-toolbar">
    <select id="console-job-select" onchange="loadConsoleJob(this.value)">
      <option value="">— Select job —</option>
    </select>
    <span id="console-label"></span>
    <div style="flex:1"></div>
    <label style="font-size:11px;color:var(--text2);display:flex;align-items:center;gap:4px;cursor:pointer">
      <input type="checkbox" id="autoScroll" checked> Auto-scroll
    </label>
    <button class="btn btn-outline btn-sm" onclick="clearConsole()">Clear</button>
  </div>
  <div id="console-body"></div>
  <div id="stdin-row">
    <span id="stdin-prompt-label">⚡ Input required</span>
    <input id="stdin-input" type="text" placeholder="Type your response...">
    <button class="btn-yn btn-yes" onclick="sendStdinText('y')">Y</button>
    <button class="btn-yn btn-no" onclick="sendStdinText('n')">N</button>
    <button class="btn btn-outline btn-sm" onclick="sendStdin()">Send</button>
    <button class="btn btn-outline btn-sm" onclick="hideStdinRow()">✕</button>
  </div>
</div>

<!-- ── BUILDER ── -->
<div id="panel-builder" class="tab-panel">
  <div id="builder-toolbox">
    <!-- populated by renderToolbox() -->
  </div>
  <div id="builder-main">
    <div id="builder-controls">
      <input id="builder-domain" type="text" placeholder="target.com" style="width:180px;background:var(--card);border:1px solid var(--border2);color:var(--text);font:inherit;font-size:12px;padding:5px 8px;border-radius:4px;outline:none">
      <button class="btn btn-primary" onclick="runBuilderPipeline()">&#9654; Run Pipeline</button>
      <button class="btn btn-outline" onclick="previewBuilderScript()">&#128196; Preview Script</button>
      <button class="btn btn-outline" onclick="clearBuilder()">&#10005; Clear</button>
      <select id="pipeline-template" onchange="loadPipelineTemplate(this.value)" style="background:var(--card);border:1px solid var(--border2);color:var(--text);font:inherit;padding:4px 8px;border-radius:4px;font-size:11px">
        <option value="">&#128203; Load Template...</option>
        <option value="full_recon">Full Bug Bounty Recon</option>
        <option value="quick_surface">Quick Attack Surface</option>
        <option value="takeover_hunt">Subdomain Takeover Hunt</option>
        <option value="api_audit">API Security Audit</option>
        <option value="osint_deep">Deep OSINT</option>
      </select>
    </div>
    <div id="builder-canvas-wrap"
      ondragover="event.preventDefault()"
      ondrop="onCanvasDrop(event)">
      <div id="builder-canvas">
        <div id="builder-empty">
          <div style="text-align:center;padding:40px 20px;max-width:500px">
            <div style="font-size:24px;margin-bottom:12px">&#128296;</div>
            <div style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:8px">Build Your Custom Pipeline</div>
            <div style="font-size:11px;color:var(--text2);line-height:1.7;margin-bottom:16px">
              Drag tools from the left panel or click them to add.<br>
              Tools run in sequence &#8212; each step&#39;s output feeds the next.<br>
              Add extra flags per-tool using the flags input on each node.
            </div>
            <div style="font-size:10px;color:var(--text3);line-height:1.8">
              &#128161; <b style="color:var(--cyan)">Bug Bounty tip:</b> Start with subfinder &#8594; httpx &#8594; gospider &#8594; gf &#8594; nuclei<br>
              &#128161; <b style="color:var(--cyan)">Takeover tip:</b> subfinder &#8594; subzy + Takeover Check<br>
              &#128161; <b style="color:var(--cyan)">OSINT tip:</b> OSINT Engine &#8594; GitHub Dork &#8594; AI Triage
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ── RESULTS ── -->
<div id="panel-results" class="tab-panel">
  <div id="results-tree">
    <div id="wordlists-section" style="margin-top:8px;border-top:1px solid var(--border)"></div>
  </div>
  <div id="results-preview"><div class="placeholder">← Select a file to preview</div></div>
</div>

<!-- ── INTELLIGENCE ── -->
<div id="panel-intel" class="tab-panel">
  <div id="intel-top">
    <div class="cfg-field" style="min-width:120px">
      <label>PROVIDER</label>
      <select id="llm-provider" style="background:var(--card);border:1px solid var(--border2);color:var(--text);font:inherit;padding:4px 6px;border-radius:3px">
        <option value="local">Local (Ollama)</option>
        <option value="remote">Remote API</option>
      </select>
    </div>
    <div class="cfg-field">
      <label>MODEL</label>
      <input id="llm-model" type="text" placeholder="llama3.1 / gpt-4o" style="width:160px">
    </div>
    <div class="cfg-field" id="llm-apikey-field" style="display:none">
      <label>API KEY</label>
      <input id="llm-apikey" type="password" placeholder="sk-..." style="width:200px">
    </div>
    <div class="cfg-field" id="llm-url-field" style="display:none">
      <label>BASE URL</label>
      <input id="llm-baseurl" type="text" placeholder="http://127.0.0.1:11434" style="width:200px">
    </div>
    <button class="btn btn-outline btn-sm" onclick="testLLM()" style="margin-top:auto">Test</button>
  </div>

  <div id="intel-context">
    <select id="result-dir-select" style="background:var(--card);border:1px solid var(--border2);color:var(--text);font:inherit;padding:4px 6px;border-radius:3px;font-size:11px">
      <option value="">— Load results context —</option>
    </select>
    <button class="btn btn-outline btn-sm" onclick="loadResultContext()">📂 Load</button>
    <span id="context-badge" class="context-badge" style="display:none"></span>
    <div style="flex:1"></div>
    <div class="action-btns">
      <button class="action-btn report" onclick="runAction('report')">📋 Generate Report</button>
      <button class="action-btn summarize" onclick="runAction('summarize')">📊 Summarize</button>
      <button class="action-btn prioritize" onclick="runAction('prioritize')">🎯 Prioritize</button>
      <button class="action-btn critical" onclick="runAction('critical')">⚠ Critical Paths</button>
      <button class="action-btn" onclick="runAction('attack_chains')" style="border-color:#ff6b35;color:#ff6b35">🔗 Attack Chains</button>
      <button class="action-btn" onclick="runAction('quick_wins')" style="border-color:#ffd700;color:#ffd700">⚡ Quick Wins</button>
      <button class="action-btn" onclick="runAction('bb_report')" style="border-color:#00d4ff;color:#00d4ff;background:transparent">&#127919; BB Report</button>
    </div>
  </div>

  <div id="intel-chat"></div>

  <div id="intel-input">
    <textarea id="intel-prompt" placeholder="Ask a question about the scan results... (Enter to send, Shift+Enter for newline)"
      onkeydown="handleIntelKey(event)"></textarea>
    <button class="btn btn-primary" onclick="sendIntelPrompt()">Send</button>
  </div>
</div>

<!-- ── HISTORY ── -->
<div id="panel-history" class="tab-panel">
  <div id="history-toolbar" style="padding:8px 16px;background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0;display:flex;gap:8px;align-items:center">
    <span style="font-size:12px;color:var(--text2)">Scan History</span>
    <button class="btn btn-outline btn-sm" onclick="refreshHistory()">⟳ Refresh</button>
  </div>
  <div id="history-body" style="flex:1;overflow-y:auto;padding:0 16px 16px">
    <table style="width:100%;border-collapse:collapse;margin-top:12px">
      <thead>
        <tr>
          <th style="padding:8px 10px;background:var(--card);border:1px solid var(--border);font-size:11px;text-align:left;color:var(--text2)">ID</th>
          <th style="padding:8px 10px;background:var(--card);border:1px solid var(--border);font-size:11px;text-align:left;color:var(--text2)">Domain</th>
          <th style="padding:8px 10px;background:var(--card);border:1px solid var(--border);font-size:11px;text-align:left;color:var(--text2)">Type</th>
          <th style="padding:8px 10px;background:var(--card);border:1px solid var(--border);font-size:11px;text-align:left;color:var(--text2)">Status</th>
          <th style="padding:8px 10px;background:var(--card);border:1px solid var(--border);font-size:11px;text-align:left;color:var(--text2)">Started</th>
          <th style="padding:8px 10px;background:var(--card);border:1px solid var(--border);font-size:11px;text-align:left;color:var(--text2)">Duration</th>
          <th style="padding:8px 10px;background:var(--card);border:1px solid var(--border);font-size:11px;text-align:left;color:var(--text2)">Actions</th>
        </tr>
      </thead>
      <tbody id="history-tbody"></tbody>
    </table>
  </div>
</div>

</div><!-- #app -->

<div id="toast"></div>

<script>
// =====================================================================
//  Phase definitions
// =====================================================================
const PHASES = [
  { id:'p0',  num:'0',   label:'Cloud Recon',       color:'#7c3aed', tools:['(Py) cloud_recon'],    cli:[],                         desc:'S3 / Azure / GCP bucket enumeration', keys:[] },
  { id:'p1',  num:'1',   label:'Subdomain Enum',     color:'#0ea5e9', tools:['subfinder','assetfinder','findomain','chaos','github-subdomains'], cli:['subfinder','assetfinder','findomain','chaos'], desc:'Multi-source subdomain discovery', keys:['CHAOS_API_KEY','GITHUB_API_TOKEN','GITLAB_API_TOKEN'] },
  { id:'p2',  num:'2',   label:'Permutation',        color:'#06b6d4', tools:['dnsgen','goaltdns','gotator','ripgen','puredns'],       cli:['dnsgen','goaltdns','gotator','ripgen','puredns'], desc:'DNS permutation & brute-force', keys:[] },
  { id:'p25', num:'2.5', label:'ASN Expansion',      color:'#10b981', tools:['asnmap','(Py) asn_recon'],  cli:['asnmap'],            desc:'IP range & ASN enumeration', keys:[] },
  { id:'p3',  num:'3',   label:'Live Detection',     color:'#f59e0b', tools:['httpx'],                    cli:['httpx'],             desc:'HTTP probing & fingerprinting', keys:[] },
  { id:'p35', num:'3.5', label:'Takeover Check',     color:'#ef4444', tools:['subzy','(Py) takeover'],    cli:['subzy'],             desc:'Subdomain takeover detection', keys:[] },
  { id:'p36', num:'3.6', label:'Favicon Scan',       color:'#8b5cf6', tools:['(Py) favicon'],             cli:[],                    desc:'MurmurHash3 fingerprinting', keys:[] },
  { id:'p37', num:'3.7', label:'Headers Audit',      color:'#f97316', tools:['(Py) headers_audit'],       cli:[],                    desc:'CORS & security headers', keys:[] },
  { id:'p4',  num:'4',   label:'Port Scanning',      color:'#ec4899', tools:['naabu'],                    cli:['naabu'],             desc:'Port & service detection', keys:[] },
  { id:'p45', num:'4.5', label:'Wayback Mining',     color:'#14b8a6', tools:['waybackurls','gau'],         cli:['waybackurls','gau'],  desc:'Passive historical URLs', keys:[] },
  { id:'p5',  num:'5',   label:'Content Discovery',  color:'#3b82f6', tools:['gospider','katana','gau'],   cli:['gospider','katana','gau'], desc:'Web spidering & crawling', keys:[] },
  { id:'p6',  num:'6',   label:'Vuln Analysis',      color:'#f59e0b', tools:['gf'],                        cli:['gf'],                desc:'GF patterns (XSS/SQLi/SSRF/...)', keys:[] },
  { id:'p75', num:'7.5', label:'Param Discovery',    color:'#06b6d4', tools:['arjun','(Py) param_disco'],  cli:['arjun'],             desc:'Hidden parameter discovery', keys:[] },
  { id:'p76', num:'7.6', label:'Nuclei Scan',        color:'#ef4444', tools:['nuclei'],                    cli:['nuclei'],            desc:'Template-based vuln scanning', keys:[] },
  { id:'p77', num:'7.7', label:'GitHub Dorking',     color:'#a855f7', tools:['(Py) github_dork'],          cli:[],                    desc:'Secrets & credentials search', keys:['GITHUB_API_TOKEN'] },
  { id:'p8',  num:'8',   label:'JS Analysis',        color:'#10b981', tools:['getjs','cariddi'],            cli:['getjs','cariddi'],   desc:'Secrets in JavaScript files', keys:[] },
];

// =====================================================================
//  Tool Catalog (Builder)
// =====================================================================
const TOOL_CATALOG = [
  {id:'subfinder',   label:'subfinder',       cat:'Subdomain', color:'#0ea5e9', type:'go',     desc:'Passive subdomain discovery', outFile:'subdomains.txt'},
  {id:'assetfinder', label:'assetfinder',     cat:'Subdomain', color:'#0ea5e9', type:'go',     desc:'Asset-based subdomain finder', outFile:'subdomains.txt'},
  {id:'findomain',   label:'findomain',       cat:'Subdomain', color:'#0ea5e9', type:'go',     desc:'Fast subdomain discovery', outFile:'subdomains.txt'},
  {id:'puredns',     label:'puredns',         cat:'DNS',       color:'#06b6d4', type:'go',     desc:'DNS brute-force & resolve', outFile:'resolved.txt'},
  {id:'dnsgen',      label:'dnsgen',          cat:'DNS',       color:'#06b6d4', type:'go',     desc:'DNS permutation generator', inFile:'subdomains.txt', outFile:'dnsgen.txt'},
  {id:'gotator',     label:'gotator',         cat:'DNS',       color:'#06b6d4', type:'go',     desc:'DNS permutation engine', inFile:'subdomains.txt', outFile:'gotator.txt'},
  {id:'ripgen',      label:'ripgen',          cat:'DNS',       color:'#06b6d4', type:'go',     desc:'Subdomain permutations', inFile:'subdomains.txt', outFile:'ripgen.txt'},
  {id:'asnmap',      label:'asnmap',          cat:'OSINT',     color:'#10b981', type:'go',     desc:'ASN IP range expansion', outFile:'asn-ips.txt'},
  {id:'httpx',       label:'httpx',           cat:'Probe',     color:'#f59e0b', type:'go',     desc:'HTTP probe & fingerprint', inFile:'subdomains.txt', outFile:'hosts-alive.txt'},
  {id:'naabu',       label:'naabu',           cat:'Ports',     color:'#ec4899', type:'go',     desc:'Port & service scanner', inFile:'hosts-alive.txt', outFile:'ports.txt'},
  {id:'subzy',       label:'subzy',           cat:'Takeover',  color:'#ef4444', type:'go',     desc:'Subdomain takeover check', inFile:'subdomains.txt', outFile:'subzy.txt'},
  {id:'gospider',    label:'gospider',        cat:'Crawl',     color:'#3b82f6', type:'go',     desc:'Web spider', inFile:'hosts-alive.txt', outFile:'gospider-urls.txt'},
  {id:'katana',      label:'katana',          cat:'Crawl',     color:'#3b82f6', type:'go',     desc:'Next-gen web crawler', inFile:'hosts-alive.txt', outFile:'urls.txt'},
  {id:'gau',         label:'gau',             cat:'Crawl',     color:'#14b8a6', type:'go',     desc:'Historical URLs (gau)', outFile:'gau-urls.txt'},
  {id:'waybackurls', label:'waybackurls',     cat:'Crawl',     color:'#14b8a6', type:'go',     desc:'Wayback Machine URLs', outFile:'wayback-urls.txt'},
  {id:'gf-xss',      label:'gf (xss)',        cat:'Patterns',  color:'#f59e0b', type:'go',     desc:'GF pattern: XSS', inFile:'urls.txt', outFile:'gf-xss.txt'},
  {id:'gf-sqli',     label:'gf (sqli)',       cat:'Patterns',  color:'#f59e0b', type:'go',     desc:'GF pattern: SQLi', inFile:'urls.txt', outFile:'gf-sqli.txt'},
  {id:'gf-ssrf',     label:'gf (ssrf)',       cat:'Patterns',  color:'#f59e0b', type:'go',     desc:'GF pattern: SSRF', inFile:'urls.txt', outFile:'gf-ssrf.txt'},
  {id:'gf-redirect', label:'gf (redirect)',   cat:'Patterns',  color:'#f59e0b', type:'go',     desc:'GF pattern: Redirect', inFile:'urls.txt', outFile:'gf-redirect.txt'},
  {id:'nuclei',      label:'nuclei',          cat:'Scanner',   color:'#ef4444', type:'go',     desc:'Template-based vuln scanner', inFile:'hosts-alive.txt', outFile:'nuclei.txt'},
  {id:'getjs',       label:'getJS',           cat:'JS',        color:'#10b981', type:'go',     desc:'Extract JS files', inFile:'hosts-alive.txt', outFile:'js-files.txt'},
  {id:'cariddi',     label:'cariddi',         cat:'JS',        color:'#10b981', type:'go',     desc:'JS secrets & endpoints', inFile:'hosts-alive.txt', outFile:'cariddi.txt'},
  {id:'py-cloud',    label:'Cloud Recon',     cat:'Cloud',     color:'#7c3aed', type:'python', desc:'S3/Azure/GCP buckets', outFile:'cloud.csv'},
  {id:'py-takeover', label:'Takeover Check',  cat:'Takeover',  color:'#ef4444', type:'python', desc:'Subdomain takeover (Python)', inFile:'subdomains.txt', outFile:'takeover.csv'},
  {id:'py-headers',  label:'Headers Audit',   cat:'Audit',     color:'#f97316', type:'python', desc:'CORS & security headers', inFile:'hosts-alive.txt', outFile:'headers.csv'},
  {id:'py-favicon',  label:'Favicon Hash',    cat:'Audit',     color:'#8b5cf6', type:'python', desc:'MurmurHash3 fingerprint', inFile:'hosts-alive.txt', outFile:'favicon.csv'},
  {id:'py-params',   label:'Param Discovery', cat:'Params',    color:'#06b6d4', type:'python', desc:'Hidden parameter discovery', inFile:'hosts-alive.txt', outFile:'params.csv'},
  {id:'py-github',   label:'GitHub Dork',     cat:'OSINT',     color:'#a855f7', type:'python', desc:'Secrets & credentials search', outFile:'github-dorks.csv'},
  {id:'py-asn',      label:'ASN Recon',       cat:'OSINT',     color:'#10b981', type:'python', desc:'IP range & ASN enum', outFile:'asn.csv'},
  {id:'py-aivuln',  label:'AI Vuln Scan',       cat:'AI Scanner', color:'#ff6b35', type:'python', desc:'AI-assisted scanning: nuclei + gf patterns + smart scoring', inFile:'hosts-alive.txt', outFile:'ai-scan.csv'},
  {id:'py-osint',   label:'OSINT Engine',       cat:'OSINT',      color:'#06b6d4', type:'python', desc:'Email harvest, tech detect, breach check', outFile:'osint-report.json'},
  {id:'py-triage',  label:'AI Triage',          cat:'AI Scanner', color:'#ff6b35', type:'python', desc:'AI finding prioritization & attack chains', outFile:'triage-report.json'},
];

// Tool status cache
let toolStatus = {};
let configData = {};
let activeJobId = null;
let consoleSource = null;
let currentResultDir = null;

// Builder state
let builderNodes = [];
let builderDragSrc = null;
let builderDragNode = null;

// =====================================================================
//  Utilities
// =====================================================================
function toast(msg, type='info'){
  const t=document.getElementById('toast');
  t.textContent=msg; t.className=type; t.style.display='block';
  setTimeout(()=>t.style.display='none',3000);
}
function fmtDuration(start,end){
  if(!start) return '—';
  const s=new Date(start), e=end?new Date(end):new Date();
  const d=Math.floor((e-s)/1000);
  if(d<60) return d+'s';
  if(d<3600) return Math.floor(d/60)+'m '+d%60+'s';
  return Math.floor(d/3600)+'h '+Math.floor((d%3600)/60)+'m';
}
function fmtTime(iso){
  if(!iso) return '—';
  return new Date(iso).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
}
function classifyLine(l){
  if(/\[✓\]|\[OK\]|completed|success/i.test(l)) return 'success';
  if(/\[!\]|error|ERROR|failed|FAIL/i.test(l)) return 'error';
  if(/warning|WARN|\[\?\]/i.test(l)) return 'warn';
  if(/\[\+\]|Phase|Step|Running/i.test(l)) return 'phase';
  if(/\[\*\]|INFO/i.test(l)) return 'info';
  return 'plain';
}

// =====================================================================
//  Tab switching
// =====================================================================
function switchTab(name){
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
  document.querySelectorAll('.tab-btn').forEach(b=>{
    if(b.textContent.toLowerCase().includes(name.substring(0,4))) b.classList.add('active');
  });
  if(name==='results') loadResults();
  if(name==='history') refreshHistory();
  if(name==='console') refreshConsoleJobList();
  if(name==='builder') renderToolbox();
}

// =====================================================================
//  Config panel
// =====================================================================
function toggleConfig(){
  const p=document.getElementById('config-panel');
  p.classList.toggle('open');
  if(p.classList.contains('open') && Object.keys(configData).length===0) loadConfig();
}
async function loadConfig(){
  const r=await fetch('/api/config/get');
  configData=await r.json();
  renderConfigPanel();
}
function renderConfigPanel(){
  const p=document.getElementById('config-panel');
  // Remove old fields (keep save row)
  p.querySelectorAll('.cfg-field').forEach(el=>el.remove());
  const saveRow=p.querySelector('.cfg-save-row');
  const fields=[
    {k:'CHAOS_API_KEY',label:'Chaos API Key'},
    {k:'GITHUB_API_TOKEN',label:'GitHub Token'},
    {k:'GITLAB_API_TOKEN',label:'GitLab Token'},
    {k:'SHODAN_API_KEY',label:'Shodan API Key'},
    {k:'HIBP_API_KEY',label:'HIBP API Key'},
    {k:'HUNTER_API_KEY',label:'Hunter.io API Key'},
    {k:'SLACK_WEBHOOK_URL',label:'Slack Webhook'},
    {k:'DISCORD_WEBHOOK_URL',label:'Discord Webhook'},
    {k:'THREADS',label:'Default Threads'},
    {k:'MONITOR_INTERVAL',label:'Monitor Interval (min)'},
  ];
  fields.forEach(({k,label})=>{
    const d=document.createElement('div'); d.className='cfg-field';
    d.innerHTML=`<label>${label}</label><input data-key="${k}" type="${k.includes('KEY')||k.includes('TOKEN')||k.includes('WEBHOOK')?'password':'text'}" value="${configData[k]||''}" placeholder="${k}">`;
    p.insertBefore(d,saveRow);
  });
}
async function saveConfig(){
  const inputs=document.getElementById('config-panel').querySelectorAll('input[data-key]');
  const data={};
  inputs.forEach(i=>data[i.dataset.key]=i.value);
  const r=await fetch('/api/config/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
  const d=await r.json();
  if(d.saved) toast('Config saved ✓','ok');
  else toast('Save failed','err');
  configData=Object.assign(configData,data);
}

// =====================================================================
//  Prerequisites check
// =====================================================================
async function checkPrerequisites(){
  const r=await fetch('/api/prerequisites');
  const d=await r.json();
  toolStatus=d.cli_tools||{};
  renderFlow();
}

// =====================================================================
//  Tool guidance hints (flags + tips shown in pipeline & builder)
// =====================================================================
const TOOL_GUIDANCE = {
  'subfinder':   {flags: '-d domain -o out.txt -all -silent', tip: 'Use -all for all sources. Add -rl 10 to rate-limit.'},
  'assetfinder': {flags: '--subs-only domain', tip: 'Fast passive enum. No API keys required.'},
  'httpx':       {flags: '-l hosts.txt -sc -title -td -o alive.txt', tip: '-sc=status code, -td=tech detect, -fr=follow redirects'},
  'naabu':       {flags: '-list hosts.txt -p 80,443,8080,8443 -o ports.txt', tip: 'Use -top-ports 1000 for comprehensive scan. Needs root for SYN scan.'},
  'nuclei':      {flags: '-l hosts.txt -t cves/ -s critical,high -o findings.txt', tip: 'Use -tags cve,rce,sqli for targeted scan. -rl 10 for rate limiting.'},
  'gospider':    {flags: '-S hosts.txt -c 10 -d 3 -o crawl/', tip: '-c=concurrency, -d=depth, --blacklist jpg,png,gif'},
  'katana':      {flags: '-list hosts.txt -d 3 -jc -o urls.txt', tip: '-jc=JS crawling. Add -kf all for all headers.'},
  'gau':         {flags: 'domain --o urls.txt --threads 10', tip: 'Fetches URLs from Wayback, OTX, CommonCrawl. Use --blacklist jpg,png'},
  'gf':          {flags: '-list urls.txt | gf xss > xss.txt', tip: 'Patterns: xss, sqli, ssrf, redirect, lfi, rce, idor, cors, debug'},
  'puredns':     {flags: 'bruteforce wordlist.txt domain -r resolvers.txt', tip: 'Needs a resolvers.txt. Uses massdns under the hood for speed.'},
  'subzy':       {flags: 'run --targets subs.txt --hide-fails', tip: 'Checks CNAME records against 50+ vulnerable service fingerprints.'},
  'waybackurls': {flags: 'domain | tee wayback.txt', tip: 'Pipe to httpx for live URL check. Filter with grep "api|admin|login"'},
  'getjs':       {flags: '--input hosts.txt --output js.txt --complete', tip: 'Use --complete for absolute URLs. Then run secretfinder on output.'},
  'asnmap':      {flags: '-d domain -o asn.txt', tip: 'Maps domain to ASN then expands to all IPs in that ASN range.'},
};

// =====================================================================
//  Flow pipeline rendering
// =====================================================================
function renderFlow(){
  const canvas=document.getElementById('flow-canvas');
  // Remove old nodes/arrows (keep SVG)
  canvas.querySelectorAll('.phase-node,.phase-arrow').forEach(el=>el.remove());
  const svg=document.getElementById('flow-svg');

  PHASES.forEach((phase,i)=>{
    // Arrow before (except first)
    if(i>0){
      const arr=document.createElement('div');
      arr.className='phase-arrow'; arr.textContent='→';
      canvas.appendChild(arr);
    }
    const node=document.createElement('div');
    node.className='phase-node'; node.id='node-'+phase.id;
    node.style.borderTopColor=phase.color;
    node.style.borderTopWidth='3px';

    // Tool rows
    const toolsHtml=phase.tools.map(t=>{
      const isPy=t.startsWith('(Py)');
      const toolName=isPy?t:t;
      const dotClass=isPy?'python':(toolStatus[t]?'ok':'missing');
      const installBtn=(!isPy&&!toolStatus[t])?`<button class="btn-install" onclick="installTool('${t}',event)">↓</button>`:'';
      const g=TOOL_GUIDANCE[t];
      const hint=g?`<span class="tool-hint" title="Flags: ${g.flags}&#10;Tip: ${g.tip}">&#x2139;</span>`:'';
      return `<div class="tool-row"><span class="tool-dot ${dotClass}"></span><span class="tool-name">${toolName}</span>${hint}${installBtn}</div>`;
    }).join('');

    // API key fields
    let keysHtml='';
    if(phase.keys.length>0){
      const keyFields=phase.keys.map(k=>`<div class="key-field"><label>${k}</label><input data-cfgkey="${k}" type="password" value="${configData[k]||''}" placeholder="${k}" onchange="configData['${k}']=this.value"></div>`).join('');
      keysHtml=`<div class="node-keys-toggle" onclick="toggleNodeKeys('${phase.id}')">🔑 API Keys ▾</div><div class="node-keys" id="nodekeys-${phase.id}">${keyFields}</div>`;
    }

    node.innerHTML=`
      <div class="node-header" style="background:${phase.color}18">
        <span class="phase-badge" style="background:${phase.color}33;color:${phase.color}">P${phase.num}</span>
        <span class="node-title" title="${phase.label}">${phase.label}</span>
      </div>
      <div class="node-desc">${phase.desc}</div>
      <div class="node-tools">${toolsHtml}</div>
      ${keysHtml}
    `;
    canvas.appendChild(node);
  });
}

function toggleNodeKeys(phaseId){
  document.getElementById('nodekeys-'+phaseId).classList.toggle('open');
}

// =====================================================================
//  Tool install — permission-aware flow
// =====================================================================
async function installTool(toolId, evt) {
  evt && evt.stopPropagation();
  // Step 1: fetch install info without running anything
  let info;
  try {
    info = await fetch('/api/tool/install', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({tool: toolId, check_only: true})
    }).then(r => r.json());
  } catch(e) {
    toast('Failed to reach server: ' + e.message, 'err');
    return;
  }
  if (info.error) { toast(info.error, 'err'); return; }
  // Step 2: show permission dialog before executing
  showInstallModal(toolId, info);
}

function showInstallModal(toolId, info) {
  // Remove any existing modal
  document.getElementById('install-modal')?.remove();
  const modal = document.createElement('div');
  modal.id = 'install-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:#000a;z-index:9999;display:flex;align-items:center;justify-content:center';
  modal.innerHTML = `
    <div style="background:var(--card);border:1px solid var(--border2);border-radius:8px;padding:24px;max-width:500px;width:90%;font-family:var(--font)">
      <div style="font-size:14px;font-weight:700;color:var(--cyan);margin-bottom:12px">Install ${info.label || toolId}</div>
      <div style="font-size:11px;color:var(--text2);margin-bottom:8px">Method: <span style="color:var(--text)">${info.method || 'go install'}</span></div>
      <div style="font-size:11px;color:var(--text2);margin-bottom:6px">Command:</div>
      <pre style="background:var(--terminal);border:1px solid var(--border);border-radius:4px;padding:8px;font-size:11px;color:var(--green);margin-bottom:12px;white-space:pre-wrap">${info.install_cmd || ''}</pre>
      <div style="font-size:10px;color:var(--yellow);margin-bottom:16px">&#9888; This will execute with your current user permissions. Go tools install to ~/go/bin.</div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button class="btn btn-outline btn-sm" onclick="document.getElementById('install-modal').remove()">Cancel</button>
        <button class="btn btn-primary btn-sm" onclick="doInstall('${toolId}')">Confirm &amp; Install</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
}

async function doInstall(toolId) {
  document.getElementById('install-modal')?.remove();
  toast(`Installing ${toolId}...`, 'info');
  let d;
  try {
    const r = await fetch('/api/tool/install', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({tool: toolId, check_only: false})
    });
    d = await r.json();
  } catch(e) {
    toast('Install request failed: ' + e.message, 'err');
    return;
  }
  if (d.job_id) {
    switchTab('console');
    refreshConsoleJobList(d.job_id);
    streamJob(d.job_id);
    watchJob(d.job_id, toolId, () => {
      checkPrerequisites();
      renderFlow();
      if (typeof renderToolbox === 'function') renderToolbox();
      toast(`${toolId} installed ✓`, 'ok');
    });
  } else {
    toast(d.error || 'Install failed', 'err');
  }
}

// =====================================================================
//  Launch scan
// =====================================================================
async function launchPipeline(){
  const domain=document.getElementById('domainInput').value.trim();
  const threads=document.getElementById('threadsInput').value||'100';
  if(!domain){toast('Enter a target domain','err');return;}
  // Save any config changes first
  if(Object.keys(configData).length>0) await saveConfig();
  const r=await fetch('/api/scan/playbook',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain,playbook:'v1',threads:parseInt(threads)})});
  const d=await r.json();
  if(d.error){toast(d.error,'err');return;}
  activeJobId=d.job_id;
  toast(`Scan started: job ${d.job_id}`,'ok');
  document.getElementById('hdr-status').textContent=`● Scanning ${domain}`;
  document.getElementById('scan-status').textContent=`Job: ${d.job_id}`;
  if(d.install_job_id) toast(`Installing prerequisites first (job ${d.install_job_id})`,'info');
  // Auto-switch to console
  switchTab('console');
  refreshConsoleJobList(d.job_id);
  streamJob(d.job_id);
}

async function stopScan(){
  if(!activeJobId){toast('No active scan','err');return;}
  const r=await fetch('/api/scan/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:activeJobId})});
  const d=await r.json();
  toast(d.stopped?'Scan stopped':'Could not stop',d.stopped?'ok':'err');
  if(d.stopped){activeJobId=null;document.getElementById('hdr-status').textContent='● No active scan';}
}

// =====================================================================
//  Bug Bounty Mode
// =====================================================================
let bugBountyMode = false;
function toggleBBMode(on) {
  bugBountyMode = on;
  document.getElementById('bb-scope-row').style.display = on ? 'flex' : 'none';
  if (on) toast('Bug Bounty Mode enabled — scope filtering active', 'info');
}

// =====================================================================
//  Console
// =====================================================================
function clearConsole(){document.getElementById('console-body').innerHTML='';}
function appendLine(text){
  const body=document.getElementById('console-body');
  const div=document.createElement('div');
  div.className='line '+classifyLine(text);
  div.textContent=text;
  body.appendChild(div);
  if(document.getElementById('autoScroll').checked) body.scrollTop=body.scrollHeight;
  // Detect interactive prompts
  const PROMPT_RE = /\[y\/n\]|\[Y\/N\]|\[yes\/no\]|\(y\/n\)|\(Y\/N\)|password:|Password:|Enter |press enter|continue\?|\? $/i;
  if(PROMPT_RE.test(text) && activeJobId){
    showStdinRow(text.trim().substring(0,80));
  }
}

// =====================================================================
//  Console stdin
// =====================================================================
function showStdinRow(promptText){
  const row=document.getElementById('stdin-row');
  const lbl=document.getElementById('stdin-prompt-label');
  lbl.textContent=promptText||'⚡ Input required';
  row.classList.add('visible');
  document.getElementById('stdin-input').focus();
}
function hideStdinRow(){
  document.getElementById('stdin-row').classList.remove('visible');
  document.getElementById('stdin-input').value='';
}
async function sendStdin(){
  const inp=document.getElementById('stdin-input');
  const text=inp.value;
  if(!activeJobId){toast('No active job','err');return;}
  inp.value='';
  hideStdinRow();
  appendLine('> '+text);
  try{
    await fetch('/api/scan/stdin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:activeJobId,text})});
  }catch(e){toast('stdin send failed','err');}
}
function sendStdinText(text){
  document.getElementById('stdin-input').value=text;
  sendStdin();
}

async function refreshConsoleJobList(selectId=null){
  const r=await fetch('/api/jobs');
  const d=await r.json();
  const sel=document.getElementById('console-job-select');
  sel.innerHTML='<option value="">— Select job —</option>';
  (d.jobs||[]).slice(0,20).forEach(j=>{
    const opt=document.createElement('option');
    opt.value=j.id;
    opt.textContent=`${j.id} | ${j.domain} | ${j.scan_type} | ${j.status}`;
    sel.appendChild(opt);
  });
  if(selectId){sel.value=selectId;}
}

async function loadConsoleJob(jobId){
  if(!jobId) return;
  clearConsole();
  // Load existing log
  const r=await fetch(`/api/log?id=${jobId}&lines=500`);
  const d=await r.json();
  if(d.log){
    d.log.split('\n').forEach(l=>appendLine(l));
  }
  // Setup label
  document.getElementById('console-label').textContent=`Job: ${jobId} | Domain: ${d.domain||'?'} | ${d.status||'?'}`;
  // Start streaming if job is running
  if(d.status==='running'||d.status==='queued') streamJob(jobId);
}

function streamJob(jobId){
  if(consoleSource){consoleSource.close();}
  consoleSource=new EventSource(`/api/stream?id=${jobId}`);
  consoleSource.addEventListener('log',e=>appendLine(e.data));
  consoleSource.addEventListener('status',e=>{
    try{
      const s=JSON.parse(e.data);
      const status=s.status||'?';
      if(status==='running'){
        showStdinRow('⚡ Input required');
        hideStdinRow(); // show the row but keep it hidden until prompt detected
      }
      if(status==='completed'){
        appendLine('[REK] ✓ Scan completed.');
        document.getElementById('hdr-status').textContent='● No active scan';
        hideStdinRow();
        checkPrerequisites(); // refresh tool status
      } else if(status==='failed'){
        appendLine('[REK] ✗ Scan failed.');
        document.getElementById('hdr-status').textContent='● No active scan';
        hideStdinRow();
      }
      if(['completed','failed'].includes(status)){
        consoleSource.close();
        refreshHistory();
      }
    }catch(err){}
  });
  consoleSource.onerror=()=>{consoleSource.close();};
}

function watchJob(jobId, label, onDone){
  const poll=setInterval(async()=>{
    const r=await fetch('/api/jobs');
    const d=await r.json();
    const job=(d.jobs||[]).find(j=>j.id===jobId);
    if(!job) return;
    if(['completed','failed'].includes(job.status)){
      clearInterval(poll);
      if(job.status==='completed') onDone();
    }
  },2000);
}

// =====================================================================
//  Results explorer
// =====================================================================
async function loadResults(){
  const r=await fetch('/api/results');
  const d=await r.json();
  const tree=document.getElementById('results-tree');
  tree.innerHTML='<div id="wordlists-section" style="margin-top:8px;border-top:1px solid var(--border)"></div>';

  // Populate result-dir-select for Intel tab
  const sel=document.getElementById('result-dir-select');
  const curVal=sel.value;
  sel.innerHTML='<option value="">— Load results context —</option>';

  (d.dirs||[]).forEach(dir=>{
    const opt=document.createElement('option');
    opt.value=dir.path; opt.textContent=dir.name;
    sel.appendChild(opt);
    if(dir.path===curVal) sel.value=curVal;

    const header=document.createElement('div');
    header.className='dir-header';
    header.innerHTML=`<span style="color:var(--cyan)">▶</span>${dir.name}`;
    let expanded=false;
    const filesContainer=document.createElement('div');
    filesContainer.style.display='none';
    header.onclick=()=>{
      expanded=!expanded;
      filesContainer.style.display=expanded?'block':'none';
      header.querySelector('span').textContent=expanded?'▼':'▶';
    };
    tree.appendChild(header);
    tree.appendChild(filesContainer);

    (dir.files||[]).forEach(f=>{
      const item=document.createElement('div');
      item.className='file-item';
      item.innerHTML=`<span style="color:var(--text3)">∙</span>${f.name} <span style="color:var(--text3);font-size:10px">(${(f.size/1024).toFixed(1)}k)</span>`;
      item.onclick=()=>{
        document.querySelectorAll('.file-item').forEach(i=>i.classList.remove('active'));
        item.classList.add('active');
        previewFile(f);
      };
      filesContainer.appendChild(item);
    });
  });

  // ── Wordlists section ──────────────────────────────────────────────
  try {
    const wr = await fetch('/api/wordlists');
    const wd = await wr.json();
    const wlSection = document.getElementById('wordlists-section');
    if (wlSection && (wd.wordlists||[]).length > 0) {
      const wlHeader = document.createElement('div');
      wlHeader.className = 'dir-header';
      wlHeader.style.cssText = 'color:var(--purple);margin-top:4px';
      wlHeader.innerHTML = `<span style="color:var(--purple)">▶</span>&#128203; Wordlists`;
      let wlExpanded = false;
      const wlContainer = document.createElement('div');
      wlContainer.style.display = 'none';
      wlHeader.onclick = () => {
        wlExpanded = !wlExpanded;
        wlContainer.style.display = wlExpanded ? 'block' : 'none';
        wlHeader.querySelector('span').textContent = wlExpanded ? '▼' : '▶';
      };
      wlSection.appendChild(wlHeader);
      wlSection.appendChild(wlContainer);
      (wd.wordlists||[]).forEach(wf => {
        const item = document.createElement('div');
        item.className = 'file-item';
        item.innerHTML = `<span style="color:var(--purple)">∙</span>${wf.name} <span style="color:var(--text3);font-size:10px">(${(wf.size/1024).toFixed(1)}k)</span>`;
        item.onclick = () => {
          document.querySelectorAll('.file-item').forEach(i=>i.classList.remove('active'));
          item.classList.add('active');
          // Preview first 50 lines of wordlist
          previewWordlist(wf);
        };
        wlContainer.appendChild(item);
      });
    }
  } catch(e) { /* wordlists section is non-critical */ }
}

async function previewWordlist(wf) {
  const preview = document.getElementById('results-preview');
  try {
    const r = await fetch(`/api/file/text?path=${encodeURIComponent(wf.path)}&limit=50`);
    const d = await r.json();
    const text = (d.text || '').split('\n').slice(0, 50).join('\n');
    const totalLines = (d.text || '').split('\n').length;
    preview.innerHTML = `<h4>&#128203; ${wf.name} <span style="color:var(--text2);font-size:11px">(wordlist — showing first 50 of ${totalLines} lines)</span></h4><pre style="color:var(--purple)">${text.replace(/</g,'&lt;')}</pre>`;
  } catch(e) {
    preview.innerHTML = `<h4>${wf.name}</h4><div style="color:var(--red)">Failed to load preview</div>`;
  }
}

async function previewFile(f){
  const preview=document.getElementById('results-preview');
  if(f.ext==='.csv'){
    const r=await fetch(`/api/file/csv?path=${encodeURIComponent(f.path)}`);
    const d=await r.json();
    if(d.data){
      const {headers,rows,total}=d.data;
      let html=`<h4>${f.name} <span style="color:var(--text2);font-size:11px">(${total} rows)</span></h4>`;
      html+='<div style="overflow-x:auto"><table>';
      html+='<tr>'+headers.map(h=>`<th>${h}</th>`).join('')+'</tr>';
      rows.slice(0,500).forEach(row=>{
        html+='<tr>'+row.map(c=>`<td title="${c}">${c}</td>`).join('')+'</tr>';
      });
      html+='</table></div>';
      preview.innerHTML=html;
    }
  } else {
    const r=await fetch(`/api/file/text?path=${encodeURIComponent(f.path)}`);
    const d=await r.json();
    const text=d.text||'';
    preview.innerHTML=`<h4>${f.name}</h4><pre>${text.replace(/</g,'&lt;')}</pre>`;
  }
}

// =====================================================================
//  Intelligence / LLM
// =====================================================================
document.getElementById('llm-provider').addEventListener('change', function(){
  document.getElementById('llm-apikey-field').style.display=this.value==='remote'?'block':'none';
  document.getElementById('llm-url-field').style.display='block';
});

async function testLLM(){
  addChatMessage('user','Testing LLM connection...');
  const spinner=addChatSpinner();
  try{
    const r=await callLLM('Say "REK LLM connected" and nothing else.',null);
    spinner.remove();
    addChatMessage('bot',r);
  }catch(e){
    spinner.remove();
    addChatMessage('error','LLM test failed: '+e.message);
  }
}

function addChatMessage(role,text){
  const chat=document.getElementById('intel-chat');
  const div=document.createElement('div');
  div.className='chat-msg '+role;
  div.textContent=text;
  chat.appendChild(div);
  chat.scrollTop=chat.scrollHeight;
  return div;
}
function addChatSpinner(){
  const chat=document.getElementById('intel-chat');
  const div=document.createElement('div');
  div.className='chat-spinner';
  div.textContent='⟳ Thinking...';
  chat.appendChild(div);
  chat.scrollTop=chat.scrollHeight;
  return div;
}

async function callLLM(prompt, resultDir, action=null){
  const payload={
    prompt, action,
    provider:document.getElementById('llm-provider').value,
    model:document.getElementById('llm-model').value||null,
    api_key:document.getElementById('llm-apikey').value||null,
    result_dir:resultDir||currentResultDir||null,
  };
  const r=await fetch('/api/llm/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const d=await r.json();
  if(d.error) throw new Error(d.error);
  return d.response;
}

async function loadResultContext(){
  const sel=document.getElementById('result-dir-select');
  const dir=sel.value;
  if(!dir){toast('Select a result directory','err');return;}
  currentResultDir=dir;
  const r=await fetch(`/api/summary?dir=${encodeURIComponent(dir)}`);
  const d=await r.json();
  const s=d.summary||{};
  const badge=document.getElementById('context-badge');
  badge.style.display='inline';
  badge.textContent=`${s.subdomains||0} subs · ${s.live_hosts||0} live · ${s.endpoints||0} endpoints · ${Object.values(s.vulnerabilities||{}).reduce((a,b)=>a+b,0)} vulns`;
  toast('Results context loaded ✓','ok');
}

async function runAction(action){
  if(!currentResultDir){toast('Load results context first','err');return;}
  const spinner=addChatSpinner();
  try{
    const r=await callLLM(null,currentResultDir,action);
    spinner.remove();
    addChatMessage('bot',r);
  }catch(e){
    spinner.remove();
    addChatMessage('error',e.message);
  }
}

function handleIntelKey(evt){
  if(evt.key==='Enter'&&!evt.shiftKey){evt.preventDefault();sendIntelPrompt();}
}
async function sendIntelPrompt(){
  const ta=document.getElementById('intel-prompt');
  const prompt=ta.value.trim();
  if(!prompt) return;
  ta.value='';
  addChatMessage('user',prompt);
  const spinner=addChatSpinner();
  try{
    const r=await callLLM(prompt,currentResultDir,null);
    spinner.remove();
    addChatMessage('bot',r);
  }catch(e){
    spinner.remove();
    addChatMessage('error',e.message);
  }
}

// =====================================================================
//  History
// =====================================================================
async function refreshHistory(){
  const r=await fetch('/api/jobs');
  const d=await r.json();
  const tbody=document.getElementById('history-tbody');
  tbody.innerHTML='';
  (d.jobs||[]).forEach(j=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`
      <td style="font-family:monospace;color:var(--cyan)">${j.id}</td>
      <td>${j.domain}</td>
      <td style="color:var(--text2)">${j.scan_type}</td>
      <td><span class="badge ${j.status}">${j.status}</span></td>
      <td style="color:var(--text2)">${fmtTime(j.started_at)}</td>
      <td style="color:var(--text2)">${fmtDuration(j.started_at,j.ended_at)}</td>
      <td><a class="lnk" onclick="viewJobLog('${j.id}')">Console</a></td>
    `;
    tbody.appendChild(tr);
  });
}

function viewJobLog(jobId){
  switchTab('console');
  document.getElementById('console-job-select').value=jobId;
  loadConsoleJob(jobId);
}

// =====================================================================
//  Builder tab
// =====================================================================
function renderToolbox(){
  const box=document.getElementById('builder-toolbox');
  box.innerHTML='';
  const cats={};
  TOOL_CATALOG.forEach(t=>{
    if(!cats[t.cat]) cats[t.cat]=[];
    cats[t.cat].push(t);
  });
  Object.entries(cats).forEach(([cat,tools])=>{
    const catEl=document.createElement('div');
    catEl.className='tb-cat'; catEl.textContent=cat;
    box.appendChild(catEl);
    tools.forEach(t=>{
      const isInstalled = t.type==='python' ? true : (toolStatus[t.id]||false);
      const dotColor = t.type==='python' ? 'var(--purple)' : (isInstalled ? 'var(--green)' : 'var(--red)');
      const el=document.createElement('div');
      el.className='tb-tool'+(isInstalled||t.type==='python'?'':' unavail');
      el.draggable=true;
      el.innerHTML=`<span style="width:7px;height:7px;border-radius:50%;background:${dotColor};flex-shrink:0;display:inline-block"></span>${t.label}`;
      const g=TOOL_GUIDANCE[t.id];
      el.title=t.desc + (g ? ' | Common flags: ' + g.flags : ' | see docs');
      el.addEventListener('dragstart',ev=>{
        builderDragSrc=t.id; builderDragNode=null;
        ev.dataTransfer.setData('text/plain',t.id);
        ev.dataTransfer.effectAllowed='copy';
      });
      el.addEventListener('dragend',()=>{builderDragSrc=null;});
      el.onclick=()=>addBuilderTool(t.id);
      box.appendChild(el);
    });
  });
}

function addBuilderTool(toolId){
  const def=TOOL_CATALOG.find(t=>t.id===toolId);
  if(!def) return;
  builderNodes.push({id:toolId, flags:'', _def:def});
  renderBuilderCanvas();
}

function removeBuilderNode(idx){
  builderNodes.splice(idx,1);
  renderBuilderCanvas();
}

function clearBuilder(){
  builderNodes=[];
  renderBuilderCanvas();
}

const PIPELINE_TEMPLATES = {
  full_recon:    ['subfinder','assetfinder','httpx','naabu','gospider','katana','gau','gf-xss','gf-sqli','gf-ssrf','nuclei','py-takeover','py-headers','py-triage'],
  quick_surface: ['subfinder','httpx','naabu','katana','nuclei'],
  takeover_hunt: ['subfinder','assetfinder','subzy','py-takeover'],
  api_audit:     ['subfinder','httpx','gospider','katana','gf-ssrf','gf-idor','nuclei','py-params','py-headers'],
  osint_deep:    ['py-osint','py-cloud','py-github','py-asn','asnmap','py-triage'],
};

function loadPipelineTemplate(name) {
  if (!name) return;
  const tools = PIPELINE_TEMPLATES[name];
  if (!tools) return;
  builderNodes = [];
  tools.forEach(id => {
    const def = TOOL_CATALOG.find(t => t.id === id);
    if (def) builderNodes.push({id, flags: '', _def: def});
  });
  renderBuilderCanvas();
  document.getElementById('pipeline-template').value = '';
  toast('Template loaded: ' + name.replace(/_/g,' '), 'ok');
}

function renderBuilderCanvas(){
  const canvas=document.getElementById('builder-canvas');
  canvas.innerHTML='';
  if(builderNodes.length===0){
    const empty=document.createElement('div');
    empty.id='builder-empty';
    empty.innerHTML=`<div style="text-align:center;padding:40px 20px;max-width:500px">
      <div style="font-size:24px;margin-bottom:12px">&#128296;</div>
      <div style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:8px">Build Your Custom Pipeline</div>
      <div style="font-size:11px;color:var(--text2);line-height:1.7;margin-bottom:16px">
        Drag tools from the left panel or click them to add.<br>
        Tools run in sequence &#8212; each step&#39;s output feeds the next.<br>
        Add extra flags per-tool using the flags input on each node.
      </div>
      <div style="font-size:10px;color:var(--text3);line-height:1.8">
        &#128161; <b style="color:var(--cyan)">Bug Bounty tip:</b> Start with subfinder &#8594; httpx &#8594; gospider &#8594; gf &#8594; nuclei<br>
        &#128161; <b style="color:var(--cyan)">Takeover tip:</b> subfinder &#8594; subzy + Takeover Check<br>
        &#128161; <b style="color:var(--cyan)">OSINT tip:</b> OSINT Engine &#8594; GitHub Dork &#8594; AI Triage
      </div>
    </div>`;
    canvas.appendChild(empty);
    return;
  }
  builderNodes.forEach((node,idx)=>{
    if(idx>0){
      const arrow=document.createElement('div');
      arrow.style.cssText='width:28px;flex-shrink:0;display:flex;align-items:center;justify-content:center;color:var(--border2);font-size:18px;user-select:none;padding-top:10px';
      arrow.textContent='\u2192';
      canvas.appendChild(arrow);
    }
    const def=node._def;
    const isInstalled=def.type==='python'?true:(toolStatus[def.id]||false);
    const dotColor=def.type==='python'?'var(--purple)':(isInstalled?'var(--green)':'var(--red)');
    const bn=document.createElement('div');
    bn.className='bn';
    bn.draggable=true;
    bn.dataset.idx=idx;
    bn.style.borderTopColor=def.color;
    bn.style.borderTopWidth='3px';
    const inMeta=def.inFile?`in: ${def.inFile}`:'';
    const outMeta=def.outFile?`out: ${def.outFile}`:'';
    const warnHtml=(!isInstalled&&def.type!=='python')?`<div class="bn-warn">⚠ not installed</div>`:'';
    bn.innerHTML=`
      <div class="bn-header">
        <span style="width:7px;height:7px;border-radius:50%;background:${dotColor};flex-shrink:0;display:inline-block"></span>
        <span class="bn-title" title="${def.label}">${def.label}</span>
        <button class="bn-rm" onclick="removeBuilderNode(${idx})" title="Remove">\u00d7</button>
      </div>
      <div class="bn-meta">${[inMeta,outMeta].filter(Boolean).join(' \u2192 ')}</div>
      ${warnHtml}
      <div class="bn-flags">
        <div class="bn-flags-label">extra flags</div>
        <input type="text" placeholder="--flag value" value="${node.flags}" oninput="builderNodes[${idx}].flags=this.value">
      </div>`;
    bn.addEventListener('dragstart',ev=>{
      builderDragNode=idx; builderDragSrc=null;
      ev.dataTransfer.setData('text/plain','node:'+idx);
      ev.dataTransfer.effectAllowed='move';
    });
    bn.addEventListener('dragover',ev=>{ev.preventDefault();bn.classList.add('drag-over');});
    bn.addEventListener('dragleave',()=>bn.classList.remove('drag-over'));
    bn.addEventListener('drop',ev=>{
      ev.preventDefault();
      bn.classList.remove('drag-over');
      onCanvasDrop(ev,idx);
    });
    canvas.appendChild(bn);
  });
}

function onCanvasDrop(e, targetIdx){
  e.preventDefault();
  const data=e.dataTransfer.getData('text/plain');
  if(data.startsWith('node:')){
    // Reorder
    const fromIdx=parseInt(data.replace('node:',''));
    if(isNaN(fromIdx)||fromIdx===targetIdx) return;
    const moved=builderNodes.splice(fromIdx,1)[0];
    const insertAt=(targetIdx===undefined)?builderNodes.length:targetIdx;
    builderNodes.splice(insertAt,0,moved);
    renderBuilderCanvas();
  } else {
    // New tool from toolbox
    const toolId=data;
    if(toolId) addBuilderTool(toolId);
  }
}

async function runBuilderPipeline(){
  const domain=document.getElementById('builder-domain').value.trim();
  if(!domain){toast('Enter a target domain','err');return;}
  if(builderNodes.length===0){toast('Add at least one tool','err');return;}
  const tools=builderNodes.map(n=>({id:n.id,flags:n.flags}));
  const r=await fetch('/api/scan/custom',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain,tools,preview_only:false})});
  const d=await r.json();
  if(d.error){toast(d.error,'err');return;}
  activeJobId=d.job_id;
  toast('Pipeline started: job '+d.job_id,'ok');
  document.getElementById('hdr-status').textContent='\u25cf Scanning '+domain;
  switchTab('console');
  refreshConsoleJobList(d.job_id);
  streamJob(d.job_id);
}

async function previewBuilderScript(){
  const domain=document.getElementById('builder-domain').value.trim()||'example.com';
  if(builderNodes.length===0){toast('Add at least one tool','err');return;}
  const tools=builderNodes.map(n=>({id:n.id,flags:n.flags}));
  const r=await fetch('/api/scan/custom',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain,tools,preview_only:true})});
  const d=await r.json();
  if(d.error){toast(d.error,'err');return;}
  switchTab('intel');
  addChatMessage('bot','## Pipeline Script Preview\n\n```bash\n'+(d.script||'')+'```');
}

// =====================================================================
//  Init
// =====================================================================
async function init(){
  await checkPrerequisites();
  await loadConfig();
  refreshHistory();
}
init();
setInterval(()=>{
  if(activeJobId) document.getElementById('hdr-status').textContent='● Scan running...';
}, 5000);
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


@app.route("/api/wordlists")
def api_wordlists():
    """Return a list of wordlist files from the wordlists/ directory."""
    wordlists_dir = ROOT_DIR / "wordlists"
    result = []
    if wordlists_dir.is_dir():
        for f in sorted(wordlists_dir.iterdir()):
            if f.is_file():
                result.append({
                    "name": f.name,
                    "path": str(f),
                    "size": f.stat().st_size,
                })
    return jsonify({"wordlists": result})


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


@app.route("/api/config/get")
def api_config_get():
    """Read config.conf and return as JSON."""
    config_path = ROOT_DIR / "config.conf"
    result = {}
    if config_path.exists():
        for line in config_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, val = line.partition('=')
                result[key.strip()] = val.strip().strip('"')
    return jsonify(result)


@app.route("/api/config/save", methods=["POST"])
def api_config_save():
    """Save config.conf from POSTed JSON key/value pairs."""
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "Expected JSON object"}), 400
    config_path = ROOT_DIR / "config.conf"
    # Read existing to preserve comments/structure
    existing_lines = []
    if config_path.exists():
        existing_lines = config_path.read_text(encoding="utf-8").splitlines()
    updated_keys = set()
    new_lines = []
    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and '=' in stripped:
            key = stripped.split('=', 1)[0].strip()
            if key in data:
                new_lines.append(f'{key}="{data[key]}"')
                updated_keys.add(key)
                continue
        new_lines.append(line)
    # Append any new keys not in existing file
    for key, val in data.items():
        if key not in updated_keys:
            new_lines.append(f'{key}="{val}"')
    config_path.write_text('\n'.join(new_lines) + '\n', encoding="utf-8")
    return jsonify({"saved": True})


INSTALL_METHODS = {
    "subfinder":    {"method": "go", "pkg": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "assetfinder":  {"method": "go", "pkg": "github.com/tomnomnom/assetfinder@latest"},
    "httpx":        {"method": "go", "pkg": "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "naabu":        {"method": "go", "pkg": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
    "nuclei":       {"method": "go", "pkg": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "katana":       {"method": "go", "pkg": "github.com/projectdiscovery/katana/cmd/katana@latest"},
    "gau":          {"method": "go", "pkg": "github.com/lc/gau/v2/cmd/gau@latest"},
    "gospider":     {"method": "go", "pkg": "github.com/jaeles-project/gospider@latest"},
    "puredns":      {"method": "go", "pkg": "github.com/d3mondev/puredns/v2@latest"},
    "gotator":      {"method": "go", "pkg": "github.com/Josue87/gotator@latest"},
    "goaltdns":     {"method": "go", "pkg": "github.com/subfinder/goaltdns@latest"},
    "gf":           {"method": "go", "pkg": "github.com/tomnomnom/gf@latest"},
    "ripgen":       {"method": "go", "pkg": "github.com/resyncgg/ripgen@latest"},
    "getjs":        {"method": "go", "pkg": "github.com/003random/getJS@latest"},
    "cariddi":      {"method": "go", "pkg": "github.com/edoardottt/cariddi/cmd/cariddi@latest"},
    "subzy":        {"method": "go", "pkg": "github.com/PentestPad/subzy@latest"},
    "waybackurls":  {"method": "go", "pkg": "github.com/tomnomnom/waybackurls@latest"},
    "asnmap":       {"method": "go", "pkg": "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"},
    "chaos":        {"method": "go", "pkg": "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"},
    "findomain":    {"method": "go", "pkg": "github.com/findomain/findomain@latest"},
    "dnsgen":       {"method": "pip", "pkg": "dnsgen", "cmd": "pip3 install dnsgen"},
    "arjun":        {"method": "pip", "pkg": "arjun",  "cmd": "pip3 install arjun"},
}


@app.route("/api/tool/install", methods=["POST"])
def api_tool_install():
    """Install a single tool by name. Supports go install and pip3 install.

    When check_only=true is passed, returns the install command and metadata
    without executing anything — used by the frontend permission dialog.
    """
    import shutil
    data = request.get_json()
    tool = (data.get("tool") or "").strip()
    check_only = bool(data.get("check_only", False))

    if not tool:
        return jsonify({"error": "tool name required"}), 400

    info = INSTALL_METHODS.get(tool)
    if not info:
        return jsonify({"error": f"unknown tool: {tool}"}), 400

    method = info["method"]

    # Build the human-readable install command string for the permission dialog
    if method == "go":
        install_cmd = f"go install -v {info['pkg']}"
        install_note = "Installs to ~/go/bin — ensure that directory is on your PATH."
    elif method == "pip":
        install_cmd = info.get("cmd", f"pip3 install {info['pkg']}")
        install_note = "Installs as a system/user Python package via pip3."
    else:
        return jsonify({"error": f"unsupported install method: {method}"}), 400

    if check_only:
        # Just return metadata — do not execute anything
        return jsonify({
            "tool":         tool,
            "method":       method,
            "install_cmd":  install_cmd,
            "note":         install_note,
            "label":        tool,
        })

    # Validate prerequisites before launching
    if method == "go":
        # Search the enriched PATH so we find go even if not in default env
        go_bin = os.path.expanduser("~/go/bin")
        search_path = f"{go_bin}:{os.environ.get('PATH', '')}"
        if not shutil.which("go", path=search_path):
            return jsonify({"error": "Go is not installed — install Go first from https://go.dev/dl/"}), 400
        cmd = ["go", "install", "-v", info["pkg"]]
    elif method == "pip":
        if not shutil.which("pip3"):
            return jsonify({"error": "pip3 not found — install Python 3 and pip first"}), 400
        cmd = info.get("cmd", f"pip3 install {info['pkg']}").split()

    job = _create_and_start_job(
        domain="install",
        scan_type=f"install-tool-{tool}",
        command=cmd,
        options={},
    )
    return jsonify({"job_id": job.id, "status": "queued", "tool": tool})


@app.route("/api/llm/analyze", methods=["POST"])
def api_llm_analyze():
    """LLM endpoint that injects latest scan results as context."""
    data = request.get_json()
    prompt = (data.get("prompt") or "").strip()
    provider = data.get("provider", "local")
    model = data.get("model", "")
    api_key = data.get("api_key", "")
    result_dir = data.get("result_dir", "")
    action = data.get("action", "")  # 'report', 'summarize', 'prioritize', 'critical'

    if not prompt and not action:
        return jsonify({"error": "prompt or action required"}), 400

    # Build context from results
    context_parts = []
    if result_dir:
        try:
            summary = _build_scan_summary(result_dir)
            context_parts.append(f"## Scan Summary\nDomain: scan results\nSubdomains: {summary['subdomains']}\nLive hosts: {summary['live_hosts']}\nEndpoints: {summary['endpoints']}\nPorts scanned: {summary['ports']}\nVulnerabilities found: {json.dumps(summary['vulnerabilities'])}\nJS secrets: {summary['js_secrets']}")
            # Add sample from key files
            rd = ROOT_DIR / result_dir
            for rel_path in ["subdomains/subs-alive.txt", "vulnerabilities/checkfor-xss.txt",
                             "vulnerabilities/checkfor-sqli.txt", "vulnerabilities/nuclei-findings.txt",
                             "vulnerabilities/takeover.csv", "js/js-secrets.txt"]:
                fp = rd / rel_path
                if fp.exists() and fp.stat().st_size > 0:
                    sample = fp.read_text(errors="replace").splitlines()[:30]
                    context_parts.append(f"\n### {rel_path} (first 30 lines)\n" + "\n".join(sample))
        except Exception as e:
            context_parts.append(f"[Error reading results: {e}]")

    # Build action-specific prompt
    action_prompts = {
        "report": "Generate a comprehensive professional penetration testing / bug bounty report based on the scan results above. Include: Executive Summary, Scope, Methodology, Findings (with severity ratings), Recommendations, and Next Steps.",
        "summarize": "Provide a concise executive summary of the reconnaissance findings. Focus on: total attack surface, most interesting subdomains, open ports, technology stack, and top 5 findings.",
        "prioritize": "Prioritize the attack surface for manual testing. Which endpoints, parameters, or subdomains should be tested first for high-impact vulnerabilities? Explain your reasoning based on the data.",
        "critical": "Identify the critical paths and highest-risk entry points from the scan data. What would an attacker target first? What are the most exploitable findings?",
        "attack_chains": "Analyze the scan findings and identify multi-step attack chains. For each chain, describe: the entry point, exploitation steps, potential impact, and affected assets. Format as a numbered list of attack scenarios.",
        "quick_wins":    "Identify the top 5 'quick win' findings from the scan data — vulnerabilities that are easy to verify/exploit with high impact. For each: finding type, affected URL/subdomain, why it's a quick win, and exact reproduction steps.",
        "bb_report":     "Generate a structured bug bounty submission report based on the scan findings. Format it as a professional HackerOne/Bugcrowd submission with: Title, Severity (CVSS score), Summary, Steps to Reproduce (numbered), Impact, Supporting Evidence (URLs/payloads from findings), Recommended Fix, and References. Focus on the highest-severity confirmed findings.",
    }

    if action and action in action_prompts:
        full_prompt = action_prompts[action]
    else:
        full_prompt = prompt

    if context_parts:
        full_prompt = "## Scan Results Context\n" + "\n".join(context_parts) + "\n\n---\n\n## Task\n" + full_prompt

    try:
        sys.path.insert(0, str(ROOT_DIR))
        from rek import LLMAssistant
        assistant = LLMAssistant(silent=True, timeout=120)
        response = assistant.ask(
            prompt=full_prompt,
            provider=provider or None,
            model=model or None,
            api_key=api_key or None,
        )
        return jsonify({"response": response})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Custom Pipeline Builder
# ---------------------------------------------------------------------------

_TOOL_CMD_TEMPLATES = {
    "subfinder":   "subfinder -d {D} -o {O}/subdomains.txt -silent -all {F}",
    "assetfinder": "assetfinder --subs-only {D} {F} | tee -a {O}/subdomains.txt",
    "findomain":   "findomain -t {D} -u {O}/findomain.txt {F}; cat {O}/findomain.txt >> {O}/subdomains.txt 2>/dev/null || true",
    "puredns":     "puredns bruteforce wordlists/subdomains.txt {D} --write {O}/resolved.txt {F}; cat {O}/resolved.txt >> {O}/subdomains.txt 2>/dev/null || true",
    "dnsgen":      "[ -f {O}/subdomains.txt ] && cat {O}/subdomains.txt | dnsgen - {F} > {O}/dnsgen.txt && cat {O}/dnsgen.txt >> {O}/subdomains.txt || true",
    "gotator":     "[ -f {O}/subdomains.txt ] && gotator -sub {O}/subdomains.txt {F} -depth 1 -o {O}/gotator.txt && cat {O}/gotator.txt >> {O}/subdomains.txt || true",
    "ripgen":      "[ -f {O}/subdomains.txt ] && ripgen -i {O}/subdomains.txt {F} > {O}/ripgen.txt && cat {O}/ripgen.txt >> {O}/subdomains.txt || true",
    "asnmap":      "asnmap -d {D} -o {O}/asn-ips.txt {F}",
    "httpx":       "[ -f {O}/subdomains.txt ] && httpx -l {O}/subdomains.txt -o {O}/hosts-alive.txt -silent -status-code -title -tech-detect {F} || httpx -u {D} -o {O}/hosts-alive.txt -silent {F}",
    "naabu":       "[ -f {O}/hosts-alive.txt ] && naabu -list {O}/hosts-alive.txt -o {O}/ports.txt -silent {F}",
    "subzy":       "[ -f {O}/subdomains.txt ] && subzy run --targets {O}/subdomains.txt --output {O}/subzy.txt {F}",
    "gospider":    "[ -f {O}/hosts-alive.txt ] && gospider -S {O}/hosts-alive.txt -o {O}/gospider/ -c 10 -d 2 {F}",
    "katana":      "[ -f {O}/hosts-alive.txt ] && katana -list {O}/hosts-alive.txt -o {O}/urls.txt -silent -d 3 {F}",
    "gau":         "gau {D} {F} > {O}/gau-urls.txt",
    "waybackurls": "waybackurls {D} {F} > {O}/wayback-urls.txt",
    "gf-xss":      "[ -f {O}/urls.txt ] && cat {O}/urls.txt | gf xss {F} > {O}/gf-xss.txt || true",
    "gf-sqli":     "[ -f {O}/urls.txt ] && cat {O}/urls.txt | gf sqli {F} > {O}/gf-sqli.txt || true",
    "gf-ssrf":     "[ -f {O}/urls.txt ] && cat {O}/urls.txt | gf ssrf {F} > {O}/gf-ssrf.txt || true",
    "gf-redirect": "[ -f {O}/urls.txt ] && cat {O}/urls.txt | gf redirect {F} > {O}/gf-redirect.txt || true",
    "nuclei":      "[ -f {O}/hosts-alive.txt ] && nuclei -l {O}/hosts-alive.txt -o {O}/nuclei.txt -silent {F}",
    "getjs":       "[ -f {O}/hosts-alive.txt ] && getJS --input {O}/hosts-alive.txt --output {O}/js-files.txt {F}",
    "cariddi":     "[ -f {O}/hosts-alive.txt ] && cariddi -l {O}/hosts-alive.txt -s -o {O}/cariddi.txt {F}",
    "py-cloud":    "python3 rek.py --cloud-recon -d {D} {F}",
    "py-takeover": "[ -f {O}/subdomains.txt ] && python3 rek.py --takeover --input {O}/subdomains.txt {F}",
    "py-headers":  "[ -f {O}/hosts-alive.txt ] && python3 rek.py --headers-audit --input {O}/hosts-alive.txt {F}",
    "py-favicon":  "[ -f {O}/hosts-alive.txt ] && python3 rek.py --favicon-scan --input {O}/hosts-alive.txt {F}",
    "py-params":   "[ -f {O}/hosts-alive.txt ] && python3 rek.py --param-discovery --input {O}/hosts-alive.txt {F}",
    "py-github":   "python3 rek.py --github-dork -d {D} {F}",
    "py-asn":      "python3 rek.py --asn-recon -d {D} {F}",
    "py-aivuln":  "python3 rek_ai_scanner.py --input {O}/hosts-alive.txt --urls {O}/urls.txt --output {O}/ai-scan.csv {F}",
    "py-osint":   "python3 rek_osint.py -d {D} --output-dir {O} {F}",
    "py-triage":  "python3 rek_ai_triage.py --result-dir {O} --output {O}/triage-report.json {F}",
}


def _build_pipeline_script(domain: str, tools: List[dict], outdir: str) -> str:
    """Generate a bash script for the custom pipeline."""
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        f'DOMAIN="{domain}"',
        f'OUTDIR="{outdir}"',
        'mkdir -p "$OUTDIR"',
        f'echo "[REK] Custom pipeline for $DOMAIN"',
        f'echo "[REK] Output: $OUTDIR"',
        "",
    ]
    for step in tools:
        tool_id = step.get("id", "")
        flags = (step.get("flags") or "").strip()
        tpl = _TOOL_CMD_TEMPLATES.get(tool_id)
        if not tpl:
            lines.append(f"echo '[REK] WARNING: unknown tool {tool_id}, skipping'")
            continue
        cmd = tpl.replace("{D}", "$DOMAIN").replace("{O}", "$OUTDIR").replace("{F}", flags)
        lines.append(f'echo "[REK] Running: {tool_id}"')
        lines.append(cmd)
        lines.append("")
    lines.append('echo "[REK] Pipeline complete."')
    return "\n".join(lines) + "\n"


@app.route("/api/scan/custom", methods=["POST"])
def api_scan_custom():
    data = request.get_json()
    domain = (data.get("domain") or "").strip().lower()
    tools = data.get("tools", [])
    preview_only = bool(data.get("preview_only", False))

    if not domain:
        return jsonify({"error": "domain required"}), 400
    if not tools:
        return jsonify({"error": "tools list is empty"}), 400

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    result_dir = RESULTS_ROOT / f"custom-{domain.replace('.', '_')}-{ts}"
    result_dir.mkdir(parents=True, exist_ok=True)

    script_content = _build_pipeline_script(domain, tools, str(result_dir))

    if preview_only:
        return jsonify({"script": script_content})

    script_path = result_dir / "pipeline.sh"
    script_path.write_text(script_content, encoding="utf-8")
    script_path.chmod(0o755)

    job = _create_and_start_job(
        domain=domain,
        scan_type="custom-pipeline",
        command=["bash", str(script_path)],
        options={"tools": [t.get("id") for t in tools]},
        result_dir=result_dir,
    )
    return jsonify({"job_id": job.id, "script": script_content})


@app.route("/api/scan/stdin", methods=["POST"])
def api_scan_stdin():
    data = request.get_json()
    job_id = (data.get("job_id") or "").strip()
    text = data.get("text", "")
    with _lock:
        proc = _processes.get(job_id)
    if not proc:
        return jsonify({"error": "job not running"}), 404
    try:
        proc.stdin.write(text + "\n")
        proc.stdin.flush()
        return jsonify({"sent": True})
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
