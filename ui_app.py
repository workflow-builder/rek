#!/usr/bin/env python3
"""REK Web UI using Python stdlib HTTP server (no external dependencies)."""

from __future__ import annotations

import html
import os
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qs, quote, unquote, urlparse

ROOT_DIR = Path(__file__).resolve().parent
RUNS_DIR = ROOT_DIR / "ui_runs"
LOGS_DIR = RUNS_DIR / "logs"
RESULTS_ROOT = ROOT_DIR / "results"

PLAYBOOKS = {
    "v1": ROOT_DIR / "playbook" / "rek-playbook-v1.sh",
    "v2": ROOT_DIR / "playbook" / "rek-playbook-v2.sh",
    "standard": ROOT_DIR / "playbook" / "rek-playbook.sh",
}

CSS = """
body { font-family: Arial, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
header { padding: 1rem 1.5rem; border-bottom: 1px solid #1e293b; }
a { color: #7dd3fc; text-decoration: none; }
main { padding: 1.25rem; }
.grid { display: grid; gap: 1rem; grid-template-columns: repeat(2, minmax(0, 1fr)); }
.card { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 1rem; }
.wide { grid-column: 1 / -1; }
.form-grid { display: grid; gap: .75rem; }
input, select, button { width: 100%; padding: .55rem; border-radius: 8px; border: 1px solid #334155; background: #0b1221; color: #e2e8f0; }
button { cursor: pointer; background: #0369a1; border-color: #0ea5e9; font-weight: 600; }
table { width: 100%; border-collapse: collapse; }
th, td { border-bottom: 1px solid #1e293b; padding: .45rem; text-align: left; }
.pill { padding: .1rem .45rem; border-radius: 999px; font-size: .8rem; text-transform: uppercase; }
.pill.running { background: #1d4ed8; }
.pill.completed { background: #15803d; }
.pill.failed { background: #b91c1c; }
.pill.queued { background: #475569; }
.log { background: #020617; border: 1px solid #1e293b; border-radius: 8px; padding: .75rem; white-space: pre-wrap; max-height: 70vh; overflow: auto; }
.row-between { display: flex; align-items: center; justify-content: space-between; }
@media (max-width: 900px){ .grid { grid-template-columns: 1fr; } }
"""


@dataclass
class Job:
    id: str
    domain: str
    playbook: str
    threads: int
    status: str = "queued"
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    log_path: Path = field(default_factory=Path)
    command: List[str] = field(default_factory=list)


RUNS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
_jobs: Dict[str, Job] = {}
_lock = threading.Lock()


def _sorted_jobs() -> List[Job]:
    with _lock:
        return sorted(_jobs.values(), key=lambda j: j.created_at, reverse=True)


def _run_playbook(job: Job) -> None:
    with _lock:
        job.status = "running"
        job.started_at = datetime.utcnow()

    with job.log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"[{datetime.utcnow().isoformat()}] Starting: {' '.join(job.command)}\n")
        process = subprocess.Popen(
            job.command,
            cwd=ROOT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        if process.stdout:
            for line in process.stdout:
                log_file.write(line)
                log_file.flush()
        return_code = process.wait()
        finished = datetime.utcnow()
        with _lock:
            job.ended_at = finished
            job.status = "completed" if return_code == 0 else "failed"
        log_file.write(f"\n[{finished.isoformat()}] Finished with exit code {return_code}.\n")


def _discover_result_dirs() -> List[dict]:
    if not RESULTS_ROOT.exists():
        return []

    directories = []
    for result_dir in sorted([p for p in RESULTS_ROOT.iterdir() if p.is_dir()], reverse=True):
        files = []
        for file_path in sorted(result_dir.rglob("*")):
            if file_path.is_file() and file_path.suffix.lower() in {".txt", ".csv", ".md", ".json", ".log"}:
                files.append({
                    "name": str(file_path.relative_to(result_dir)),
                    "path": str(file_path.relative_to(ROOT_DIR)),
                    "size": file_path.stat().st_size,
                })
        directories.append({"name": result_dir.name, "files": files})
    return directories


class UIHandler(BaseHTTPRequestHandler):
    def _send_html(self, content: str, status: int = 200) -> None:
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(self.render_index())
        elif parsed.path == "/logs":
            params = parse_qs(parsed.query)
            job_id = params.get("id", [""])[0]
            self._send_html(self.render_log(job_id))
        elif parsed.path == "/results":
            self._send_html(self.render_results())
        elif parsed.path == "/view":
            params = parse_qs(parsed.query)
            rel_path = unquote(params.get("file", [""])[0])
            self._send_html(self.render_file(rel_path))
        elif parsed.path == "/styles.css":
            css_data = CSS.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/css")
            self.send_header("Content-Length", str(len(css_data)))
            self.end_headers()
            self.wfile.write(css_data)
        else:
            self._send_html("<h1>Not Found</h1>", status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/run":
            self._send_html("<h1>Not Found</h1>", status=404)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        form = parse_qs(body)

        domain = form.get("domain", [""])[0].strip()
        playbook = form.get("playbook", ["v1"])[0].strip()
        threads = form.get("threads", ["100"])[0].strip()

        if not domain or playbook not in PLAYBOOKS or not threads.isdigit():
            self._send_html("<h1>Invalid form input.</h1>", status=400)
            return

        job_id = uuid.uuid4().hex[:8]
        log_path = LOGS_DIR / f"{job_id}.log"
        command = ["bash", str(PLAYBOOKS[playbook]), "-d", domain, "-t", threads]

        job = Job(
            id=job_id,
            domain=domain,
            playbook=playbook,
            threads=int(threads),
            log_path=log_path,
            command=command,
        )
        with _lock:
            _jobs[job_id] = job
        threading.Thread(target=_run_playbook, args=(job,), daemon=True).start()
        self._redirect("/")

    def render_index(self) -> str:
        jobs = _sorted_jobs()
        results_dirs = _discover_result_dirs()
        job_rows = "".join(
            f"<tr><td>{j.id}</td><td>{html.escape(j.domain)}</td><td>{j.playbook}</td>"
            f"<td><span class='pill {j.status}'>{j.status}</span></td>"
            f"<td><a href='/logs?id={j.id}'>Open</a></td></tr>"
            for j in jobs
        ) or "<tr><td colspan='5'>No jobs yet.</td></tr>"

        options = "".join(f"<option value='{k}'>{k}</option>" for k in PLAYBOOKS)

        result_preview = "".join(
            f"<details><summary>{html.escape(r['name'])} ({len(r['files'])} files)</summary><ul>" +
            "".join(
                f"<li><a href='/view?file={quote(f['path'])}'>{html.escape(f['name'])}</a></li>"
                for f in r["files"][:10]
            ) + "</ul></details>"
            for r in results_dirs[:3]
        ) or "<p>No results directory found yet.</p>"

        return f"""<!doctype html><html><head><meta charset='utf-8'><title>REK Control Center</title><link rel='stylesheet' href='/styles.css'></head>
<body><header><h1>REK Control Center</h1><p>Run recon playbooks, stream logs, and inspect output artifacts.</p></header>
<main class='grid'>
<section class='card'><h2>Start New Scan</h2>
<form action='/run' method='post' class='form-grid'>
<label>Target Domain<input name='domain' placeholder='example.com' required></label>
<label>Playbook<select name='playbook'>{options}</select></label>
<label>Threads<input name='threads' value='100' type='number' min='1'></label>
<button type='submit'>Run Playbook</button></form></section>
<section class='card'><h2>Job Activity</h2><table><thead><tr><th>ID</th><th>Domain</th><th>Playbook</th><th>Status</th><th>Logs</th></tr></thead><tbody>{job_rows}</tbody></table></section>
<section class='card wide'><div class='row-between'><h2>Result Browser</h2><a href='/results'>Open full results page</a></div>{result_preview}</section>
</main></body></html>"""

    def render_log(self, job_id: str) -> str:
        with _lock:
            job = _jobs.get(job_id)
        if not job:
            return "<h1>Job not found</h1>"

        content = ""
        if job.log_path.exists():
            content = html.escape(job.log_path.read_text(encoding="utf-8", errors="replace"))

        return f"""<!doctype html><html><head><meta charset='utf-8'><title>Log {job.id}</title><link rel='stylesheet' href='/styles.css'></head>
<body><header><h1>Job {job.id} · {html.escape(job.domain)}</h1><a href='/'>← Back</a></header>
<main><p>Status: <span class='pill {job.status}'>{job.status}</span></p><pre class='log'>{content}</pre></main></body></html>"""

    def render_results(self) -> str:
        results_dirs = _discover_result_dirs()
        if not results_dirs:
            body = "<p>No result folders found at <code>results/</code>.</p>"
        else:
            body = ""
            for result in results_dirs:
                rows = "".join(
                    f"<li><a href='/view?file={quote(f['path'])}'>{html.escape(f['name'])}</a> · {f['size']} bytes</li>"
                    for f in result["files"]
                )
                body += f"<details><summary>{html.escape(result['name'])} ({len(result['files'])} files)</summary><ul>{rows}</ul></details>"

        return f"""<!doctype html><html><head><meta charset='utf-8'><title>REK Results</title><link rel='stylesheet' href='/styles.css'></head>
<body><header><h1>Results Explorer</h1><a href='/'>← Back</a></header><main class='card'>{body}</main></body></html>"""

    def render_file(self, rel_path: str) -> str:
        target = (ROOT_DIR / rel_path).resolve()
        if ROOT_DIR not in target.parents or not target.is_file():
            return "<h1>File not found</h1>"

        content = html.escape(target.read_text(encoding="utf-8", errors="replace"))
        return f"""<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(rel_path)}</title><link rel='stylesheet' href='/styles.css'></head>
<body><header><h1>{html.escape(rel_path)}</h1><a href='/results'>← Back</a></header><main><pre class='log'>{content}</pre></main></body></html>"""


def run_server(host: str = "0.0.0.0", port: int = 5000):
    server = ThreadingHTTPServer((host, port), UIHandler)
    print(f"REK UI running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
