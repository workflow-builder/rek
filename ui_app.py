#!/usr/bin/env python3
"""REK Web UI: playbook launcher, live logs, and results explorer."""

from __future__ import annotations

import html
import json
import subprocess
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qs, quote, unquote, urlparse

ROOT_DIR = Path(__file__).resolve().parent
RUNS_DIR = ROOT_DIR / "ui_runs"
LOGS_DIR = RUNS_DIR / "logs"
STATE_FILE = RUNS_DIR / "jobs.json"
RESULTS_ROOT = ROOT_DIR / "results"

PLAYBOOKS = {
    "v1": ROOT_DIR / "playbook" / "rek-playbook-v1.sh",
    "v2": ROOT_DIR / "playbook" / "rek-playbook-v2.sh",
    "standard": ROOT_DIR / "playbook" / "rek-playbook.sh",
}

ARCHITECTURE_NOTES = [
    ("Subdomain Discovery", "Collects assets from multiple sources and permutations."),
    ("Live Host Probing", "Checks reachability and HTTP metadata of discovered hosts."),
    ("Endpoint Crawling", "Extracts URLs/paths and scans JavaScript/exposed endpoints."),
    ("Vulnerability Checks", "Runs focused checks and templates against collected targets."),
]

CSS = """
body { font-family: Inter, Arial, sans-serif; margin:0; background:#0b1220; color:#e2e8f0; }
header { padding:1rem 1.4rem; border-bottom:1px solid #1f2a44; }
a { color:#7dd3fc; text-decoration:none; }
a:hover { text-decoration:underline; }
main { padding:1rem 1.4rem 1.5rem; }
.grid { display:grid; gap:1rem; grid-template-columns:repeat(2,minmax(0,1fr)); }
.card { background:#111a2f; border:1px solid #223153; border-radius:12px; padding:1rem; }
.wide { grid-column:1/-1; }
label { display:grid; gap:.35rem; font-size:.92rem; }
.form-grid { display:grid; gap:.75rem; }
input,select,button { width:100%; box-sizing:border-box; border-radius:8px; border:1px solid #33466f; background:#0a1428; color:#e2e8f0; padding:.55rem; }
button { cursor:pointer; font-weight:700; background:#0b67a9; border-color:#0ea5e9; }
table { width:100%; border-collapse:collapse; }
th,td { border-bottom:1px solid #223153; text-align:left; padding:.5rem; font-size:.92rem; vertical-align:top; }
.pill { padding:.15rem .5rem; border-radius:999px; font-size:.74rem; text-transform:uppercase; }
.pill.running { background:#1d4ed8; } .pill.completed { background:#15803d; } .pill.failed { background:#b91c1c; } .pill.queued { background:#475569; }
.muted { color:#9fb1d3; font-size:.85rem; }
.log { background:#030916; border:1px solid #223153; border-radius:10px; padding:.7rem; white-space:pre-wrap; overflow:auto; max-height:70vh; }
ul { margin:.45rem 0 .2rem 1rem; }
.row-between { display:flex; justify-content:space-between; align-items:center; gap:1rem; flex-wrap:wrap; }
@media (max-width: 980px){ .grid { grid-template-columns:1fr; } }
"""


@dataclass
class Job:
    id: str
    domain: str
    playbook: str
    threads: int
    status: str = "queued"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    log_path: str = ""
    result_dir: str = ""
    command: List[str] = field(default_factory=list)
    return_code: Optional[int] = None


RUNS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
_jobs: Dict[str, Job] = {}
_lock = threading.Lock()


def _supports_output_flag(script_path: Path) -> bool:
    try:
        content = script_path.read_text(encoding="utf-8", errors="ignore")
        return "--output" in content and "-o, --output" in content
    except OSError:
        return False


def _save_state() -> None:
    with _lock:
        data = [asdict(j) for j in _jobs.values()]
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_state() -> None:
    if not STATE_FILE.exists():
        return
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        for row in data:
            job = Job(**row)
            _jobs[job.id] = job
    except Exception:
        return


def _sorted_jobs() -> List[Job]:
    with _lock:
        return sorted(_jobs.values(), key=lambda j: j.created_at, reverse=True)


def _run_playbook(job_id: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.utcnow().isoformat()
    _save_state()

    log_path = Path(job.log_path)
    with log_path.open("a", encoding="utf-8") as log_file:
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

        code = process.wait()
        ended = datetime.utcnow().isoformat()
        with _lock:
            current = _jobs.get(job_id)
            if current:
                current.status = "completed" if code == 0 else "failed"
                current.return_code = code
                current.ended_at = ended
        log_file.write(f"\n[{ended}] Finished with exit code {code}.\n")
    _save_state()


def _tail_text(path: Path, max_lines: int = 400) -> str:
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-max_lines:])


def _discover_result_dirs() -> List[dict]:
    if not RESULTS_ROOT.exists():
        return []
    dirs = []
    for result_dir in sorted([p for p in RESULTS_ROOT.iterdir() if p.is_dir()], reverse=True):
        files = []
        for f in sorted(result_dir.rglob("*")):
            if f.is_file() and f.suffix.lower() in {".txt", ".csv", ".md", ".json", ".log"}:
                files.append({
                    "name": str(f.relative_to(result_dir)),
                    "path": str(f.relative_to(ROOT_DIR)),
                    "size": f.stat().st_size,
                })
        dirs.append({"name": result_dir.name, "files": files})
    return dirs


class UIHandler(BaseHTTPRequestHandler):
    def _send(self, content: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_html(self, content: str, status: int = 200) -> None:
        self._send(content.encode("utf-8"), status)

    def _send_json(self, payload: dict, status: int = 200) -> None:
        self._send(json.dumps(payload).encode("utf-8"), status, "application/json")

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(self.render_index())
        elif parsed.path == "/logs":
            job_id = parse_qs(parsed.query).get("id", [""])[0]
            self._send_html(self.render_log(job_id))
        elif parsed.path == "/results":
            self._send_html(self.render_results())
        elif parsed.path == "/view":
            rel = unquote(parse_qs(parsed.query).get("file", [""])[0])
            self._send_html(self.render_file(rel))
        elif parsed.path == "/api/jobs":
            self._send_json({"jobs": [asdict(j) for j in _sorted_jobs()]})
        elif parsed.path == "/api/log":
            params = parse_qs(parsed.query)
            job_id = params.get("id", [""])[0]
            lines = int(params.get("lines", ["350"])[0])
            with _lock:
                job = _jobs.get(job_id)
            if not job:
                self._send_json({"error": "job not found"}, 404)
                return
            log_txt = _tail_text(Path(job.log_path), max_lines=max(50, min(lines, 1200)))
            self._send_json({"job_id": job_id, "status": job.status, "log": log_txt})
        elif parsed.path == "/styles.css":
            self._send(CSS.encode("utf-8"), ctype="text/css")
        else:
            self._send_html("<h1>Not Found</h1>", 404)

    def do_POST(self):
        if urlparse(self.path).path != "/run":
            self._send_html("<h1>Not Found</h1>", 404)
            return

        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        domain = form.get("domain", [""])[0].strip().lower()
        playbook = form.get("playbook", ["v1"])[0].strip()
        threads = form.get("threads", ["100"])[0].strip()

        if not domain or playbook not in PLAYBOOKS or not threads.isdigit():
            self._send_html("<h1>Invalid input.</h1>", 400)
            return

        job_id = uuid.uuid4().hex[:8]
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        result_dir = RESULTS_ROOT / f"ui-{domain.replace('.', '_')}-{timestamp}"
        result_dir.mkdir(parents=True, exist_ok=True)
        log_path = LOGS_DIR / f"{job_id}.log"

        script = PLAYBOOKS[playbook]
        command = ["bash", str(script), "-d", domain, "-t", threads]
        if _supports_output_flag(script):
            command += ["-o", str(result_dir)]

        job = Job(
            id=job_id,
            domain=domain,
            playbook=playbook,
            threads=int(threads),
            log_path=str(log_path),
            result_dir=str(result_dir.relative_to(ROOT_DIR)),
            command=command,
        )
        with _lock:
            _jobs[job.id] = job
        _save_state()
        threading.Thread(target=_run_playbook, args=(job.id,), daemon=True).start()
        self._redirect("/")

    def render_index(self) -> str:
        jobs = _sorted_jobs()
        architecture = "".join(f"<li><strong>{html.escape(t)}</strong>: {html.escape(d)}</li>" for t, d in ARCHITECTURE_NOTES)
        playbook_options = "".join(f"<option value='{k}'>{k}</option>" for k in PLAYBOOKS)

        rows = []
        for j in jobs:
            output_link = f"<a href='/results'>{html.escape(j.result_dir)}</a>" if j.result_dir else "-"
            rows.append(
                f"<tr><td>{j.id}</td><td>{html.escape(j.domain)}</td><td>{j.playbook}</td><td>{j.threads}</td>"
                f"<td><span class='pill {j.status}'>{j.status}</span></td><td class='muted'>{j.created_at}</td>"
                f"<td>{output_link}</td><td><a href='/logs?id={j.id}'>View</a></td></tr>"
            )
        job_rows = "".join(rows) or "<tr><td colspan='8'>No runs yet.</td></tr>"

        return f"""<!doctype html><html><head><meta charset='utf-8'><title>REK Control Center</title><link rel='stylesheet' href='/styles.css'></head>
<body><header><h1>REK Control Center</h1><div class='muted'>Run playbooks, monitor execution, and inspect artifacts in one place.</div></header>
<main class='grid'>
<section class='card'>
<h2>Start Recon Run</h2>
<form action='/run' method='post' class='form-grid'>
<label>Target Domain<input name='domain' placeholder='example.com' required></label>
<label>Playbook<select name='playbook'>{playbook_options}</select></label>
<label>Threads<input name='threads' type='number' value='100' min='1' required></label>
<button type='submit'>Launch Run</button>
</form>
</section>
<section class='card'>
<h2>Architecture at a Glance</h2>
<ul>{architecture}</ul>
<div class='muted'>Derived from the project's recon pipeline phases and playbooks.</div>
</section>
<section class='card wide'>
<div class='row-between'><h2>Recent Jobs</h2><a href='/results'>Browse Results</a></div>
<table><thead><tr><th>ID</th><th>Domain</th><th>Playbook</th><th>Threads</th><th>Status</th><th>Created</th><th>Output Dir</th><th>Logs</th></tr></thead><tbody>{job_rows}</tbody></table>
</section>
</main></body></html>"""

    def render_log(self, job_id: str) -> str:
        with _lock:
            job = _jobs.get(job_id)
        if not job:
            return "<h1>Job not found</h1>"
        safe = html.escape(_tail_text(Path(job.log_path), 500))
        return f"""<!doctype html><html><head><meta charset='utf-8'><title>Logs {job_id}</title><link rel='stylesheet' href='/styles.css'></head>
<body><header><h1>Job {job_id} · {html.escape(job.domain)}</h1><a href='/'>← Back</a></header>
<main><div id='status' class='pill {job.status}'>{job.status}</div><p class='muted'>Auto-refresh every 3s.</p>
<pre id='log' class='log'>{safe}</pre></main>
<script>
const logEl = document.getElementById('log');
const statusEl = document.getElementById('status');
async function refresh() {{
  const r = await fetch('/api/log?id={job_id}&lines=700');
  if (!r.ok) return;
  const data = await r.json();
  statusEl.className = 'pill ' + data.status;
  statusEl.textContent = data.status;
  logEl.textContent = data.log || '';
}}
setInterval(refresh, 3000);
</script>
</body></html>"""

    def render_results(self) -> str:
        dirs = _discover_result_dirs()
        if not dirs:
            body = "<p>No result folders found in <code>results/</code> yet.</p>"
        else:
            blocks = []
            for d in dirs:
                rows = "".join(
                    f"<li><a href='/view?file={quote(f['path'])}'>{html.escape(f['name'])}</a> <span class='muted'>({f['size']} bytes)</span></li>"
                    for f in d["files"]
                ) or "<li class='muted'>No supported files in this folder.</li>"
                blocks.append(f"<details><summary>{html.escape(d['name'])} ({len(d['files'])} files)</summary><ul>{rows}</ul></details>")
            body = "".join(blocks)

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
    _load_state()
    server = ThreadingHTTPServer((host, port), UIHandler)
    print(f"REK UI running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
