#!/usr/bin/env python3
"""REK Web UI: full launcher for CLI/playbooks with live logs and results explorer."""

from __future__ import annotations

import html
import json
import os
import shlex
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

CSS = """
body{font-family:Inter,Arial,sans-serif;margin:0;background:#0b1220;color:#e2e8f0}
header{padding:1rem 1.4rem;border-bottom:1px solid #1f2a44}
main{padding:1rem 1.4rem 1.6rem}
a{color:#7dd3fc;text-decoration:none}a:hover{text-decoration:underline}
.grid{display:grid;gap:1rem;grid-template-columns:repeat(2,minmax(0,1fr))}
.card{background:#111a2f;border:1px solid #223153;border-radius:12px;padding:1rem}
.wide{grid-column:1/-1}
label{display:grid;gap:.35rem;font-size:.9rem}
.form-grid{display:grid;gap:.7rem}
input,select,button{width:100%;box-sizing:border-box;border-radius:8px;border:1px solid #33466f;background:#0a1428;color:#e2e8f0;padding:.55rem}
button{cursor:pointer;font-weight:700;background:#0b67a9;border-color:#0ea5e9}
small,.muted{color:#9fb1d3}
.group{display:none;border:1px dashed #2f4573;border-radius:10px;padding:.75rem}
.group.active{display:block}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.7rem}
.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.7rem}
.checkbox{display:flex;align-items:center;gap:.45rem}
.checkbox input{width:auto}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #223153;text-align:left;padding:.5rem;font-size:.89rem;vertical-align:top}
.pill{padding:.15rem .45rem;border-radius:999px;font-size:.74rem;text-transform:uppercase}
.pill.running{background:#1d4ed8}.pill.completed{background:#15803d}.pill.failed{background:#b91c1c}.pill.queued{background:#475569}
.code{font-family:ui-monospace,Consolas,monospace;background:#030916;border:1px solid #223153;border-radius:8px;padding:.2rem .35rem}
.log{background:#030916;border:1px solid #223153;border-radius:10px;padding:.7rem;white-space:pre-wrap;overflow:auto;max-height:70vh}
ul{margin:.45rem 0 .2rem 1rem}
.row-between{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
.err{background:#451020;border:1px solid #8f2f45;color:#ffd5df;padding:.6rem;border-radius:10px;margin:.6rem 0}
@media(max-width:1050px){.grid{grid-template-columns:1fr}.grid2,.grid3{grid-template-columns:1fr}}
"""


@dataclass
class Job:
    id: str
    mode: str
    domain: str
    status: str = "queued"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat(timespec="seconds"))
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    log_path: str = ""
    result_dir: str = ""
    command: List[str] = field(default_factory=list)
    return_code: Optional[int] = None
    notes: str = ""
    env_vars: Dict[str, str] = field(default_factory=dict)


RUNS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
_jobs: Dict[str, Job] = {}
_lock = threading.Lock()


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
            _jobs[row["id"]] = Job(**row)
    except Exception:
        pass


def _sorted_jobs() -> List[Job]:
    with _lock:
        return sorted(_jobs.values(), key=lambda j: j.created_at, reverse=True)


def _tail_text(path: Path, max_lines: int = 450) -> str:
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-max_lines:])


def _discover_result_dirs() -> List[dict]:
    if not RESULTS_ROOT.exists():
        return []
    out = []
    for result_dir in sorted([p for p in RESULTS_ROOT.iterdir() if p.is_dir()], reverse=True):
        files = []
        for f in sorted(result_dir.rglob("*")):
            if f.is_file() and f.suffix.lower() in {".txt", ".csv", ".md", ".json", ".log"}:
                files.append({
                    "name": str(f.relative_to(result_dir)),
                    "path": str(f.relative_to(ROOT_DIR)),
                    "size": f.stat().st_size,
                })
        out.append({"name": result_dir.name, "files": files})
    return out


def _arg_if(form: dict, key: str, flag: str, cmd: List[str]) -> None:
    value = form.get(key, [""])[0].strip()
    if value:
        cmd.extend([flag, value])


def _bool_flag(form: dict, key: str, flag: str, cmd: List[str]) -> None:
    if form.get(key, [""])[0] in {"on", "1", "true"}:
        cmd.append(flag)


def _build_command(form: dict, result_dir: Path) -> tuple[List[str], str, str, str, Dict[str, str]]:
    mode = form.get("mode", ["playbook"])[0].strip()
    domain = form.get("domain", [""])[0].strip().lower()

    if mode == "playbook":
        version = form.get("playbook", ["v1"])[0].strip()
        threads = form.get("threads", ["100"])[0].strip() or "100"
        if not domain or version not in PLAYBOOKS:
            raise ValueError("Playbook mode requires valid domain and playbook version.")
        script = PLAYBOOKS[version]
        env_vars: Dict[str, str] = {}

        if version == "v2":
            # v2 script is primarily interactive and reads TARGET_URL from env when provided.
            cmd = ["bash", str(script)]
            env_vars["TARGET_URL"] = f"https://{domain}"
            env_vars["THREADS"] = threads
        else:
            cmd = ["bash", str(script), "-d", domain, "-t", threads, "-o", str(result_dir)]
            _arg_if(form, "chaos_key", "--chaos-key", cmd)
            _arg_if(form, "github_token", "--github-token", cmd)
            _bool_flag(form, "skip_portscan", "--skip-portscan", cmd)
            _bool_flag(form, "skip_jsanalysis", "--skip-jsanalysis", cmd)
            _bool_flag(form, "skip_nuclei", "--skip-nuclei", cmd)
            _bool_flag(form, "skip_subtakeover", "--skip-subtakeover", cmd)

        return cmd, mode, domain, f"playbook={version}", env_vars

    # mirrors rek.py CLI modes
    cmd = ["python3", str(ROOT_DIR / "rek.py")]
    if mode == "subdomain":
        if not domain:
            raise ValueError("Subdomain mode requires domain.")
        cmd.extend(["-d", domain])
        cmd.extend(["-o", str(result_dir / "results.txt")])
        _arg_if(form, "subdomain_wordlist", "-w", cmd)
        _arg_if(form, "token", "--token", cmd)
        _arg_if(form, "limit_commits", "--limit-commits", cmd)
        _bool_flag(form, "skip_forks", "--skip-forks", cmd)
        _arg_if(form, "timeout", "-t", cmd)
        _arg_if(form, "concurrency", "-c", cmd)
        _arg_if(form, "retries", "-r", cmd)
        _bool_flag(form, "silent", "--silent", cmd)
    elif mode == "http":
        input_file = form.get("input", [""])[0].strip() or str(result_dir / "results.txt")
        output_file = form.get("output", [""])[0].strip() or str(result_dir / "http_results.csv")
        cmd.extend(["--input", input_file, "-o", output_file])
        _arg_if(form, "timeout", "-t", cmd)
        _arg_if(form, "concurrency", "-c", cmd)
        _bool_flag(form, "silent", "--silent", cmd)
    elif mode == "directory":
        input_file = form.get("input", [""])[0].strip()
        status = form.get("status", [""])[0].strip()
        single_url = form.get("url", [""])[0].strip()
        if input_file:
            cmd.extend(["--input", input_file])
        if status:
            cmd.extend(["--status", status])
        if single_url:
            cmd.extend(["--url", single_url])
        _arg_if(form, "dir_wordlist", "--dir-wordlist", cmd)
        _arg_if(form, "depth", "--depth", cmd)
        _arg_if(form, "timeout", "-t", cmd)
        _arg_if(form, "concurrency", "-c", cmd)
        _bool_flag(form, "silent", "--silent", cmd)
    elif mode == "email":
        email_domain = form.get("email_domain", [""])[0].strip()
        email_username = form.get("email_username", [""])[0].strip()
        org = form.get("org", [""])[0].strip()
        if not any([email_domain, email_username, org]):
            raise ValueError("Email mode requires email-domain, email-username, or org.")
        if email_domain:
            cmd.extend(["--email-domain", email_domain])
        if email_username:
            cmd.extend(["--email-username", email_username])
        if org:
            cmd.extend(["--org", org])
        cmd.extend(["-o", str(result_dir / "email_results.csv")])
        _arg_if(form, "token", "--token", cmd)
        _arg_if(form, "hibp_key", "--hibp-key", cmd)
        _arg_if(form, "limit_commits", "--limit-commits", cmd)
        _bool_flag(form, "skip_forks", "--skip-forks", cmd)
        _arg_if(form, "timeout", "-t", cmd)
        _bool_flag(form, "silent", "--silent", cmd)
    else:
        raise ValueError("Invalid mode")

    if not domain:
        domain = form.get("email_domain", [""])[0].strip() or form.get("org", [""])[0].strip() or form.get("email_username", [""])[0].strip() or "n/a"
    return cmd, mode, domain, f"rek.py mode={mode}", {}


def _run_job(job_id: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.utcnow().isoformat(timespec="seconds")
    _save_state()

    log_path = Path(job.log_path)
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"[{datetime.utcnow().isoformat(timespec='seconds')}] START\n")
        log_file.write(f"Command: {' '.join(shlex.quote(x) for x in job.command)}\n\n")
        log_file.flush()

        process = subprocess.Popen(
            ["stdbuf", "-oL", "-eL", *job.command],
            cwd=ROOT_DIR,
            env={**os.environ, **job.env_vars},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        if job.notes == "playbook=v2" and process.stdin and job.env_vars.get("TARGET_URL"):
            process.stdin.write(f"{job.env_vars['TARGET_URL']}\n")
            process.stdin.flush()
            process.stdin.close()

        if process.stdout:
            for line in process.stdout:
                log_file.write(line)
                log_file.flush()

        code = process.wait()
        with _lock:
            current = _jobs.get(job_id)
            if current:
                current.return_code = code
                current.status = "completed" if code == 0 else "failed"
                current.ended_at = datetime.utcnow().isoformat(timespec="seconds")
        log_file.write(f"\n[{datetime.utcnow().isoformat(timespec='seconds')}] END (exit={code})\n")
        log_file.flush()
    _save_state()


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
            lines = int(params.get("lines", ["450"])[0])
            with _lock:
                job = _jobs.get(job_id)
            if not job:
                self._send_json({"error": "job not found"}, 404)
                return
            self._send_json({
                "job_id": job_id,
                "status": job.status,
                "return_code": job.return_code,
                "log": _tail_text(Path(job.log_path), max(50, min(lines, 1400))),
            })
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
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        domain_hint = form.get("domain", [""])[0].strip() or "target"
        result_dir = RESULTS_ROOT / f"ui-{domain_hint.replace('.', '_')}-{timestamp}"
        result_dir.mkdir(parents=True, exist_ok=True)
        job_id = uuid.uuid4().hex[:8]
        log_path = LOGS_DIR / f"{job_id}.log"

        try:
            command, mode, domain, notes, env_vars = _build_command(form, result_dir)
        except Exception as exc:
            self._send_html(self.render_index(error=str(exc)), 400)
            return

        job = Job(
            id=job_id,
            mode=mode,
            domain=domain,
            log_path=str(log_path),
            result_dir=str(result_dir.relative_to(ROOT_DIR)),
            command=command,
            notes=notes,
            env_vars=env_vars,
        )
        with _lock:
            _jobs[job.id] = job
        _save_state()
        threading.Thread(target=_run_job, args=(job.id,), daemon=True).start()
        self._redirect(f"/logs?id={job.id}")

    def render_index(self, error: str = "") -> str:
        jobs = _sorted_jobs()
        rows = []
        for j in jobs:
            cmd_preview = html.escape(" ".join(shlex.quote(x) for x in j.command[:8]))
            if len(j.command) > 8:
                cmd_preview += " ..."
            rows.append(
                f"<tr><td>{j.id}</td><td>{html.escape(j.mode)}</td><td>{html.escape(j.domain)}</td>"
                f"<td><span class='pill {j.status}'>{j.status}</span></td><td class='muted'>{j.created_at}</td>"
                f"<td><span class='code'>{cmd_preview}</span></td><td><a href='/logs?id={j.id}'>Logs</a></td></tr>"
            )
        job_rows = "".join(rows) or "<tr><td colspan='7'>No runs yet.</td></tr>"
        err = f"<div class='err'>{html.escape(error)}</div>" if error else ""

        return f"""<!doctype html><html><head><meta charset='utf-8'><title>REK Control Center</title><link rel='stylesheet' href='/styles.css'></head>
<body><header><h1>REK Control Center</h1><div class='muted'>Full launcher for playbook + rek.py modes with live logs.</div></header>
<main class='grid'>
<section class='card'>
<h2>Launch Scan</h2>{err}
<form action='/run' method='post' class='form-grid'>
<label>Mode
<select id='mode' name='mode'>
<option value='playbook'>Recon Playbook</option>
<option value='subdomain'>rek.py - Subdomain Enumeration</option>
<option value='http'>rek.py - HTTP Status Check</option>
<option value='directory'>rek.py - Directory Scan</option>
<option value='email'>rek.py - Email Search</option>
</select></label>

<div id='common-domain' class='group active'>
<label>Target Domain<input name='domain' placeholder='example.com'></label>
</div>

<div id='group-playbook' class='group active'>
<div class='grid2'>
<label>Playbook<select name='playbook'><option value='v1'>v1</option><option value='v2'>v2</option><option value='standard'>standard</option></select></label>
<label>Threads<input name='threads' type='number' min='1' value='100'></label>
</div>
<div class='grid2'>
<label>Chaos API Key<input name='chaos_key' placeholder='optional'></label>
<label>GitHub Token<input name='github_token' placeholder='optional'></label>
</div>
<div class='grid2'>
<label class='checkbox'><input type='checkbox' name='skip_portscan'>Skip port scan</label>
<label class='checkbox'><input type='checkbox' name='skip_jsanalysis'>Skip JS analysis</label>
<label class='checkbox'><input type='checkbox' name='skip_nuclei'>Skip nuclei</label>
<label class='checkbox'><input type='checkbox' name='skip_subtakeover'>Skip subdomain takeover checks</label>
</div>
</div>

<div id='group-subdomain' class='group'>
<div class='grid2'>
<label>Subdomain Wordlist (-w)<input name='subdomain_wordlist' placeholder='wordlists/subdomains-top5000.txt'></label>
<label>GitHub Token (--token)<input name='token' placeholder='optional'></label>
<label>Limit commits<input name='limit_commits' type='number' value='50'></label>
<label>Retries (-r)<input name='retries' type='number' value='3'></label>
<label>Timeout (-t)<input name='timeout' type='number' value='10'></label>
<label>Concurrency (-c)<input name='concurrency' type='number' value='50'></label>
</div>
<label class='checkbox'><input type='checkbox' name='skip_forks'>Skip forks</label>
<label class='checkbox'><input type='checkbox' name='silent'>Silent mode</label>
</div>

<div id='group-http' class='group'>
<div class='grid2'>
<label>Input file (--input)<input name='input' placeholder='results.txt'></label>
<label>Output file (-o)<input name='output' placeholder='http_results.csv'></label>
<label>Timeout (-t)<input name='timeout' type='number' value='10'></label>
<label>Concurrency (-c)<input name='concurrency' type='number' value='50'></label>
</div>
<label class='checkbox'><input type='checkbox' name='silent'>Silent mode</label>
</div>

<div id='group-directory' class='group'>
<div class='grid2'>
<label>Input file (--input)<input name='input' placeholder='http_results.csv'></label>
<label>Status codes (--status)<input name='status' placeholder='200,301,403'></label>
<label>Single URL (--url)<input name='url' placeholder='https://example.com'></label>
<label>Dir wordlist<input name='dir_wordlist' placeholder='wordlists/common-paths.txt'></label>
<label>Depth<input name='depth' type='number' min='1' max='10' value='5'></label>
<label>Timeout (-t)<input name='timeout' type='number' value='10'></label>
<label>Concurrency (-c)<input name='concurrency' type='number' value='50'></label>
</div>
<label class='checkbox'><input type='checkbox' name='silent'>Silent mode</label>
</div>

<div id='group-email' class='group'>
<div class='grid2'>
<label>Email domain (--email-domain)<input name='email_domain' placeholder='example.com'></label>
<label>Email username (--email-username)<input name='email_username' placeholder='github-user'></label>
<label>Organization (--org)<input name='org' placeholder='github-org'></label>
<label>Token (--token)<input name='token' placeholder='optional'></label>
<label>HIBP key (--hibp-key)<input name='hibp_key' placeholder='optional'></label>
<label>Limit commits<input name='limit_commits' type='number' value='50'></label>
<label>Timeout (-t)<input name='timeout' type='number' value='10'></label>
</div>
<label class='checkbox'><input type='checkbox' name='skip_forks'>Skip forks</label>
<label class='checkbox'><input type='checkbox' name='silent'>Silent mode</label>
</div>

<button type='submit'>Start Job</button>
<small>Mode options are aligned with existing CLI flags from <span class='code'>rek.py</span> and playbook scripts.</small>
</form>
</section>

<section class='card'>
<h2>How it maps to CLI</h2>
<ul>
<li><strong>Playbook</strong>: runs <span class='code'>playbook/rek-playbook-*.sh</span> with domain/threads and skip toggles.</li>
<li><strong>Subdomain</strong>: runs <span class='code'>python3 rek.py -d ...</span> with timeout/concurrency/retries/token controls.</li>
<li><strong>HTTP</strong>: runs <span class='code'>python3 rek.py --input ... -o ...</span>.</li>
<li><strong>Directory</strong>: runs <span class='code'>python3 rek.py --input/--status/--url ...</span>.</li>
<li><strong>Email</strong>: runs <span class='code'>python3 rek.py --email-domain/--email-username/--org ...</span>.</li>
</ul>
<div class='muted'>Jobs are persisted in <span class='code'>ui_runs/jobs.json</span>.</div>
</section>

<section class='card wide'>
<div class='row-between'><h2>Recent Jobs</h2><a href='/results'>Browse Results</a></div>
<table><thead><tr><th>ID</th><th>Mode</th><th>Target</th><th>Status</th><th>Created</th><th>Command preview</th><th>Logs</th></tr></thead><tbody>{job_rows}</tbody></table>
</section>
</main>
<script>
const mode = document.getElementById('mode');
const groups = {{
  playbook: document.getElementById('group-playbook'),
  subdomain: document.getElementById('group-subdomain'),
  http: document.getElementById('group-http'),
  directory: document.getElementById('group-directory'),
  email: document.getElementById('group-email'),
}};
const common = document.getElementById('common-domain');
function refreshMode() {{
  Object.values(groups).forEach(g => g.classList.remove('active'));
  groups[mode.value].classList.add('active');
  common.classList.toggle('active', mode.value !== 'email' && mode.value !== 'http' && mode.value !== 'directory');
}}
mode.addEventListener('change', refreshMode); refreshMode();
</script>
</body></html>"""

    def render_log(self, job_id: str) -> str:
        with _lock:
            job = _jobs.get(job_id)
        if not job:
            return "<h1>Job not found</h1>"
        safe = html.escape(_tail_text(Path(job.log_path)))
        cmd = html.escape(" ".join(shlex.quote(x) for x in job.command))
        return f"""<!doctype html><html><head><meta charset='utf-8'><title>Logs {job_id}</title><link rel='stylesheet' href='/styles.css'></head>
<body><header><h1>Job {job_id} · {html.escape(job.mode)} · {html.escape(job.domain)}</h1><a href='/'>← Back</a></header>
<main>
<div class='row-between'><div id='status' class='pill {job.status}'>{job.status}</div><a href='/results'>Browse Results</a></div>
<p class='muted'>Command: <span class='code'>{cmd}</span></p>
<pre id='log' class='log'>{safe}</pre>
</main>
<script>
const logEl = document.getElementById('log');
const statusEl = document.getElementById('status');
async function refresh() {{
  const res = await fetch('/api/log?id={job_id}&lines=900');
  if (!res.ok) return;
  const data = await res.json();
  statusEl.className = 'pill ' + data.status;
  statusEl.textContent = data.status + (data.return_code === null ? '' : ' (exit=' + data.return_code + ')');
  const atBottom = (logEl.scrollTop + logEl.clientHeight + 50) >= logEl.scrollHeight;
  logEl.textContent = data.log || '';
  if (atBottom) logEl.scrollTop = logEl.scrollHeight;
}}
setInterval(refresh, 2000);
refresh();
</script>
</body></html>"""

    def render_results(self) -> str:
        dirs = _discover_result_dirs()
        if not dirs:
            body = "<p>No result folders found in <code>results/</code> yet.</p>"
        else:
            parts = []
            for d in dirs:
                rows = "".join(
                    f"<li><a href='/view?file={quote(f['path'])}'>{html.escape(f['name'])}</a> <span class='muted'>({f['size']} bytes)</span></li>"
                    for f in d["files"]
                ) or "<li class='muted'>No supported files in this folder.</li>"
                parts.append(f"<details><summary>{html.escape(d['name'])} ({len(d['files'])} files)</summary><ul>{rows}</ul></details>")
            body = "".join(parts)

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
