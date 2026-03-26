"""
REK REST API
Provides a FastAPI-based REST API for programmatic access to all REK capabilities.
Endpoints for subdomain enumeration, cloud recon, takeover detection, headers audit, etc.
"""
import asyncio
import os
import json
import time
import uuid
import threading
from typing import List, Optional, Dict, Any
from datetime import datetime

try:
    from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    print("[!] FastAPI not installed. Run: pip install fastapi uvicorn")

import logging
logger = logging.getLogger(__name__)

# In-memory job store (use Redis for distributed)
_jobs: Dict[str, Dict] = {}
_jobs_lock = threading.Lock()

JOBS_FILE = 'rek_api_jobs.json'


def save_jobs():
    """Persist jobs to disk."""
    try:
        with open(JOBS_FILE, 'w') as f:
            json.dump(_jobs, f, default=str, indent=2)
    except Exception:
        pass


def load_jobs():
    """Load jobs from disk on startup."""
    global _jobs
    try:
        if os.path.exists(JOBS_FILE):
            with open(JOBS_FILE) as f:
                _jobs = json.load(f)
    except Exception:
        _jobs = {}


if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="REK Reconnaissance API",
        description="REK - Advanced Reconnaissance Toolkit REST API for bug bounty hunters",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    async def startup_event():
        load_jobs()

    # ── Request Models ────────────────────────────────────────────────────────

    class SubdomainRequest(BaseModel):
        domain: str
        wordlist_path: Optional[str] = None
        timeout: int = 10
        concurrency: int = 50
        github_token: Optional[str] = None

    class CloudReconRequest(BaseModel):
        domain: str
        timeout: int = 10
        concurrency: int = 50

    class TakeoverRequest(BaseModel):
        subdomains: List[str]
        timeout: int = 10
        concurrency: int = 50

    class HeadersAuditRequest(BaseModel):
        urls: List[str]
        timeout: int = 10
        concurrency: int = 30

    class FaviconRequest(BaseModel):
        urls: List[str]
        timeout: int = 10

    class ParamDiscoveryRequest(BaseModel):
        urls: List[str]
        timeout: int = 10
        concurrency: int = 20

    class ASNRequest(BaseModel):
        domain: str
        timeout: int = 15

    class GitHubDorkRequest(BaseModel):
        domain: str
        github_token: Optional[str] = None
        timeout: int = 15

    class MonitorRequest(BaseModel):
        domains: List[str]
        interval_minutes: int = 60
        slack_webhook: Optional[str] = None
        discord_webhook: Optional[str] = None

    class NotifyRequest(BaseModel):
        message: str
        title: Optional[str] = None
        severity: str = 'info'
        slack_webhook: Optional[str] = None
        discord_webhook: Optional[str] = None

    # ── Job management helpers ────────────────────────────────────────────────

    def create_job(job_type: str, params: Dict) -> str:
        job_id = str(uuid.uuid4())[:8]
        with _jobs_lock:
            _jobs[job_id] = {
                'id': job_id,
                'type': job_type,
                'status': 'queued',
                'params': params,
                'created_at': datetime.utcnow().isoformat(),
                'started_at': None,
                'completed_at': None,
                'result': None,
                'error': None,
            }
        save_jobs()
        return job_id

    def update_job(job_id: str, **kwargs):
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].update(kwargs)
        save_jobs()

    def get_job(job_id: str) -> Optional[Dict]:
        with _jobs_lock:
            return _jobs.get(job_id)

    def run_job_async(job_id: str, func, *args, **kwargs):
        """Run a job in a background thread."""
        def worker():
            update_job(job_id, status='running', started_at=datetime.utcnow().isoformat())
            try:
                result = func(*args, **kwargs)
                update_job(job_id, status='completed', result=result, completed_at=datetime.utcnow().isoformat())
            except Exception as e:
                update_job(job_id, status='failed', error=str(e), completed_at=datetime.utcnow().isoformat())

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    # ── API Routes ────────────────────────────────────────────────────────────

    @app.get("/", tags=["Health"])
    async def root():
        return {
            "name": "REK Reconnaissance API",
            "version": "1.0.0",
            "status": "running",
            "endpoints": [
                "/api/subdomains",
                "/api/cloud-recon",
                "/api/takeover",
                "/api/headers-audit",
                "/api/favicon",
                "/api/param-discovery",
                "/api/asn",
                "/api/github-dork",
                "/api/monitor/start",
                "/api/notify",
                "/jobs/{job_id}",
                "/jobs",
            ]
        }

    @app.get("/health", tags=["Health"])
    async def health():
        return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

    @app.get("/jobs", tags=["Jobs"])
    async def list_jobs(limit: int = Query(50, le=200)):
        with _jobs_lock:
            jobs = list(_jobs.values())
        jobs.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return {"jobs": jobs[:limit], "total": len(jobs)}

    @app.get("/jobs/{job_id}", tags=["Jobs"])
    async def get_job_status(job_id: str):
        job = get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return job

    @app.delete("/jobs/{job_id}", tags=["Jobs"])
    async def delete_job(job_id: str):
        with _jobs_lock:
            if job_id not in _jobs:
                raise HTTPException(status_code=404, detail="Job not found")
            del _jobs[job_id]
        save_jobs()
        return {"status": "deleted", "job_id": job_id}

    @app.post("/api/subdomains", tags=["Recon"])
    async def start_subdomain_enum(req: SubdomainRequest, background_tasks: BackgroundTasks):
        """Start subdomain enumeration for a domain."""
        job_id = create_job('subdomain_enum', req.dict())

        def run():
            from rek_wordlist_generator import REKWordlistGenerator
            from rek_email_search import EmailSearcher
            # Use the SubdomainScanner from rek.py
            sys_path_backup = None
            try:
                import sys
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from rek import SubdomainScanner
                scanner = SubdomainScanner(
                    timeout=req.timeout,
                    wordlist_path=req.wordlist_path,
                    concurrency=req.concurrency,
                    silent=True
                )
                output_file = f"results/{req.domain}_subdomains.txt"
                os.makedirs('results', exist_ok=True)
                asyncio.run(scanner.enumerate_subdomains(
                    domain=req.domain,
                    output_file=output_file,
                    github_token=req.github_token,
                ))
                subdomains = list(scanner.subdomains | scanner.validated_subdomains)
                return {'domain': req.domain, 'count': len(subdomains), 'subdomains': subdomains[:500], 'output_file': output_file}
            except Exception as e:
                return {'domain': req.domain, 'error': str(e), 'subdomains': []}

        run_job_async(job_id, run)
        return {"job_id": job_id, "status": "queued", "message": f"Subdomain enumeration started for {req.domain}"}

    @app.post("/api/cloud-recon", tags=["Recon"])
    async def start_cloud_recon(req: CloudReconRequest, background_tasks: BackgroundTasks):
        """Discover cloud assets (S3/Azure/GCP buckets) for a domain."""
        job_id = create_job('cloud_recon', req.dict())

        def run():
            from rek_cloud_recon import CloudRecon
            recon = CloudRecon(timeout=req.timeout, concurrency=req.concurrency, silent=True)
            findings = recon.run(req.domain, f"results/cloud_{req.domain}.csv")
            return {'domain': req.domain, 'count': len(findings), 'findings': findings[:100]}

        run_job_async(job_id, run)
        return {"job_id": job_id, "status": "queued", "message": f"Cloud recon started for {req.domain}"}

    @app.post("/api/takeover", tags=["Recon"])
    async def start_takeover_check(req: TakeoverRequest, background_tasks: BackgroundTasks):
        """Check subdomains for takeover vulnerabilities."""
        job_id = create_job('takeover', req.dict())

        def run():
            from rek_takeover import TakeoverDetector
            detector = TakeoverDetector(timeout=req.timeout, concurrency=req.concurrency, silent=True)
            findings = detector.run(subdomains=req.subdomains)
            return {'count': len(findings), 'findings': findings, 'vulnerable': [f for f in findings if f.get('status') == 'VULNERABLE']}

        run_job_async(job_id, run)
        return {"job_id": job_id, "status": "queued", "message": f"Takeover check started for {len(req.subdomains)} subdomains"}

    @app.post("/api/headers-audit", tags=["Recon"])
    async def start_headers_audit(req: HeadersAuditRequest, background_tasks: BackgroundTasks):
        """Audit URLs for CORS misconfigurations and missing security headers."""
        job_id = create_job('headers_audit', req.dict())

        def run():
            import re
            import sys
            sys.modules.setdefault('re', re)
            from rek_headers_audit import HeadersAuditor
            auditor = HeadersAuditor(timeout=req.timeout, concurrency=req.concurrency, silent=True)
            findings = auditor.run(urls=req.urls)
            return {'count': len(findings), 'findings': findings[:200], 'high': len([f for f in findings if f.get('severity') == 'High'])}

        run_job_async(job_id, run)
        return {"job_id": job_id, "status": "queued", "message": f"Headers audit started for {len(req.urls)} URLs"}

    @app.post("/api/favicon", tags=["Recon"])
    async def start_favicon_scan(req: FaviconRequest, background_tasks: BackgroundTasks):
        """Compute favicon hashes for infrastructure fingerprinting."""
        job_id = create_job('favicon_scan', req.dict())

        def run():
            from rek_favicon import FaviconScanner
            scanner = FaviconScanner(timeout=req.timeout, silent=True)
            findings = scanner.run(urls=req.urls)
            return {'count': len(findings), 'findings': findings, 'known_services': [f for f in findings if f.get('known_service')]}

        run_job_async(job_id, run)
        return {"job_id": job_id, "status": "queued", "message": f"Favicon scan started for {len(req.urls)} URLs"}

    @app.post("/api/param-discovery", tags=["Recon"])
    async def start_param_discovery(req: ParamDiscoveryRequest, background_tasks: BackgroundTasks):
        """Discover hidden parameters on web endpoints."""
        job_id = create_job('param_discovery', req.dict())

        def run():
            from rek_param_discovery import ParamDiscovery
            disco = ParamDiscovery(timeout=req.timeout, concurrency=req.concurrency, silent=True)
            findings = disco.run(urls=req.urls)
            return {'count': len(findings), 'findings': findings, 'total_params': sum(f.get('param_count', 0) for f in findings)}

        run_job_async(job_id, run)
        return {"job_id": job_id, "status": "queued", "message": f"Param discovery started for {len(req.urls)} URLs"}

    @app.post("/api/asn", tags=["Recon"])
    async def start_asn_recon(req: ASNRequest, background_tasks: BackgroundTasks):
        """Expand IP ranges via ASN lookup."""
        job_id = create_job('asn_recon', req.dict())

        def run():
            from rek_asn import ASNRecon
            recon = ASNRecon(timeout=req.timeout, silent=True)
            results = recon.run(req.domain)
            return {
                'domain': req.domain,
                'asns': list(results.get('asns', {}).values()),
                'prefix_count': len(results.get('prefixes', [])),
                'total_ips': results.get('total_ips', 0),
                'prefixes': results.get('prefixes', [])[:100],
            }

        run_job_async(job_id, run)
        return {"job_id": job_id, "status": "queued", "message": f"ASN recon started for {req.domain}"}

    @app.post("/api/github-dork", tags=["Recon"])
    async def start_github_dork(req: GitHubDorkRequest, background_tasks: BackgroundTasks):
        """Run GitHub dorks to find exposed secrets."""
        job_id = create_job('github_dork', {'domain': req.domain})

        def run():
            from rek_github_dorking import GitHubDorker
            dorker = GitHubDorker(token=req.github_token, timeout=req.timeout, silent=True)
            findings = dorker.run(req.domain)
            return {
                'domain': req.domain,
                'count': len(findings),
                'secrets': [f for f in findings if f.get('type') != 'DORK_MATCH'],
                'dork_matches': [f for f in findings if f.get('type') == 'DORK_MATCH'],
            }

        run_job_async(job_id, run)
        return {"job_id": job_id, "status": "queued", "message": f"GitHub dorking started for {req.domain}"}

    @app.post("/api/notify", tags=["Utilities"])
    async def send_notification(req: NotifyRequest):
        """Send a notification to configured webhooks."""
        from rek_notify import NotificationManager
        mgr = NotificationManager(
            slack_webhook=req.slack_webhook,
            discord_webhook=req.discord_webhook,
            silent=True,
        )
        sent = mgr.notify(req.message, title=req.title, severity=req.severity)
        return {"sent": sent}

    @app.get("/api/monitor/status", tags=["Monitor"])
    async def get_monitor_status():
        """Get current monitoring status."""
        from rek_monitor import ContinuousMonitor
        monitor = ContinuousMonitor(silent=True)
        return monitor.get_status()

    @app.post("/api/monitor/start", tags=["Monitor"])
    async def start_monitor(req: MonitorRequest, background_tasks: BackgroundTasks):
        """Start continuous monitoring for domains."""
        job_id = create_job('monitor', req.dict())

        def run():
            from rek_monitor import ContinuousMonitor
            monitor = ContinuousMonitor(
                interval_minutes=req.interval_minutes,
                slack_webhook=req.slack_webhook,
                discord_webhook=req.discord_webhook,
                silent=True,
            )
            monitor.start(req.domains, daemon=True)
            return {'domains': req.domains, 'interval_minutes': req.interval_minutes}

        run_job_async(job_id, run)
        return {"job_id": job_id, "status": "started", "message": f"Monitor started for {req.domains}"}

    @app.post("/api/monitor/stop", tags=["Monitor"])
    async def stop_monitor():
        """Stop running monitor daemon."""
        from rek_monitor import ContinuousMonitor
        monitor = ContinuousMonitor(silent=True)
        stopped = monitor.stop_daemon()
        return {"stopped": stopped}


def start_api_server(host: str = '0.0.0.0', port: int = 8080):
    """Start the REK API server."""
    if not FASTAPI_AVAILABLE:
        print("[!] FastAPI not available. Install with: pip install fastapi uvicorn")
        return

    try:
        import uvicorn
        print(f"[+] Starting REK API server on http://{host}:{port}")
        print(f"    Docs: http://{host}:{port}/docs")
        print(f"    OpenAPI: http://{host}:{port}/openapi.json")
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except ImportError:
        print("[!] uvicorn not installed. Run: pip install uvicorn")


if __name__ == '__main__':
    start_api_server()
