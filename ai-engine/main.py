import os
import logging
import hmac
import hashlib
import json
import re
from datetime import datetime

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Gauge, Histogram

log = logging.getLogger("orchestrator")
from sqlalchemy import text
from db import get_db_session, ScanRun, Finding, ScanReport
from report_parsers import parse_sarif, parse_bandit, determine_finding_class, validate_report_shape, REQUIRED_TOOLS, SUPPORTED_TOOLS

# ── App setup ────────────────────────────────────────────────
app = FastAPI(title="SecureGuard Orchestrator", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

# ── Prometheus metrics ────────────────────────────────────────
scans_total    = Counter("secureguard_scans_total",    "Total scans", ["repo", "status"])
findings_total = Counter("secureguard_findings_total", "Total findings", ["severity", "scanner"])
scans_active   = Gauge(  "secureguard_scans_active",   "Active scans")
prs_opened_total = Counter("secureguard_prs_opened_total", "Total AI fix PRs opened", ["repo"])
cve_fixed_total  = Counter("secureguard_cve_fixed_total",  "CVEs matched and fixed by AI engine", ["cve_id", "package", "severity"])

Instrumentator().instrument(app).expose(app, endpoint="/metrics")

WEBHOOK_SECRET = os.getenv("GITEA_WEBHOOK_SECRET", "")
API_KEY = os.getenv("SG_API_KEY", "")


@app.middleware("http")
async def protect_mutating_api_routes(request: Request, call_next):
    """Require the shared Jenkins key for state-changing API calls."""
    if request.url.path.startswith("/api/") and request.method in {"POST", "PATCH", "PUT", "DELETE"}:
        supplied = request.headers.get("X-API-Key", "")
        if not API_KEY or not hmac.compare_digest(supplied, API_KEY):
            return JSONResponse(
                status_code=401, content={"detail": "Unauthorized"}
            )
    return await call_next(request)


@app.on_event("startup")
async def startup():
    """Replay metrics after the migration service has prepared the database."""

    # Replay existing scan counts into Prometheus counters
    # (counters reset on restart — this restores accurate values)
    try:
        with get_db_session() as db:
            from sqlalchemy import text as _text, func
            # Count scans by status
            rows = db.execute(_text(
                "SELECT COALESCE(repo_name, 'unknown'), status, COUNT(*) FROM scan_runs GROUP BY repo_name, status"
            )).fetchall()
            for repo, status, count in rows:
                scans_total.labels(repo=repo, status=status).inc(count)
            scans_active.set(db.execute(_text(
                "SELECT COUNT(*) FROM scan_runs WHERE finished_at IS NULL AND status IN ('running', 'pr_opened')"
            )).scalar())

            # Count findings by severity and scanner
            rows2 = db.execute(_text(
                "SELECT severity, scanner, COUNT(*) FROM findings GROUP BY severity, scanner"
            )).fetchall()
            for severity, scanner, count in rows2:
                findings_total.labels(
                    severity=severity or "UNKNOWN",
                    scanner=scanner or "unknown"
                ).inc(count)

            # One PR may be associated with thousands of findings. Count its
            # URL once, matching the increment performed when a PR is opened.
            prs = db.execute(_text(
                """SELECT s.repo_name, COUNT(DISTINCT f.pr_url)
                   FROM findings f JOIN scan_runs s ON f.scan_run_id = s.id 
                   WHERE f.pr_url IS NOT NULL AND f.pr_url <> ''
                   GROUP BY s.repo_name"""
            )).fetchall()
            for repo_name, count in prs:
                prs_opened_total.labels(repo=repo_name or "unknown").inc(count)

            print(f"Metrics replayed from DB on startup")
    except Exception as e:
        print(f"Metric replay warning: {e}")


# ── Helpers ───────────────────────────────────────────────────

def verify_signature(payload: bytes, signature: str) -> bool:
    if not WEBHOOK_SECRET:
        return False
    expected = hmac.new(
        WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    # Gitea sends the SHA-256 HMAC as a bare hexadecimal value.
    return hmac.compare_digest(expected, signature.removeprefix("sha256="))


def save_findings_to_db(db, scan_run_id: int, findings: list[dict]):
    """Insert findings and update scan_run counters."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in findings:
        sev = (f.get("severity") or "MEDIUM").upper()
        if sev in counts:
            counts[sev] += 1

        db.add(Finding(
            scan_run_id    = scan_run_id,
            scanner        = f.get("scanner", "unknown"),
            rule_id        = f.get("rule_id"),
            cve_id         = f.get("cve_id"),
            cwe_id         = f.get("cwe_id"),
            severity       = sev,
            cvss_score     = f.get("cvss_score"),
            title          = f.get("title", "Unknown")[:500],
            description    = f.get("description", "")[:2000],
            file_path      = f.get("file_path", ""),
            line_start     = f.get("line_start"),
            line_end       = f.get("line_end"),
            vulnerable_code= f.get("vulnerable_code", "")[:5000],
            finding_class  = f.get("finding_class", determine_finding_class(f.get("scanner", "unknown"))),
            package        = f.get("package"),
            installed_version = f.get("installed_version"),
            fixed_version  = f.get("fixed_version"),
            image          = f.get("image"),
        ))
        findings_total.labels(
            severity=sev,
            scanner=f.get("scanner", "unknown")
        ).inc()

    # Update scan_run counters
    scan = db.query(ScanRun).filter_by(id=scan_run_id).first()
    if scan:
        scan.total_findings = (scan.total_findings or 0) + len(findings)
        scan.critical_count = (scan.critical_count or 0) + counts["CRITICAL"]
        scan.high_count     = (scan.high_count or 0) + counts["HIGH"]
        scan.medium_count   = (scan.medium_count or 0) + counts["MEDIUM"]
        scan.low_count      = (scan.low_count or 0) + counts["LOW"]


# ── API endpoints ─────────────────────────────────────────────

def required_tools(value):
    if (not isinstance(value, list) or any(not isinstance(tool, str) for tool in value)
            or not REQUIRED_TOOLS <= set(value) or not set(value) <= SUPPORTED_TOOLS):
        raise HTTPException(status_code=422, detail='Invalid required scanner report set')
    return sorted(set(value))


@app.post("/webhook/gitea")
async def gitea_webhook(request: Request):
    """Direct Gitea webhook — alternative to Jenkins pipeline."""
    payload_bytes = await request.body()
    sig = request.headers.get("X-Gitea-Signature", "")
    if not verify_signature(payload_bytes, sig):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload    = json.loads(payload_bytes)
    repo_url   = payload.get("repository", {}).get("clone_url", "")
    commit_sha = payload.get("after", "")
    repo_name  = payload.get("repository", {}).get("full_name", "unknown")

    if not repo_url or not commit_sha:
        raise HTTPException(status_code=400, detail="Missing repo_url or commit")

    return {"status": "received", "repo": repo_name, "commit": commit_sha[:8]}


@app.post("/api/scans")
async def create_scan(request: Request):
    """Called by Jenkins pipeline — registers a new scan run, returns real DB id."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail='Scan payload must be an object')
    expected = required_tools(body.get('required_reports', sorted(REQUIRED_TOOLS)))
    repo_url   = body.get("repo_url")
    commit_sha = body.get("commit_sha")
    branch     = body.get("branch", "main")
    from fix_engine import canonical_repo_url
    if not isinstance(repo_url, str):
        raise HTTPException(status_code=422, detail='repo_url must be a configured Gitea clone URL')
    try:
        repo_url = canonical_repo_url(repo_url)
    except ValueError:
        raise HTTPException(status_code=422, detail='repo_url must be a configured Gitea clone URL')
    if not isinstance(commit_sha, str) or not re.fullmatch(r'[0-9a-fA-F]{40}', commit_sha):
        raise HTTPException(status_code=422, detail='commit_sha must be the exact 40-character scanned commit')
    if not isinstance(branch, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_./-]{0,254}', branch):
        raise HTTPException(status_code=422, detail='Invalid scan branch')
    pipeline_commit = body.get('pipeline_commit')
    if pipeline_commit is not None and (not isinstance(pipeline_commit, str) or not re.fullmatch(r'[0-9a-fA-F]{40}', pipeline_commit)):
        raise HTTPException(status_code=422, detail='pipeline_commit must be a full Git SHA')
    if body.get('repo_name') is not None and (not isinstance(body['repo_name'], str) or len(body['repo_name']) > 255):
        raise HTTPException(status_code=422, detail='Invalid repository name')
    repo_name  = body.get("repo_name") or repo_url.rstrip("/").removesuffix(".git").split("/")[-1]

    try:
        with get_db_session() as db:
            scan = ScanRun(
                repo_url     = repo_url,
                commit_sha   = commit_sha,
                branch       = branch,
                repo_name    = repo_name,
                triggered_by = "jenkins",
                status       = "running",
                started_at   = datetime.utcnow(),
                required_reports = expected,
                pipeline_commit = pipeline_commit,
            )
            db.add(scan)
            db.flush()          # flush to get the auto-generated id
            scan_id = scan.id   # capture before session closes
            db.commit()

        scans_total.labels(repo=repo_name, status="started").inc()
        scans_active.inc()

        return {"id": scan_id, "status": "created", "repo": repo_name}

    except Exception as e:
        print(f"DB error in create_scan: {e}")
        raise HTTPException(status_code=503, detail="Database unavailable") from e


@app.get("/api/scans")
async def get_scans(limit: int = 100, summary_only: bool = False):
    """Return recent scan runs for the dashboard."""
    try:
        with get_db_session() as db:
            results = (
                db.query(ScanRun)
                .order_by(ScanRun.started_at.desc())
                .limit(max(1, min(limit, 500)))
                .all()
            )
            payload = []
            for row in results:
                item = row.to_dict()
                if not summary_only:
                    findings = db.query(Finding).filter_by(scan_run_id=row.id).all()
                    item["findings"] = [finding.to_dict() for finding in findings]
                payload.append(item)
            return payload
    except Exception as e:
        print(f"DB error in get_scans: {e}")
        raise HTTPException(status_code=503, detail="Database unavailable") from e


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    try:
        with get_db_session() as db:
            result = db.query(ScanRun).filter_by(id=int(scan_id)).first()
            if not result:
                raise HTTPException(status_code=404, detail="Scan not found")
            scan_dict = result.to_dict()
            # Also fetch findings
            findings = db.query(Finding).filter_by(scan_run_id=int(scan_id)).all()
            scan_dict["findings"] = [f.to_dict() for f in findings]
            scan_dict['reports'] = [report.to_dict() for report in db.query(ScanReport).filter_by(scan_run_id=int(scan_id)).all()]
            return scan_dict
    except HTTPException:
        raise
    except Exception:
        log.exception("Could not read scan %s", scan_id)
        raise HTTPException(status_code=503, detail="Scan data unavailable")


@app.patch("/api/scans/{scan_id}")
async def update_scan(scan_id: int, request: Request):
    """Called by Jenkins to update scan status."""
    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise HTTPException(status_code=422, detail="Invalid scan update")
        status = body.get("status")
        if status is not None and (not isinstance(status, str) or status not in {"complete", "failed"}):
            raise HTTPException(status_code=422, detail="Invalid scan status")
        expected = required_tools(body['required_reports']) if 'required_reports' in body else None
        if status is None and expected is None:
            raise HTTPException(status_code=422, detail='No scan update supplied')
        with get_db_session() as db:
            scan = db.query(ScanRun).filter_by(id=int(scan_id)).with_for_update().first()
            if scan:
                if expected is not None:
                    if scan.finished_at is not None and set(expected) != set(scan.required_reports or []):
                        raise HTTPException(status_code=409, detail='Finalized report contract cannot be changed')
                    if not set(scan.required_reports or []) <= set(expected):
                        raise HTTPException(status_code=422, detail='Required reports cannot be removed')
                    scan.required_reports = expected
                if status == 'complete':
                    if scan.status == 'failed':
                        raise HTTPException(status_code=409, detail='Failed scans require a new scan; completion cannot be replayed')
                    received = {report.tool for report in db.query(ScanReport).filter_by(scan_run_id=scan.id).all()}
                    missing = set(scan.required_reports or REQUIRED_TOOLS) - received
                    if missing:
                        raise HTTPException(status_code=409, detail='Missing scanner reports: ' + ', '.join(sorted(missing)))
                if status is not None and scan.finished_at is None:
                    scan.finished_at = datetime.utcnow()
                    scans_active.dec()
                if status is not None and (status == "failed" or scan.status not in {"pr_opened", "ai_fixed"}):
                    scan.status = status
            else:
                raise HTTPException(status_code=404, detail="Scan not found")
        return {"status": "updated"}
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid scan update")
    except Exception:
        log.exception("Could not update scan %s", scan_id)
        raise HTTPException(status_code=503, detail="Scan update unavailable")


@app.post("/api/scans/{scan_id}/reports/{tool}")
async def upload_report(scan_id: int, tool: str, request: Request):
    """
    Receives scanner output from Jenkins.
    Accepts SARIF (JSON) or Bandit JSON.
    Parses findings and saves to DB.
    """
    try:
        raw = await request.body()
        data = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid {tool} JSON report")

    try:
        validate_report_shape(data, tool)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {tool} report: {exc}") from exc

    try:
        if tool == "bandit":
            findings = parse_bandit(data)
        elif tool == "syft-sbom":
            findings = []  # An inventory, not a vulnerability report.
        else:
            findings = parse_sarif(data, tool)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {tool} report content") from exc

    try:
        with get_db_session() as db:
            scan = db.query(ScanRun).filter_by(id=scan_id).with_for_update().first()
            if not scan:
                raise HTTPException(status_code=404, detail="Scan not found")
            digest = hashlib.sha256(raw).hexdigest()
            existing = db.query(ScanReport).filter_by(scan_run_id=scan_id, tool=tool).first()
            if existing and existing.sha256 != digest:
                raise HTTPException(status_code=409, detail='A different report for this tool is already stored; create a new scan')
            if not existing and scan.finished_at is not None:
                raise HTTPException(status_code=409, detail='Scan is already finalized')
            if findings and not existing:
                save_findings_to_db(db, int(scan_id), findings)
            if not existing:
                not_applicable = tool in {'osv', 'hadolint', 'shellcheck'} and any(run.get('properties', {}).get('coverage') == 'not_applicable' for run in data.get('runs', []))
                db.add(ScanReport(scan_run_id=scan_id, tool=tool, sha256=digest,
                                  finding_count=len(findings), coverage='not_applicable' if not_applicable else 'analyzed'))
    except HTTPException:
        raise
    except Exception:
        log.exception("DB error saving findings for %s", tool)
        raise HTTPException(status_code=500, detail="Could not persist findings")

    return {
        "status":   "received",
        "tool":     tool,
        "scan_id":  scan_id,
        "findings": len(findings),
    }


@app.post("/api/scans/{scan_id}/enrich")
async def enrich_scan(scan_id: str, request: Request):
    """Queue CVE enrichment and return its worker job ID."""
    try:
        numeric_scan_id = int(scan_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="scan_id must be an integer")
    CVE_INTEL = os.getenv("CVE_INTEL_URL", "http://sg-cve-intel:8001")
    try:
        import httpx as _httpx
        async with _httpx.AsyncClient() as client:
            r = await client.post(
                f"{CVE_INTEL}/enrich/{numeric_scan_id}",
                headers={"X-API-Key": API_KEY}, timeout=15,
            )
    except _httpx.RequestError as e:
        log.error("CVE enrichment service unavailable: %s", e)
        raise HTTPException(status_code=502, detail="CVE enrichment service unavailable")
    if r.status_code != 202:
        log.error("CVE enrichment rejected scan %s: HTTP %s", scan_id, r.status_code)
        raise HTTPException(status_code=502, detail="CVE enrichment was not queued")
    return {**r.json(), "status": "enrichment_queued", "scan_id": numeric_scan_id}


@app.post("/api/scans/{scan_id}/fix")
async def fix_scan(scan_id: str, request: Request):
    """
    Queue a proposal for eligible Python SAST findings after report acceptance.
    """
    # Repository coordinates are always loaded from the trusted scan record. Never
    # accept a caller-provided URL because clone_repo injects the Gitea credential.
    try:
        numeric_scan_id = int(scan_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="scan_id must be an integer")

    with get_db_session() as db:
        scan = db.query(ScanRun).filter_by(id=numeric_scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.status == 'failed':
            raise HTTPException(status_code=409, detail='Cannot remediate a failed scan')
        received = {report.tool for report in db.query(ScanReport).filter_by(scan_run_id=scan.id).all()}
        if set(scan.required_reports or REQUIRED_TOOLS) - received:
            raise HTTPException(status_code=409, detail='Accept all required reports before queuing remediation')
        repo_url = scan.repo_url
        commit_sha = scan.commit_sha

    from tasks import run_ai_fix
    job = run_ai_fix.delay(numeric_scan_id, repo_url, commit_sha)
    return {"status": "fix_queued", "scan_id": scan_id, "job_id": job.id}


@app.post("/api/scans/{scan_id}/notify")
async def notify_scan(scan_id: str, request: Request):
    """Notification trigger."""
    try:
        with get_db_session() as db:
            scan = db.query(ScanRun).filter_by(id=int(scan_id)).first()
            if not scan:
                return {"status": "error", "reason": "scan not found"}
            
            repo_name = scan.repo_url.rstrip("/").removesuffix(".git").split("/")[-1] if scan.repo_url else "Unknown Repo"
            
            # Get critical findings for this scan
            findings = db.query(Finding).filter(
                Finding.scan_run_id == int(scan_id),
                Finding.severity.in_(["HIGH", "CRITICAL"])
            ).all()
            
            if findings:
                criticals = [f.to_dict() for f in findings]
                from notifier import Notifier
                notifier = Notifier()
                notifier.send_alert(repo_name, scan.commit_sha or "HEAD", criticals)
                
    except Exception as e:
        print(f"Notification error: {e}")
        return {"status": "error", "reason": str(e)}

    return {"status": "notified", "scan_id": scan_id}



@app.get("/api/cves")
async def get_cve_findings(limit: int = 100):
    """Return all findings that have CVE IDs — for Grafana CVE panel."""
    try:
        with get_db_session() as db:
            from sqlalchemy import text as _text
            rows = db.execute(_text("""
                SELECT f.cve_id, f.severity, f.cvss_score, f.title,
                       f.file_path, f.scanner, f.fix_status, f.pr_url,
                       f.pr_confidence, sr.repo_name, sr.id as scan_id,
                       sr.started_at
                FROM findings f
                JOIN scan_runs sr ON sr.id = f.scan_run_id
                WHERE f.cve_id IS NOT NULL
                  AND f.cve_id != ''
                ORDER BY f.cvss_score DESC NULLS LAST, f.severity DESC
                LIMIT :limit
            """), {"limit": limit}).fetchall()

            return [
                {
                    "cve_id":       r.cve_id,
                    "severity":     r.severity,
                    "cvss_score":   float(r.cvss_score) if r.cvss_score else None,
                    "title":        r.title,
                    "file_path":    r.file_path,
                    "scanner":      r.scanner,
                    "fix_status":   r.fix_status,
                    "pr_url":       r.pr_url,
                    "confidence":   float(r.pr_confidence) if r.pr_confidence else None,
                    "repo":         r.repo_name,
                    "scan_id":      r.scan_id,
                }
                for r in rows
            ]
    except Exception as e:
        return {"error": str(e)}

@app.get("/health")
async def health():
    """Health check — also verifies DB connectivity."""
    try:
        with get_db_session() as db:
            db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {e}"

    payload = {
        "status":    "ok" if db_status == "ok" else "error",
        "db":        db_status,
        "timestamp": datetime.utcnow().isoformat(),
    }
    return JSONResponse(payload, status_code=200 if db_status == "ok" else 503)
