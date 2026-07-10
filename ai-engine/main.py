import os
import logging
import hmac
import hashlib
import json
import re
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Gauge, Histogram

log = logging.getLogger("orchestrator")
from sqlalchemy import text
from db import get_db_session, ScanRun, Finding, init_db, ScanResult

# ── App setup ────────────────────────────────────────────────
app = FastAPI(title="SecureGuard Orchestrator", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Prometheus metrics ────────────────────────────────────────
scans_total    = Counter("secureguard_scans_total",    "Total scans", ["repo", "status"])
findings_total = Counter("secureguard_findings_total", "Total findings", ["severity", "scanner"])
scans_active   = Gauge(  "secureguard_scans_active",   "Active scans")
prs_opened_total = Counter("secureguard_prs_opened_total", "Total AI fix PRs opened", ["repo"])
cve_fixed_total  = Counter("secureguard_cve_fixed_total",  "CVEs matched and fixed by AI engine", ["cve_id", "package", "severity"])

Instrumentator().instrument(app).expose(app, endpoint="/metrics")

WEBHOOK_SECRET = os.getenv("GITEA_WEBHOOK_SECRET", "")


@app.on_event("startup")
async def startup():
    """Initialize DB tables on startup."""
    try:
        init_db()
    except Exception as e:
        print(f"DB init warning: {e}")


# ── Helpers ───────────────────────────────────────────────────

def verify_signature(payload: bytes, signature: str) -> bool:
    if not WEBHOOK_SECRET:
        return True
    expected = hmac.new(
        WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


def parse_sarif(sarif_data: dict, tool: str) -> list[dict]:
    """Parse SARIF 2.1.0 format into finding dicts."""
    findings = []
    for run in sarif_data.get("runs", []):
        rules = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            sev_map = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
            level   = result.get("level", "warning")
            sev     = result.get("properties", {}).get("severity",
                        sev_map.get(level, "MEDIUM")).upper()

            locs   = result.get("locations", [{}])
            loc    = locs[0].get("physicalLocation", {}) if locs else {}
            region = loc.get("region", {})
            rule_id = result.get("ruleId", "")
            rule    = rules.get(rule_id, {})

            findings.append({
                "scanner":        tool,
                "rule_id":        rule_id,
                "cve_id":         (result.get("properties", {}).get("cve_id")
                                   or (rule_id if rule_id.startswith("CVE-") else None)),
                "cwe_id":         result.get("properties", {}).get("cwe_id"),
                "severity":       sev,
                "cvss_score":     result.get("properties", {}).get("cvss_score"),
                "title":          (rule.get("name") or
                                   result.get("message", {}).get("text", rule_id) or
                                   rule_id)[:500],
                "description":    (rule.get("fullDescription", {}).get("text") or
                                   result.get("message", {}).get("text", ""))[:2000],
                "file_path":      loc.get("artifactLocation", {}).get("uri", ""),
                "line_start":     region.get("startLine"),
                "line_end":       region.get("endLine"),
                "vulnerable_code": result.get("properties", {}).get("snippet", "")[:5000],
            })
    return findings


def parse_bandit(bandit_data: dict) -> list[dict]:
    """Parse Bandit JSON format into finding dicts."""
    findings = []
    sev_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    for issue in bandit_data.get("results", []):
        findings.append({
            "scanner":        "bandit",
            "rule_id":        issue.get("test_id", ""),
            "cve_id":         None,
            "cwe_id":         str(issue.get("issue_cwe", {}).get("id", "")),
            "severity":       sev_map.get(issue.get("issue_severity", "MEDIUM"), "MEDIUM"),
            "cvss_score":     None,
            "title":          issue.get("test_name", "")[:500],
            "description":    issue.get("issue_text", "")[:2000],
            "file_path":      issue.get("filename", "").lstrip("/src/"),
            "line_start":     issue.get("line_number"),
            "line_end":       (issue.get("line_range") or [None])[-1],
            "vulnerable_code": issue.get("code", "")[:5000],
        })
    return findings


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
        ))
        findings_total.labels(
            severity=sev,
            scanner=f.get("scanner", "unknown")
        ).inc()

    # Update scan_run counters
    scan = db.query(ScanRun).filter_by(id=scan_run_id).first()
    if scan:
        scan.total_findings = len(findings)
        scan.critical_count = counts["CRITICAL"]
        scan.high_count     = counts["HIGH"]
        scan.medium_count   = counts["MEDIUM"]
        scan.low_count      = counts["LOW"]
        scan.status         = "complete"
        scan.finished_at    = datetime.utcnow()


# ── API endpoints ─────────────────────────────────────────────

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

    repo_url   = body.get("repo_url", "")
    commit_sha = body.get("commit_sha", "HEAD")
    branch     = body.get("branch", "main")
    repo_name  = body.get("repo_name") or repo_url.rstrip("/").rstrip(".git").split("/")[-1]

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
        return {"id": 0, "status": "db_error", "error": str(e)}


@app.get("/api/scans")
async def get_scans(limit: int = 100):
    """Return recent scan runs for the dashboard."""
    try:
        with get_db_session() as db:
            results = (
                db.query(ScanRun)
                .order_by(ScanRun.started_at.desc())
                .limit(limit)
                .all()
            )
            return [r.to_dict() for r in results]
    except Exception as e:
        print(f"DB error in get_scans: {e}")
        return []


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    try:
        with get_db_session() as db:
            result = db.query(ScanRun).filter_by(id=int(scan_id)).first()
            if not result:
                raise HTTPException(status_code=404, detail="Scan not found")
            scan_dict = result.to_dict()
            # Also fetch findings
            findings = db.query(Finding).filter_by(scan_run_id=int(scan_id)).all()
            scan_dict["findings"] = [f.to_dict() for f in findings]
            return scan_dict
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/api/scans/{scan_id}")
async def update_scan(scan_id: str, request: Request):
    """Called by Jenkins to update scan status."""
    try:
        body = await request.json()
        with get_db_session() as db:
            scan = db.query(ScanRun).filter_by(id=int(scan_id)).first()
            if scan:
                scan.status = body.get("status", scan.status)
                if body.get("status") in ("complete", "failed"):
                    scan.finished_at = datetime.utcnow()
                    scans_active.dec()
        return {"status": "updated"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/scans/{scan_id}/reports/{tool}")
async def upload_report(scan_id: str, tool: str, request: Request):
    """
    Receives scanner output from Jenkins.
    Accepts SARIF (JSON) or Bandit JSON.
    Parses findings and saves to DB.
    """
    try:
        raw = await request.body()
        data = json.loads(raw)
    except Exception:
        return {"status": "parse_error", "tool": tool}

    findings = []
    if tool == "bandit":
        findings = parse_bandit(data)
    elif "runs" in data:
        findings = parse_sarif(data, tool)

    if findings:
        try:
            with get_db_session() as db:
                save_findings_to_db(db, int(scan_id), findings)
        except Exception as e:
            print(f"DB error saving findings for {tool}: {e}")

    return {
        "status":   "received",
        "tool":     tool,
        "scan_id":  scan_id,
        "findings": len(findings),
    }


@app.post("/api/scans/{scan_id}/enrich")
async def enrich_scan(scan_id: str, request: Request):
    """CVE enrichment trigger - calls cve-intel service."""
    CVE_INTEL = os.getenv("CVE_INTEL_URL", "http://sg-cve-intel:8001")
    try:
        import httpx as _httpx
        async with _httpx.AsyncClient() as client:
            r = await client.post(f"{CVE_INTEL}/enrich/{scan_id}", timeout=300)
            if r.status_code == 200:
                return {"status": "enriched", "scan_id": scan_id, **r.json()}
    except Exception as e:
        print(f"CVE enrichment call error: {e}")
    return {"status": "enrichment_queued", "scan_id": scan_id}


@app.post("/api/scans/{scan_id}/fix")
async def fix_scan(scan_id: str, request: Request):
    """
    AI fix engine trigger — called by Jenkins after CVE enrichment.
    Reads HIGH/CRITICAL findings, calls NVIDIA NIM, opens Gitea PRs.
    Runs in background so Jenkins does not timeout.
    """
    try:
        body       = await request.json()
        repo_url   = body.get("repo_url", "")
        commit_sha = body.get("commit_sha", "HEAD")
    except Exception:
        repo_url   = ""
        commit_sha = "HEAD"

    # Get repo_url from DB if not provided
    if not repo_url:
        try:
            with get_db_session() as db:
                scan = db.query(ScanRun).filter_by(id=int(scan_id)).first()
                if scan:
                    repo_url   = scan.repo_url
                    commit_sha = scan.commit_sha
        except Exception:
            pass

    async def _run_fix():
        try:
            from fix_engine import run_ai_fix_engine
            result = run_ai_fix_engine(int(scan_id), repo_url, commit_sha)
            log.info(f"AI fix complete for scan {scan_id}: {result}")
        except Exception as e:
            log.error(f"AI fix engine error for scan {scan_id}: {e}")

    import asyncio
    asyncio.create_task(_run_fix())

    return {"status": "fix_started", "scan_id": scan_id, "repo_url": repo_url}


@app.post("/api/scans/{scan_id}/notify")
async def notify_scan(scan_id: str, request: Request):
    """Notification trigger."""
    return {"status": "notified", "scan_id": scan_id}


@app.get("/health")
async def health():
    """Health check — also verifies DB connectivity."""
    try:
        with get_db_session() as db:
            db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {e}"

    return {
        "status":    "ok",
        "db":        db_status,
        "timestamp": datetime.utcnow().isoformat(),
    }
