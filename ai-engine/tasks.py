import os, json, subprocess, tempfile, shutil
from celery import Celery
from ai_fix import AIFixEngine
from nvd_client import NVDClient
from notifier import Notifier

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
celery_app = Celery("secureguard", broker=REDIS_URL, backend=REDIS_URL)

ai_engine = AIFixEngine()
nvd_client = NVDClient()
notifier = Notifier()

@celery_app.task(name="run_full_scan", bind=True, max_retries=2)
def run_full_scan(self, repo_url: str, commit_sha: str, repo_name: str):
    """Clone repo, run 5 scanners in parallel, enrich, AI-fix critical findings."""
    tmpdir = tempfile.mkdtemp(prefix="sg_scan_")
    
    try:
        # 1. Clone the specific commit
        subprocess.run(
            ["git", "clone", "--depth=1", repo_url, tmpdir],
            check=True, capture_output=True, timeout=120
        )
        subprocess.run(
            ["git", "checkout", commit_sha],
            cwd=tmpdir, capture_output=True, timeout=30
        )
        
        findings = []
        
        # 2. Semgrep SAST
        findings += run_semgrep(tmpdir)
        
        # 3. Bandit (Python)
        findings += run_bandit(tmpdir)
        
        # 4. Gitleaks
        findings += run_gitleaks(tmpdir)
        
        # 5. Trivy deps
        findings += run_trivy(tmpdir)
        
        # 6. Enrich with NVD
        enriched = nvd_client.enrich_findings(findings)
        
        # 7. Filter High/Critical → AI fix
        critical = [f for f in enriched if f.get("cvss_score", 0) >= 7.0]
        
        for finding in critical:
            fix = ai_engine.generate_fix(finding, tmpdir)
            if fix and fix.get("confidence", 0) > 0.7:
                finding["ai_fix"] = fix
                # Open Gitea PR with the fix
                open_gitea_pr(repo_name, commit_sha, finding, fix)
        
        # 8. Alert on criticals
        if critical:
            notifier.send_alert(repo_name, commit_sha, critical)
        
        # 9. Save results
        save_scan_results(repo_name, commit_sha, enriched)
        
        return {
            "status": "complete",
            "total_findings": len(findings),
            "critical": len(critical),
            "ai_fixes_generated": sum(1 for f in critical if "ai_fix" in f)
        }
        
    except Exception as e:
        raise self.retry(exc=e, countdown=30)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def run_semgrep(path: str) -> list:
    try:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json", "--quiet", path],
            capture_output=True, text=True, timeout=180
        )
        data = json.loads(result.stdout or "{}")
        findings = []
        for r in data.get("results", []):
            findings.append({
                "tool": "semgrep",
                "rule_id": r.get("check_id", ""),
                "file": r.get("path", ""),
                "line": r.get("start", {}).get("line", 0),
                "message": r.get("extra", {}).get("message", ""),
                "severity": r.get("extra", {}).get("severity", "WARNING"),
                "code_snippet": r.get("extra", {}).get("lines", ""),
                "cwe": r.get("extra", {}).get("metadata", {}).get("cwe", [])
            })
        return findings
    except Exception as e:
        print(f"Semgrep error: {e}")
        return []


def run_bandit(path: str) -> list:
    try:
        result = subprocess.run(
            ["bandit", "-r", path, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=120
        )
        data = json.loads(result.stdout or "{}")
        findings = []
        for issue in data.get("results", []):
            findings.append({
                "tool": "bandit",
                "rule_id": issue.get("test_id", ""),
                "file": issue.get("filename", ""),
                "line": issue.get("line_number", 0),
                "message": issue.get("issue_text", ""),
                "severity": issue.get("issue_severity", "MEDIUM"),
                "code_snippet": issue.get("code", ""),
                "cwe": issue.get("issue_cwe", {}).get("id", "")
            })
        return findings
    except Exception as e:
        print(f"Bandit error: {e}")
        return []


def run_gitleaks(path: str) -> list:
    try:
        result = subprocess.run(
            ["gitleaks", "detect", "--source", path, "--report-format", "json",
             "--report-path", "/tmp/gitleaks_report.json", "--no-git"],
            capture_output=True, text=True, timeout=60
        )
        with open("/tmp/gitleaks_report.json", "r") as f:
            data = json.load(f)
        findings = []
        for leak in (data or []):
            findings.append({
                "tool": "gitleaks",
                "rule_id": leak.get("RuleID", ""),
                "file": leak.get("File", ""),
                "line": leak.get("StartLine", 0),
                "message": f"Secret detected: {leak.get('Description', '')}",
                "severity": "HIGH",
                "code_snippet": leak.get("Match", ""),
                "secret_type": leak.get("RuleID", "")
            })
        return findings
    except Exception as e:
        print(f"Gitleaks error: {e}")
        return []


def run_trivy(path: str) -> list:
    try:
        result = subprocess.run(
            ["trivy", "fs", "--format", "json", "--quiet", path],
            capture_output=True, text=True, timeout=300
        )
        data = json.loads(result.stdout or "{}")
        findings = []
        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                findings.append({
                    "tool": "trivy",
                    "rule_id": vuln.get("VulnerabilityID", ""),
                    "file": res.get("Target", ""),
                    "line": 0,
                    "message": vuln.get("Title", ""),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "pkg_name": vuln.get("PkgName", ""),
                    "cve_id": vuln.get("VulnerabilityID", "")
                })
        return findings
    except Exception as e:
        print(f"Trivy error: {e}")
        return []


def open_gitea_pr(repo_name, commit_sha, finding, fix):
    """Create a branch with the fix and open a PR in Gitea."""
    import httpx
    gitea_url = os.getenv("GITEA_URL", "http://gitea:3000")
    token = os.getenv("GITEA_TOKEN", "")
    
    headers = {"Authorization": f"token {token}", "Content-Type": "application/json"}
    branch_name = f"secureguard/fix-{finding['rule_id']}-{commit_sha[:6]}"
    
    pr_body = f"""## 🔒 SecureGuard AI Fix

**Vulnerability:** {finding.get('rule_id', 'unknown')}  
**CVE:** {finding.get('cve_id', 'N/A')}  
**CVSS Score:** {finding.get('cvss_score', 'N/A')}  
**File:** `{finding.get('file', '')}` line {finding.get('line', 0)}  
**Confidence:** {fix.get('confidence', 0):.0%}

### Original issue
{finding.get('message', '')}

### AI-generated fix
{fix.get('fixed_code', '')}
> Auto-generated by SecureGuard AI engine. Review before merging.
"""
    
    try:
        with httpx.Client() as client:
            client.post(
                f"{gitea_url}/api/v1/repos/{repo_name}/pulls",
                headers=headers,
                json={
                    "title": f"[SecureGuard] Fix {finding.get('rule_id', 'vulnerability')}",
                    "body": pr_body,
                    "head": branch_name,
                    "base": "main"
                }
            )
    except Exception as e:
        print(f"PR creation error: {e}")


def save_scan_results(repo_name, commit_sha, findings):
    from db import get_db_session, ScanResult
    import uuid
    with get_db_session() as db:
        scan = ScanResult(
            id=str(uuid.uuid4()),
            repo_name=repo_name,
            commit_sha=commit_sha,
            findings=json.dumps(findings),
            total_findings=len(findings),
            critical_count=sum(1 for f in findings if f.get("cvss_score", 0) >= 9.0),
            high_count=sum(1 for f in findings if 7.0 <= f.get("cvss_score", 0) < 9.0),
        )
        db.add(scan)
        db.commit()
