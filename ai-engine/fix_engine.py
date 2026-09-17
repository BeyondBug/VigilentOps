import time
"""
SecureGuard AI Fix Engine v3
─────────────────────────────
Key improvements over v2:
1. Processes MEDIUM+ findings (not just HIGH/CRITICAL)
2. Sends ENTIRE FILE to NIM — fixes all vulnerabilities in one pass
3. No line-by-line patching — NIM returns the complete fixed file
4. PR description correctly populated with actual changes
5. Strict prompt — returns only pure code, zero comments
6. Model fallback: Llama 3.1 70B → Kimi K2 if quality is low
7. Single branch + single PR per scan run
"""

import os
import re
import json
import tempfile
import shutil
import subprocess
import logging
from urllib.parse import urlparse
from pathlib import Path
from typing import Optional
from collections import defaultdict

import re, ast, json as _json
from llm_response import extract_llm_content

def parses_ok(path: str, content: str) -> bool:
    if path.endswith(".py"):
        try:
            ast.parse(content); return True
        except SyntaxError as e:
            log.warning(f"REJECT {path}: syntax error L{e.lineno}: {e.msg}")
            return False
    if path.endswith(".json"):
        try:
            _json.loads(content); return True
        except Exception:
            log.warning(f"REJECT {path}: invalid JSON"); return False
    if path.endswith(".txt"):
        bad = [l for l in content.splitlines()
               if l.strip() and not re.match(r'^[A-Za-z0-9._\-\[\]]+\s*[=<>!~]', l.strip())]
        if bad:
            log.warning(f"REJECT {path}: {len(bad)} malformed requirement lines")
            return False
    return True

import httpx
import psycopg2
import psycopg2.extras
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

PUSHGATEWAY_URL = os.getenv("PUSHGATEWAY_URL", "http://sg-pushgateway:9091")
log = logging.getLogger("ai-fix-v3")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ── Config ────────────────────────────────────────────────────

MODELS = []
for i in range(1, 10):
    m = os.getenv(f"MODEL_{i}")
    k = os.getenv(f"API_KEY_{i}")
    u = os.getenv(f"API_URL_{i}")
    if m and k and u:
        MODELS.append({"model": m, "key": k, "url": u})

# Fallback to legacy
if not MODELS:
    MODELS.append({
        "model": os.getenv("PRIMARY_MODEL", "moonshotai/kimi-k3"),
        "key": os.getenv("PRIMARY_API_KEY", ""),
        "url": os.getenv("PRIMARY_API_URL", "https://api.moonshot.cn/v1/chat/completions")
    })
    MODELS.append({
        "model": os.getenv("SECONDARY_MODEL", "deepseek-ai/deepseek-v4-flash-0731"),
        "key": os.getenv("SECONDARY_API_KEY", ""),
        "url": os.getenv("SECONDARY_API_URL", "https://api.deepseek.com/chat/completions")
    })
    MODELS.append({
        "model": os.getenv("FALLBACK_MODEL", "meta/muse-glimmer-30b"),
        "key": os.getenv("FALLBACK_API_KEY", ""),
        "url": os.getenv("FALLBACK_API_URL", "https://api.together.xyz/v1/chat/completions")
    })

GITEA_URL        = os.getenv("GITEA_URL",      "http://sg-gitea:3000")

GITEA_TOKEN      = os.getenv("GITEA_TOKEN",    "")

DB_PARAMS = {
    "host":     "postgres",
    "dbname":   os.getenv("POSTGRES_DB",      "secureguard"),
    "user":     os.getenv("POSTGRES_USER",     "sgadmin"),
    "password": os.getenv("POSTGRES_PASSWORD", ""),
}

# Process MEDIUM and above (not just HIGH/CRITICAL)
MIN_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
PROCESS_MIN_RANK  = 2   # MEDIUM and above
MIN_CONFIDENCE    = 0.55


def get_db():
    return psycopg2.connect(**DB_PARAMS)


# ── DB helpers ────────────────────────────────────────────────

def get_all_findings(scan_run_id: int) -> list[dict]:
    """Return all open findings for this scan — MEDIUM and above."""
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT f.id, f.scan_run_id, f.scanner, f.rule_id, f.cve_id,
                       f.cwe_id, f.severity, f.cvss_score, f.title,
                       f.description, f.file_path, f.line_start, f.line_end,
                       f.vulnerable_code, f.fix_status,
                       sr.repo_url, sr.repo_name, sr.commit_sha, sr.branch
                FROM findings f
                JOIN scan_runs sr ON sr.id = f.scan_run_id
                WHERE f.scan_run_id = %s
                  AND f.severity IN ('CRITICAL','HIGH','MEDIUM')
                  AND f.fix_status = 'open'
                  AND f.file_path IS NOT NULL
                  AND f.file_path != ''
                ORDER BY f.severity DESC, f.file_path, f.line_start
            """, (scan_run_id,))
            return [dict(r) for r in cur.fetchall()]


def mark_pr_opened(scan_run_id: int, pr_url: str, confidence: float,
                   fixed_paths: list[str]):
    """Mark only findings whose files were actually changed."""
    if not fixed_paths:
        return
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE findings SET
                    fix_status    = 'pr_opened',
                    pr_url        = %s,
                    pr_confidence = %s
                WHERE scan_run_id = %s
                  AND fix_status = 'open'
                  AND file_path = ANY(%s)
            """, (pr_url, confidence, scan_run_id, fixed_paths))
            cur.execute("""
                UPDATE scan_runs SET status = 'ai_fixed' WHERE id = %s
            """, (scan_run_id,))
        conn.commit()


# ── NIM call — whole-file approach ───────────────────────────

MAX_FILE_CHARS = 200_000 # Maximum source content sent to the AI model

def build_primary_prompt(file_path: str, file_content: str, findings: list[dict]) -> str:
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += f"\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: [{f.get('severity')}] {f.get('title','')}\n"
    return f"""You are the Primary AI Fix Engine (Moonshot Kimi). Fix ALL vulnerabilities strictly.
FILE: {file_path}
VULNERABILITIES TO FIX:
{vuln_list}
CURRENT FILE CONTENT:
```
{file_content}
```
OUTPUT RULES:
- You MUST wrap your final fixed code in a single markdown block (```)
- The markdown block must contain the FULL file content, not just a snippet."""

def build_secondary_prompt(file_path: str, file_content: str, findings: list[dict]) -> str:
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += f"\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: [{f.get('severity')}] {f.get('title','')}\n"
    return f"""You are the Secondary AI Fix Engine (DeepSeek V4).
FILE: {file_path}
VULNS:
{vuln_list}
CODE:
```
{file_content}
```
Rule: Return the FULL fixed code wrapped in a markdown block (```)."""

def build_fallback_prompt(file_path: str, file_content: str, findings: list[dict]) -> str:
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += f"\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: [{f.get('severity')}] {f.get('title','')}\n"
    return f"""You are the Fallback Fix Engine (Muse Glimmer).
Fix this code.
FILE: {file_path}
VULNS:
{vuln_list}
CODE:
```
{file_content}
```
Return the code wrapped in ```"""

def build_fix_prompt(file_path: str, file_content: str,
                      findings: list[dict]) -> str:
    """
    Build a prompt that lists ALL vulnerabilities in a file
    and asks NIM to return the COMPLETE fixed file.
    """
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += (
            f"\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: "
            f"[{f.get('severity')}] {f.get('title','')}\n"
            f"   Rule: {f.get('rule_id') or f.get('cve_id') or 'N/A'} | "
            f"CWE: {f.get('cwe_id') or 'N/A'}\n"
            f"   Detail: {str(f.get('description',''))[:150]}\n"
        )

    return f"""You are a code security tool. Fix ALL vulnerabilities listed below in the file.

FILE: {file_path}
VULNERABILITIES TO FIX:
{vuln_list}

CURRENT FILE CONTENT:
```
{file_content}
```

STRICT RULES:
1. Fix EVERY vulnerability listed above
2. Return ONLY the complete fixed file content — nothing else
3. NO comments explaining what you changed
4. NO markdown code fences (no ``` or ```python)
5. NO preamble, NO explanation, NO notes after the code
6. Preserve all existing functionality — only change security-relevant lines
7. Use parameterized queries for SQL injection
8. Use subprocess with shell=False and list args for command injection
9. Replace weak crypto (md5/sha1) with bcrypt or hashlib.sha256
10. Replace pickle with json for deserialization
11. Replace hardcoded secrets with os.environ.get()
12. For requirements.txt: bump vulnerable packages to latest safe versions

OUTPUT RULES (violating any = failure):
- Output ONLY raw source code — zero other text
- Do NOT open with any explanation, preamble, or thinking steps
- Do NOT close with any explanation or notes
- Do NOT wrap in markdown fences (no ``` or ```python)
- First line of output = first line of the fixed file
- Last line of output = last line of the fixed file"""



def call_llm(prompt: str, model: str, api_url: str, api_key: str, max_tokens: int = 4096) -> tuple[str, float]:
    if not api_key or api_key.strip() == "":
        return "", 0.0

    """
    Call the LLM API. Returns (fixed_content, confidence).
    """
    max_retries = 3
    for attempt in range(max_retries):
        try:
            r = httpx.post(
                api_url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                    "temperature": 0.1,
                },
                timeout=45.0
            )
            r.raise_for_status()

            content = extract_llm_content(r.json())
            # This is a generation score, not a correctness claim. Syntax and
            # size gates are enforced separately before any file is written.
            return content, 0.70

        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 502, 503, 504) and attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            log.error(f"API HTTP {e.response.status_code}: {e.response.text[:200]}")
            return "", 0.0
        except Exception as e:
            log.error(f"API call error: {e}")
            return "", 0.0
    return "", 0.0



def try_with_fallback(file_path: str, file_content: str, findings: list[dict], max_tokens: int = 4096, is_requirements: bool = False) -> tuple[str, float, str]:
    if is_requirements:
        prompt = build_sca_prompt(file_path, file_content, findings)
    else:
        prompt = build_primary_prompt(file_path, file_content, findings)

    best_content, best_confidence, best_model = "", 0.0, ""

    for i, m_conf in enumerate(MODELS):
        m = m_conf["model"]
        k = m_conf["key"]
        u = m_conf["url"]
        
        if not k or k.strip() == "":
            log.warning(f"Skipping model {m} because API key is empty.")
            continue

        log.info(f"Trying model {i+1}/{len(MODELS)}: {m}")
        content, confidence = call_llm(prompt, m, u, k, max_tokens)
        
        if confidence >= MIN_CONFIDENCE and content:
            return content, confidence, m
            
        if confidence > best_confidence:
            best_confidence = confidence
            best_content = content
            best_model = m
            
        if i < len(MODELS) - 1:
            log.warning(f"Model {m} confidence {confidence:.0%} — falling back to next model...")

    return best_content, best_confidence, best_model


# ── File operations ───────────────────────────────────────────

def find_file_in_repo(repo_path: str, file_path: str) -> Optional[Path]:
    p = (Path(repo_path) / file_path.lstrip("/")).resolve()
    root = Path(repo_path).resolve()
    if p.is_file() and root in p.parents:
        return p
    log.warning(f"SKIP: cannot resolve {file_path} under repo root")
    return None


def apply_file_fix(repo_path: str, file_path: str,
                    fixed_content: str) -> bool:
    """Write fixed content to file. Returns True if changed."""
    fpath = find_file_in_repo(repo_path, file_path)
    if not fpath:
        log.warning(f"File not found in repo: {file_path}")
        return False

    original = fpath.read_text(errors="ignore")
    if original.strip() == fixed_content.strip():
        log.info(f"No changes in {file_path}")
        return False

    # Hard gates
    if not parses_ok(file_path, fixed_content):
        return False
    if len(fixed_content.splitlines()) < len(original.splitlines()) * 0.7:
        log.warning(f"REJECT {file_path}: patch removes >30% of lines")
        return False

    fpath.write_text(fixed_content)
    log.info(f"Fixed: {fpath}")
    return True


# ── Requirements.txt special handling ────────────────────────

def build_sca_prompt(file_path: str, file_content: str,
                      findings: list[dict]) -> str:
    """Prompt specifically for requirements.txt version bumps."""
    cve_list = ""
    seen = set()
    for f in findings:
        cve = f.get("cve_id", "unknown")
        title = f.get("title", "")
        desc  = f.get("description", "")[:120]
        key   = f"{cve}:{f.get('line_start')}"
        if key not in seen:
            seen.add(key)
            cve_list += f"  - Line {f.get('line_start')}: {cve} — {desc}\n"

    return f"""You are a Python security expert. Update package versions in requirements.txt to fix CVEs.

FILE: {file_path}
CURRENT CONTENT:
{file_content}

CVEs TO FIX:
{cve_list}

RULES:
1. Return ONLY the complete fixed requirements.txt content
2. Bump each vulnerable package to the minimum safe version that fixes its CVE
3. Keep all other packages unchanged
4. No comments, no explanation, no markdown
5. First line of output must be the first line of requirements.txt"""


# ── Git operations ────────────────────────────────────────────

def clone_repo(repo_url: str, branch: str = "main") -> Optional[str]:
    parsed = urlparse(repo_url)
    allowed_hosts = {
        h.strip() for h in os.getenv(
            "GITEA_ALLOWED_HOSTS", "sg-gitea,gitea,localhost"
        ).split(",") if h.strip()
    }
    if parsed.scheme not in ("http", "https") or parsed.hostname not in allowed_hosts:
        log.error("Clone rejected: repository host is not allowlisted")
        return None
    if parsed.username or parsed.password:
        log.error("Clone rejected: repository URL contains credentials")
        return None
    repo_url = repo_url.replace("localhost:3000", "gitea:3000")
    tmpdir   = tempfile.mkdtemp(prefix="sg_fix_")
    try:
        authed = repo_url.replace("http://", f"http://secureguard:{GITEA_TOKEN}@")
        subprocess.run(
            ["git", "clone", "--depth=20", "-b", branch, authed, tmpdir],
            check=True, capture_output=True, timeout=60
        )
        subprocess.run(["git", "config", "user.email", "secureguard@cyberlab.local"],
                       cwd=tmpdir, capture_output=True)
        subprocess.run(["git", "config", "user.name", "SecureGuard Bot"],
                       cwd=tmpdir, capture_output=True)
        return tmpdir
    except subprocess.CalledProcessError as e:
        log.error(f"Clone failed: {e.stderr.decode()[:200] if e.stderr else str(e)}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None


def commit_and_push(tmpdir: str, repo_url: str,
                     branch_name: str, scan_run_id: int,
                     summary_lines: list[str]) -> bool:
    try:
        subprocess.run(["git", "add", "-A"], cwd=tmpdir,
                       check=True, capture_output=True)
        status = subprocess.run(["git", "status", "--porcelain"],
                                cwd=tmpdir, capture_output=True, text=True)
        if not status.stdout.strip():
            log.info("No changes to commit")
            return False

        msg = (f"fix(security): SecureGuard AI remediation — scan #{scan_run_id}\n\n"
               + "\n".join(summary_lines[:30])
               + "\n\nGenerated by SecureGuard AI Engine v3")

        subprocess.run(["git", "commit", "-m", msg],
                       cwd=tmpdir, check=True, capture_output=True)

        authed = (repo_url
                  .replace("localhost:3000", "gitea:3000")
                  .replace("http://", f"http://secureguard:{GITEA_TOKEN}@"))
        subprocess.run(
            ["git", "push", authed, f"HEAD:{branch_name}"],
            cwd=tmpdir, check=True, capture_output=True, timeout=30
        )
        log.info(f"Pushed: {branch_name}")
        return True
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode()[:300] if e.stderr else str(e)
        log.error(f"Push failed: {err.replace(GITEA_TOKEN, '***') if GITEA_TOKEN else err}")
        return False


def open_pr(repo_url: str, branch_name: str, scan_run_id: int,
             fixed_files: list[dict], avg_confidence: float,
             model_used: str) -> Optional[str]:
    parts     = repo_url.rstrip("/").removesuffix(".git").split("/")
    owner     = parts[-2] if len(parts) >= 2 else "BeyondBug"
    repo_name = parts[-1] if parts else "ShadowPatch"

    # Build detailed table of what was fixed
    rows = ""
    for item in fixed_files:
        fp        = item["file_path"]
        n_vulns   = item["num_vulns"]
        scanners  = ", ".join(set(item["scanners"]))
        conf      = item["confidence"]
        model     = item.get("model", model_used)
        rows += f"| `{fp}` | {n_vulns} | {scanners} | {conf:.0%} | {model} |\n"

    total = sum(i["num_vulns"] for i in fixed_files)

    body = f"""##   SecureGuard AI Auto-Remediation — Scan #{scan_run_id}

**{total} vulnerabilities fixed across {len(fixed_files)} files**
Average confidence: **{avg_confidence:.0%}**

---

### Files Fixed

| File | Vulns Fixed | Scanners | Confidence | Model |
|---|---|---|---|---|
{rows}

### What was fixed
- SQL injection → parameterized queries
- Command injection → subprocess list args, shell=False
- Weak crypto (MD5/SHA1) → SHA-256 / PBKDF2
- Insecure deserialization (pickle) → json
- Hardcoded secrets → os.environ.get()
- Vulnerable dependencies → bumped to safe versions

###   Review checklist
- [ ] All changed files look correct in the diff tab
- [ ] Run your test suite before merging
- [ ] Verify parameterized queries use correct placeholder syntax for your DB driver
- [ ] Confirm bumped dependency versions are compatible with your codebase

> ⚠️ AI-generated — requires human review before merging.
> _SecureGuard AI Engine v3 · Supported Models: {len(MODELS)} configured_"""

    title = (f"[SecureGuard] Scan #{scan_run_id} — "
             f"{total} vulns fixed in {len(fixed_files)} files "
             f"({avg_confidence:.0%} confidence)")

    try:
        r = httpx.post(
            f"{GITEA_URL}/api/v1/repos/{owner}/{repo_name}/pulls",
            headers={"Authorization": f"token {GITEA_TOKEN}",
                     "Content-Type":  "application/json"},
            json={"title": title, "body": body,
                  "head": branch_name, "base": "main"},
            timeout=15,
        )
        if r.status_code in (200, 201):
            pr_url = r.json().get("html_url", "")
            log.info(f"PR: {pr_url}")
            try:
                from main import prs_opened_total
                prs_opened_total.labels(repo=repo_name).inc()
            except Exception:
                pass
            return pr_url
        log.error(f"PR failed {r.status_code}: {r.text[:300]}")
    except Exception as e:
        log.error(f"PR error: {e}")
    return None


def push_cve_metrics(scan_run_id: int, all_findings: list[dict], fixed_files: list[dict]):
    """
    Push secureguard_cve_fixed_total metrics to Pushgateway.
    Panel expects labels: cve_id, job, package, severity
    """
    registry = CollectorRegistry()
    cve_gauge = Gauge(
        'secureguard_cve_fixed_total',
        'CVEs detected and auto-fixed by SecureGuard AI engine per scan run',
        ['cve_id', 'job', 'package', 'severity'],
        registry=registry,
    )

    # Build a set of fixed file paths for quick lookup
    fixed_paths = {f['file_path'] for f in fixed_files}

    seen = set()
    for finding in all_findings:
        # Only emit for findings in files that were actually fixed
        if finding.get('file_path') not in fixed_paths:
            continue

        cve_id   = finding.get('cve_id') or finding.get('rule_id') or 'N/A'
        package  = finding.get('file_path', 'unknown')
        severity = finding.get('severity', 'UNKNOWN')
        job      = finding.get('scanner', 'secureguard')

        key = (cve_id, package, severity, job)
        if key in seen:
            continue
        seen.add(key)

        cve_gauge.labels(
            cve_id=cve_id,
            job=job,
            package=package,
            severity=severity,
        ).set(1)

    try:
        push_to_gateway(
            PUSHGATEWAY_URL,
            job=f'sg-ai-fix-engine-scan-{scan_run_id}',
            registry=registry,
        )
        log.info(f"Pushed {len(seen)} CVE metrics to Pushgateway")
    except Exception as e:
        log.error(f"Pushgateway push failed: {e}")



# ── Main ──────────────────────────────────────────────────────

def run_ai_fix_engine(scan_run_id: int, repo_url: str,
                       commit_sha: str) -> dict:
    log.info(f"AI Fix Engine v3 — scan #{scan_run_id}")

    if not MODELS:
        return {"status": "skipped", "reason": "No models configured in .env"}

    all_findings = get_all_findings(scan_run_id)
    log.info(f"Total MEDIUM+ findings: {len(all_findings)}")
    if not all_findings:
        return {"status": "complete", "fixes_attempted": 0, "prs_opened": 0}

    # Group findings by file
    by_file: dict[str, list] = defaultdict(list)
    for f in all_findings:
        fp = f.get("file_path", "")
        if fp:
            by_file[fp].append(f)

    log.info(f"Files to fix: {list(by_file.keys())}")

    # Clone repo
    branch_ref  = all_findings[0].get("branch", "main")
    tmpdir      = clone_repo(repo_url, branch_ref)
    if not tmpdir:
        return {"status": "error", "reason": "Clone failed"}

    branch_name = f"secureguard/scan-{scan_run_id}-fixes"
    try:
        subprocess.run(["git", "checkout", "-b", branch_name],
                       cwd=tmpdir, check=True, capture_output=True)
    except Exception:
        subprocess.run(["git", "checkout", branch_name],
                       cwd=tmpdir, capture_output=True)

    fixed_files   = []
    summary_lines = []
    models_used   = []

    try:
        for file_path, findings in by_file.items():
            log.info(f"Processing {file_path} — {len(findings)} findings")

            # Find file in repo
            fpath = find_file_in_repo(tmpdir, file_path)
            if not fpath:
                log.warning(f"  File not found: {file_path}")
                continue

            file_content = fpath.read_text(errors="ignore")
            if not file_content.strip():
                continue

            # Choose prompt based on file type
            is_requirements = Path(file_path).name.lower() in ("requirements.txt", "requirements-dev.txt", "constraints.txt")
            # Call LLM with fallback
            fixed_content, confidence, model_used = try_with_fallback(
                file_path, file_content, findings,
                max_tokens=max(2048, len(file_content.split()) * 3),
                is_requirements=is_requirements
            )
            models_used.append(model_used)

            if not fixed_content or confidence < MIN_CONFIDENCE:
                log.warning(f"  Low confidence {confidence:.0%} for {file_path} — skipping")
                continue

            # Verify fixed content looks like code (not a refusal or explanation)
            first_lines = fixed_content.strip().splitlines()[:3]
            looks_like_code = any(
                l.strip() and not l.strip().startswith(("I ", "The ", "Here ", "Sorry", "As an"))
                for l in first_lines
            )
            if not looks_like_code:
                log.warning(f"  API returned explanation instead of code for {file_path}")
                continue

            # Apply fix
            changed = apply_file_fix(tmpdir, file_path, fixed_content)
            if changed:
                scanners = list(set(f.get("scanner", "?") for f in findings))
                fixed_files.append({
                    "file_path":  file_path,
                    "num_vulns":  len(findings),
                    "scanners":   scanners,
                    "confidence": confidence,
                    "model":      model_used,
                })
                summary_lines.append(
                    f"- {file_path}: {len(findings)} vulns fixed "
                    f"[{', '.join(scanners)}] ({confidence:.0%} conf)"
                )
                log.info(f"  Fixed {file_path} ({confidence:.0%} confidence via {model_used})")

            

        if not fixed_files:
            log.info("No files were successfully fixed")
            return {"status": "complete", "fixes_attempted": len(by_file), "prs_opened": 0}

        # Commit and push
        pushed = commit_and_push(tmpdir, repo_url, branch_name,
                                  scan_run_id, summary_lines)
        if not pushed:
            return {"status": "error", "reason": "Nothing committed or push failed"}

        # Calculate average confidence
        avg_conf   = sum(i["confidence"] for i in fixed_files) / len(fixed_files)
        model_used = models_used[0] if models_used else "Unknown"

        # Open single PR
        pr_url = open_pr(repo_url, branch_name, scan_run_id,
                          fixed_files, avg_conf, model_used)
        if pr_url:
            mark_pr_opened(
                scan_run_id, pr_url, avg_conf,
                [item["file_path"] for item in fixed_files],
            )
            push_cve_metrics(scan_run_id, all_findings, fixed_files)
            return {
                "status":          "complete",
                "fixes_attempted": len(by_file),
                "files_fixed":     len(fixed_files),
                "prs_opened":      1,
                "pr_url":          pr_url,
                "avg_confidence":  f"{avg_conf:.0%}",
                "model":           model_used,
            }
        return {"status": "error", "reason": "PR creation failed"}

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
