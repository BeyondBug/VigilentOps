"""
SecureGuard AI Fix Engine v3
─────────────────────────────
Proposes reviewable changes for Python SAST findings.
"""

import time
import os
import tempfile
import shutil
import subprocess
import logging
from urllib.parse import urlparse, unquote
from pathlib import Path
from typing import Optional
from collections import defaultdict

from llm_response import extract_llm_content
from fix_validation import parses_ok
from fix_prompts import build_primary_prompt

import httpx
import psycopg2
import psycopg2.extras
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

def get_db():
    return psycopg2.connect(**DB_PARAMS)


# ── DB helpers ────────────────────────────────────────────────

def get_all_findings(scan_run_id: int) -> list[dict]:
    """Return Python SAST findings eligible for a reviewable proposal."""
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
                  AND f.finding_class = 'sast'
                  AND f.file_path IS NOT NULL
                  AND right(lower(f.file_path), 3) = '.py'
                ORDER BY f.severity DESC, f.file_path, f.line_start
            """, (scan_run_id,))
            return [dict(r) for r in cur.fetchall()]


def mark_pr_opened(scan_run_id: int, pr_url: str,
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
                    pr_confidence = NULL
                WHERE scan_run_id = %s
                  AND fix_status = 'open'
                  AND file_path = ANY(%s)
            """, (pr_url, scan_run_id, fixed_paths))
            cur.execute("""
                UPDATE scan_runs SET status = 'pr_opened' WHERE id = %s
            """, (scan_run_id,))
        conn.commit()


# ── NIM call — whole-file approach ───────────────────────────

MAX_FILE_CHARS = 25_000
MAX_PROMPT_CHARS = 40_000
GENERATED_LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock", "uv.lock", "Cargo.lock", "Gemfile.lock",
    "composer.lock", ".terraform.lock.hcl",
}

def call_llm(prompt: str, model: str, api_url: str, api_key: str, max_tokens: int = 4096) -> str:
    """Return model output, or an empty string when the request fails."""
    if not api_key or api_key.strip() == "":
        return ""

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

            return extract_llm_content(r.json())

        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 502, 503, 504) and attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            log.error(f"API HTTP {e.response.status_code}: {e.response.text[:200]}")
            return ""
        except Exception as e:
            log.error(f"API call error: {e}")
            return ""
    return ""



def try_with_fallback(file_path: str, file_content: str, findings: list[dict], max_tokens: int = 4096) -> tuple[str, str]:
    prompt = build_primary_prompt(file_path, file_content, findings)

    if len(prompt) > MAX_PROMPT_CHARS:
        log.warning("SKIP %s: prompt exceeds %s characters", file_path, MAX_PROMPT_CHARS)
        return "", ""

    for i, m_conf in enumerate(MODELS):
        m = m_conf["model"]
        k = m_conf["key"]
        u = m_conf["url"]
        
        if not k or k.strip() == "":
            log.warning(f"Skipping model {m} because API key is empty.")
            continue

        log.info(f"Trying model {i+1}/{len(MODELS)}: {m}")
        content = call_llm(prompt, m, u, k, max_tokens)
        if content:
            return content, m
        if i < len(MODELS) - 1:
            log.warning("Model %s returned no usable content; trying next model", m)

    return "", ""


# ── File operations ───────────────────────────────────────────

def find_file_in_repo(repo_path: str, file_path: str) -> Optional[Path]:
    if file_path.startswith("file://"):
        parsed = urlparse(file_path)
        if parsed.netloc not in ("", "localhost"):
            return None
        file_path = unquote(parsed.path)
    if file_path.startswith("/src/"):
        file_path = file_path[len("/src/"):]
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
             fixed_files: list[dict], model_used: str) -> Optional[str]:
    parts     = repo_url.rstrip("/").removesuffix(".git").split("/")
    owner     = parts[-2] if len(parts) >= 2 else "BeyondBug"
    repo_name = parts[-1] if parts else "ShadowPatch"

    # Describe the proposed changes without claiming findings are resolved.
    rows = ""
    for item in fixed_files:
        fp        = item["file_path"]
        n_vulns   = item["num_vulns"]
        scanners  = ", ".join(set(item["scanners"]))
        model     = item.get("model", model_used)
        rows += f"| `{fp}` | {n_vulns} | {scanners} | {model} |\n"

    total = sum(i["num_vulns"] for i in fixed_files)

    body = f"""## SecureGuard remediation proposal — Scan #{scan_run_id}

AI-generated changes in {len(fixed_files)} files associated with {total} scanner findings. Syntax checks passed; security and behavior are unverified.

### Changed files

| File | Associated findings | Scanners | Model |
|---|---:|---|---|
{rows}

### Before marking ready to merge
- [ ] Review every changed line and the original scanner findings.
- [ ] Run the affected tests and rescan the branch.
- [ ] Confirm the change preserves behavior and removes the reported issue.
"""

    title = f"WIP: [SecureGuard] Review scan #{scan_run_id} changes in {len(fixed_files)} files"

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


# ── Main ──────────────────────────────────────────────────────

def run_ai_fix_engine(scan_run_id: int, repo_url: str,
                       commit_sha: str) -> dict:
    log.info(f"AI Fix Engine v3 — scan #{scan_run_id}")

    if not MODELS:
        return {"status": "skipped", "reason": "No models configured in .env"}

    all_findings = get_all_findings(scan_run_id)
    log.info("Eligible Python SAST findings: %s", len(all_findings))
    if not all_findings:
        return {"status": "complete", "fixes_attempted": 0, "prs_opened": 0}

    # Group findings by file
    by_file: dict[str, list] = defaultdict(list)
    for f in all_findings:
        fp = f.get("file_path", "")
        if fp:
            by_file[fp].append(f)

    log.info("Scanner paths to review: %s", list(by_file))

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

    try:
        candidate_files: dict[str, dict] = {}
        for file_path, findings in by_file.items():
            if Path(file_path).name in GENERATED_LOCKFILES:
                log.info("Skipping generated lockfile %s", file_path)
                continue
            fpath = find_file_in_repo(tmpdir, file_path)
            if not fpath:
                continue
            canonical_path = fpath.relative_to(Path(tmpdir).resolve()).as_posix()
            group = candidate_files.setdefault(
                canonical_path, {"findings": [], "source_paths": set()}
            )
            group["findings"].extend(findings)
            group["source_paths"].add(file_path)

        for file_path, group in candidate_files.items():
            findings = group["findings"]
            log.info("Processing %s — %s findings", file_path, len(findings))
            fpath = Path(tmpdir) / file_path

            file_content = fpath.read_text(errors="ignore")
            if not file_content.strip():
                continue
            if len(file_content) > MAX_FILE_CHARS:
                log.info("Skipping %s: %s characters exceeds model limit", file_path, len(file_content))
                continue

            # Call LLM with fallback
            fixed_content, model_used = try_with_fallback(
                file_path, file_content, findings,
                max_tokens=min(8192, max(2048, len(file_content.split()) * 3)),
            )

            if not fixed_content:
                log.warning("No usable model output for %s", file_path)
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
                    "model":      model_used,
                    "source_paths": sorted(group["source_paths"]),
                })
                summary_lines.append(
                    f"- {file_path}: proposed changes for {len(findings)} findings "
                    f"[{', '.join(scanners)}]"
                )
                log.info("  Proposed change for %s via %s", file_path, model_used)

            

        if not fixed_files:
            log.info("No files were successfully fixed")
            return {"status": "complete", "fixes_attempted": len(candidate_files), "prs_opened": 0}

        # Commit and push
        pushed = commit_and_push(tmpdir, repo_url, branch_name,
                                  scan_run_id, summary_lines)
        if not pushed:
            return {"status": "error", "reason": "Nothing committed or push failed"}

        model_used = fixed_files[0]["model"]

        # Open single PR
        pr_url = open_pr(repo_url, branch_name, scan_run_id,
                          fixed_files, model_used)
        if pr_url:
            mark_pr_opened(
                scan_run_id, pr_url,
                [path for item in fixed_files for path in item["source_paths"]],
            )
            return {
                "status":          "complete",
                "fixes_attempted": len(candidate_files),
                "files_changed":   len(fixed_files),
                "prs_opened":      1,
                "pr_url":          pr_url,
                "model":           model_used,
            }
        return {"status": "error", "reason": "PR creation failed"}

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
