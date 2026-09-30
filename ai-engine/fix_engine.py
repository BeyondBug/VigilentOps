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
import random
import math
import re
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse, unquote
from pathlib import Path
from typing import Optional
from collections import defaultdict

from llm_response import extract_llm_content
from fix_validation import parses_ok, preserves_python_interface, validates_security_change
from fix_prompts import build_primary_prompt
from pr_findings import build_finding_comments
from model_pool import load_model_pool, bounded_integer, RouteCooldowns

import httpx
import psycopg2
import psycopg2.extras
log = logging.getLogger("ai-fix-v3")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ── Config ────────────────────────────────────────────────────

MODELS = load_model_pool(os.environ)
MAX_MODEL_ROUTES_PER_FILE = bounded_integer(os.environ, 'AI_MAX_MODEL_ROUTES_PER_FILE', 4, 1, 32)
MODEL_FAILURE_COOLDOWN = bounded_integer(os.environ, 'AI_MODEL_FAILURE_COOLDOWN_SECONDS', 60, 1, 3600)
MODEL_COOLDOWNS = RouteCooldowns()

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


def get_scan_findings(scan_run_id: int) -> list[dict]:
    """Return every stored scanner finding for the PR conversation."""
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, scanner, finding_class, severity, rule_id, cve_id,
                       cwe_id, cvss_score, title, description, file_path,
                       line_start, line_end, fix_status, package,
                       installed_version, fixed_version, image
                FROM findings
                WHERE scan_run_id = %s
                ORDER BY scanner, id
            """, (scan_run_id,))
            return [dict(row) for row in cur.fetchall()]


def get_scan_reports(scan_run_id: int) -> list[dict]:
    with get_db() as connection:
        with connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute('SELECT tool, finding_count, coverage FROM scan_reports WHERE scan_run_id = %s ORDER BY tool', (scan_run_id,))
            return [dict(row) for row in cursor.fetchall()]


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
                  AND finding_class = 'sast'
                  AND severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
                  AND file_path = ANY(%s)
            """, (pr_url, scan_run_id, fixed_paths))
            cur.execute("""
                UPDATE scan_runs SET status = 'pr_opened' WHERE id = %s
            """, (scan_run_id,))
        conn.commit()


# ── Model call — whole-file approach ─────────────────────────

MAX_FILE_CHARS = 25_000
MAX_PROMPT_CHARS = 40_000
GENERATED_LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock", "uv.lock", "Cargo.lock", "Gemfile.lock",
    "composer.lock", ".terraform.lock.hcl",
}


class RateLimitDeferred(Exception):
    """Usable routes are cooling or unavailable; retry the Celery task later."""

    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(f"Model routes temporarily unavailable; retry in {retry_after}s")


def _retry_delay(value: str | None, attempt: int) -> int:
    """Honor Retry-After in seconds or HTTP-date form, with a bounded wait."""
    delay = None
    if value:
        try:
            delay = float(value)
        except ValueError:
            try:
                target = parsedate_to_datetime(value)
                if target.tzinfo is None:
                    target = target.replace(tzinfo=timezone.utc)
                delay = (target - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                pass
    if delay is None or not math.isfinite(delay):
        delay = min(60, 2 ** (attempt + 2)) + random.uniform(0, 1)
    return max(1, min(3600, int(delay + 0.999)))

def call_llm(prompt: str, model: str, api_url: str, api_key: str, max_tokens: int = 4096) -> str:
    """Return model output, or an empty string when the request fails."""
    if not api_key or api_key.strip() == "":
        return ""

    max_attempts = 3
    for attempt in range(max_attempts):
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
            status = e.response.status_code
            if status in (429, 500, 502, 503, 504):
                delay = _retry_delay(e.response.headers.get("Retry-After"), attempt)
                if attempt < max_attempts - 1 and delay <= 60:
                    log.warning("Model API HTTP %s; retrying in %ss", status, delay)
                    time.sleep(delay)
                    continue
                if status == 429:
                    raise RateLimitDeferred(delay) from e
            # Provider error bodies may echo request content or credentials.
            log.error("Model API HTTP %s", status)
            return ""
        except httpx.RequestError as e:
            log.warning("Model transport error: %s", type(e).__name__)
            if attempt < max_attempts - 1:
                time.sleep(_retry_delay(None, attempt))
                continue
            return ""
        except Exception as e:
            log.error("Model response error: %s", type(e).__name__)
            return ""
    return ""



def try_with_fallback(file_path: str, file_content: str, findings: list[dict], max_tokens: int = 4096) -> tuple[str, str]:
    prompt = build_primary_prompt(file_path, file_content, findings)

    if len(prompt) > MAX_PROMPT_CHARS:
        log.warning("SKIP %s: prompt exceeds %s characters", file_path, MAX_PROMPT_CHARS)
        return "", ""

    deferred = []
    validation_feedback = ""
    attempted = 0
    for i, m_conf in enumerate(MODELS):
        m = m_conf["model"]
        k = m_conf["key"]
        u = m_conf["url"]
        
        if not k or k.strip() == "":
            log.warning(f"Skipping model {m} because API key is empty.")
            continue

        remaining = MODEL_COOLDOWNS.remaining(m_conf)
        if remaining:
            deferred.append(remaining)
            log.info('Skipping cooling model %s; retry available in %ss', m, remaining)
            continue
        if attempted >= MAX_MODEL_ROUTES_PER_FILE:
            log.warning('Per-file model route budget exhausted (%s)', MAX_MODEL_ROUTES_PER_FILE)
            break
        attempted += 1

        log.info(f"Trying model {i+1}/{len(MODELS)}: {m}")
        try:
            content = call_llm(prompt + validation_feedback, m, u, k, max_tokens)
        except RateLimitDeferred as exc:
            MODEL_COOLDOWNS.defer(m_conf, exc.retry_after)
            deferred.append(exc.retry_after)
            log.warning("Model %s rate limited; trying next configured model", m)
            continue
        if not content:
            MODEL_COOLDOWNS.defer(m_conf, MODEL_FAILURE_COOLDOWN)
            deferred.append(MODEL_FAILURE_COOLDOWN)
        else:
            MODEL_COOLDOWNS.clear(m_conf)
        if content and content.strip() != file_content.strip() and parses_ok(file_path, content) and len(content.splitlines()) >= len(file_content.splitlines()) * 0.7:
            if file_path.endswith('.py') and not preserves_python_interface(file_content, content):
                validation_feedback = "\nPREVIOUS CANDIDATE REJECTED: preserve existing classes, functions, method names and argument names.\n"
                log.warning("Model %s changed an existing Python interface", m)
                continue
            valid, reason = validates_security_change(file_content, content, findings)
            if valid:
                return content, m
            log.warning("Model %s candidate rejected: %s", m, reason)
            validation_feedback = "\nPREVIOUS CANDIDATE REJECTED: " + reason + "\nAddress the original cause without suppressing checks.\n"
        if content:
            log.warning("Model %s returned unchanged, invalid, or overly shortened code", m)
        if i < len(MODELS) - 1:
            log.warning("Model %s returned no usable content; trying next model", m)

    if deferred:
        raise RateLimitDeferred(min(deferred))
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

def canonical_repo_url(repo_url: str) -> str:
    parsed = urlparse(repo_url)
    allowed_hosts = {
        h.strip() for h in os.getenv(
            "GITEA_ALLOWED_HOSTS", "sg-gitea,gitea,localhost"
        ).split(",") if h.strip()
    }
    try:
        valid_port = parsed.port == 3000
    except ValueError:
        valid_port = False
    parts = parsed.path.strip('/').removesuffix('.git').split('/')
    if (parsed.scheme not in ('http', 'https') or parsed.hostname not in allowed_hosts
            or not valid_port or parsed.username or parsed.password or parsed.query or parsed.fragment
            or len(parts) != 2 or any(part in {'.', '..'} for part in parts)
            or not re.fullmatch(r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git', parsed.path)):
        raise ValueError('Repository URL is outside the configured Gitea clone origin/path')
    # All Git traffic stays within the canonical private Docker Gitea service.
    return 'http://sg-gitea:3000' + parsed.path


def authenticated_git(arguments: list[str], **kwargs):
    """Use ephemeral askpass credentials, never a token in Git argv or remotes."""
    with tempfile.TemporaryDirectory(prefix='sg_git_auth_') as directory:
        helper = Path(directory) / 'askpass.py'
        helper.write_text('#!' + sys.executable + '\n'
                          'import os,sys\n'
                          'prompt = sys.argv[1].lower()\n'
                          'print("secureguard" if "username" in prompt else os.environ["SG_GIT_TOKEN"])\n')
        helper.chmod(0o700)
        environment = {**os.environ, 'GIT_ASKPASS': str(helper), 'GIT_TERMINAL_PROMPT': '0',
                       'SG_GIT_TOKEN': GITEA_TOKEN, 'GIT_CONFIG_GLOBAL': '/dev/null'}
        return subprocess.run(['git', '-c', 'credential.helper=', '-c', 'http.followRedirects=false', *arguments],
                              env=environment, **kwargs)


def clone_repo(repo_url: str, branch: str = "main", commit_sha: str = "") -> Optional[str]:
    try:
        repo_url = canonical_repo_url(repo_url)
    except ValueError as error:
        log.error('Clone rejected: %s', error)
        return None
    tmpdir   = tempfile.mkdtemp(prefix="sg_fix_")
    try:
        authenticated_git(
            ["clone", "--depth=20", "-b", branch, repo_url, tmpdir],
            check=True, capture_output=True, timeout=60
        )
        actual_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=tmpdir,
            check=True, capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        if commit_sha and commit_sha != "HEAD" and actual_commit.lower() != commit_sha.lower():
            log.error("Clone rejected: target branch no longer matches scan commit")
            shutil.rmtree(tmpdir, ignore_errors=True)
            return None
        subprocess.run(["git", "config", "user.email", "secureguard@cyberlab.local"],
                       cwd=tmpdir, capture_output=True)
        subprocess.run(["git", "config", "user.name", "SecureGuard Bot"],
                       cwd=tmpdir, capture_output=True)
        return tmpdir
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        detail = type(e).__name__
        log.error("Clone failed: %s", detail.replace(GITEA_TOKEN, "***") if GITEA_TOKEN else detail)
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

        authenticated_git(
            ["push", canonical_repo_url(repo_url), f"HEAD:{branch_name}"],
            cwd=tmpdir, check=True, capture_output=True, timeout=30
        )
        log.info(f"Pushed: {branch_name}")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, ValueError) as e:
        log.error('Push failed: %s', type(e).__name__)
        return False


def open_pr(repo_url: str, branch_name: str, scan_run_id: int,
             fixed_files: list[dict], model_used: str,
             finding_comments: list[str], base_branch: str = "main") -> tuple[Optional[str], bool]:
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

### Complete tool findings

This PR conversation should contain {len(finding_comments)} numbered finding
comments covering every stored scanner finding from scan #{scan_run_id}.
Check that all parts are present before review. The proposed code change
addresses only selected Python SAST findings; other findings are not addressed
by this proposal.

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
                  "head": branch_name, "base": base_branch},
            timeout=15,
        )
        if r.status_code in (200, 201):
            payload = r.json()
            pr_url = payload.get("html_url", "")
            pr_number = payload.get("number")
            log.info(f"PR: {pr_url}")
            try:
                from main import prs_opened_total
                prs_opened_total.labels(repo=repo_name).inc()
            except Exception:
                pass
            if not pr_number:
                log.error("PR created but Gitea returned no PR number; finding comments not posted")
                return pr_url, False
            comments_complete = True
            for index, comment in enumerate(finding_comments, 1):
                try:
                    response = httpx.post(
                        f"{GITEA_URL}/api/v1/repos/{owner}/{repo_name}/issues/{pr_number}/comments",
                        headers={"Authorization": f"token {GITEA_TOKEN}",
                                 "Content-Type": "application/json"},
                        json={"body": comment},
                        timeout=30,
                    )
                    if response.status_code != 201:
                        log.error("Finding comment %s/%s failed with HTTP %s",
                                  index, len(finding_comments), response.status_code)
                        comments_complete = False
                        break
                except Exception as exc:
                    log.error("Finding comment %s/%s failed: %s",
                              index, len(finding_comments), type(exc).__name__)
                    comments_complete = False
                    break
            return pr_url, comments_complete
        log.error("PR creation failed with HTTP %s", r.status_code)
    except Exception as e:
        log.error("PR creation error: %s", type(e).__name__)
    return None, False


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
    tmpdir      = clone_repo(repo_url, branch_ref, commit_sha)
    if not tmpdir:
        return {"status": "error", "reason": "Clone failed or target branch no longer matches scan commit"}

    branch_name = f"secureguard/scan-{scan_run_id}-fixes"
    try:
        subprocess.run(["git", "checkout", "-b", branch_name],
                       cwd=tmpdir, check=True, capture_output=True)
    except Exception:
        subprocess.run(["git", "checkout", branch_name],
                       cwd=tmpdir, capture_output=True)

    fixed_files   = []
    summary_lines = []
    model_failures = 0

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
                model_failures += 1
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
                    "finding_ids": sorted(
                        {f["id"] for f in findings if f.get("id") is not None}
                    ),
                })
                summary_lines.append(
                    f"- {file_path}: proposed changes for {len(findings)} findings "
                    f"[{', '.join(scanners)}]"
                )
                log.info("  Proposed change for %s via %s", file_path, model_used)

            

        if not fixed_files:
            log.info("No files were successfully fixed")
            return {"status": "no_proposal", "fixes_attempted": len(candidate_files),
                    "prs_opened": 0,
                    "reason": "No model produced an acceptable code change" if model_failures else "No eligible file produced a code change"}

        scan_findings = get_scan_findings(scan_run_id)
        if not scan_findings:
            return {"status": "error", "reason": "Scan findings unavailable for PR conversation"}
        proposed_ids = {
            finding_id
            for item in fixed_files
            for finding_id in item["finding_ids"]
        }
        finding_comments = build_finding_comments(
            scan_run_id, scan_findings, proposed_ids, get_scan_reports(scan_run_id)
        )

        # Commit and push
        pushed = commit_and_push(tmpdir, repo_url, branch_name,
                                  scan_run_id, summary_lines)
        if not pushed:
            return {"status": "error", "reason": "Nothing committed or push failed"}

        model_used = fixed_files[0]["model"]

        # Open single PR
        pr_url, comments_complete = open_pr(
            repo_url, branch_name, scan_run_id,
            fixed_files, model_used, finding_comments,
            base_branch=branch_ref,
        )
        if pr_url:
            if comments_complete:
                mark_pr_opened(
                    scan_run_id, pr_url,
                    [path for item in fixed_files for path in item["source_paths"]],
                )
            return {
                "status":          "complete" if comments_complete else "partial",
                "fixes_attempted": len(candidate_files),
                "files_changed":   len(fixed_files),
                "prs_opened":      1,
                "pr_url":          pr_url,
                "model":           model_used,
                "findings_published": comments_complete,
                "reason": None if comments_complete else "PR finding comments are incomplete",
            }
        return {"status": "error", "reason": "PR creation failed"}

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
