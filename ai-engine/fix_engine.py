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
from pathlib import Path
from typing import Optional
from collections import defaultdict

import httpx
import psycopg2
import psycopg2.extras

log = logging.getLogger("ai-fix-v3")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ── Config ────────────────────────────────────────────────────
NVIDIA_API_URL   = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_API_KEY   = os.getenv("NVIDIA_API_KEY", "")
PRIMARY_MODEL    = os.getenv("NVIDIA_MODEL",   "meta/llama-3.1-70b-instruct")
FALLBACK_MODEL   = "nvidia/kimi-k2"
GITEA_URL        = os.getenv("GITEA_URL",      "http://gitea:3000")
GITEA_TOKEN      = os.getenv("GITEA_TOKEN",    "")

DB_PARAMS = {
    "host":     "postgres",
    "dbname":   os.getenv("POSTGRES_DB",      "secureguard"),
    "user":     os.getenv("POSTGRES_USER",     "sgadmin"),
    "password": os.getenv("POSTGRES_PASSWORD", "sgpassword123"),
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


def mark_all_pr_opened(scan_run_id: int, pr_url: str, confidence: float):
    """Mark entire scan as AI-fixed with the PR URL."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE findings SET
                    fix_status    = 'pr_opened',
                    pr_url        = %s,
                    pr_confidence = %s
                WHERE scan_run_id = %s
                  AND fix_status = 'open'
            """, (pr_url, confidence, scan_run_id))
            cur.execute("""
                UPDATE scan_runs SET status = 'ai_fixed' WHERE id = %s
            """, (scan_run_id,))
        conn.commit()


# ── NIM call — whole-file approach ───────────────────────────

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

OUTPUT: The complete fixed file content only. First character must be the first character of the file."""


def call_nim(prompt: str, model: str, max_tokens: int = 4096) -> tuple[str, float]:
    """
    Call NVIDIA NIM. Returns (fixed_content, confidence).
    Confidence is estimated from response quality.
    """
    try:
        r = httpx.post(
            NVIDIA_API_URL,
            headers={
                "Authorization": f"Bearer {NVIDIA_API_KEY}",
                "Content-Type":  "application/json",
            },
            json={
                "model":       model,
                "messages":    [{"role": "user", "content": prompt}],
                "max_tokens":  max_tokens,
                "temperature": 0.05,
                "top_p":       0.9,
            },
            timeout=120,
        )
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"].strip()

        # Strip accidental markdown fences
        content = re.sub(r"^```[\w]*\n?", "", content)
        content = re.sub(r"\n?```\s*$", "", content)
        content = content.strip()

        # Estimate confidence:
        # Low confidence if model added lots of comments or explanatory text
        lines        = content.splitlines()
        comment_lines = sum(1 for l in lines if l.strip().startswith("#") and "TODO" not in l)
        code_lines    = sum(1 for l in lines if l.strip() and not l.strip().startswith("#"))
        comment_ratio = comment_lines / max(len(lines), 1)

        # Penalise if the output looks like explanation not code
        has_prose = any(l.strip().startswith(("The ", "This ", "I ", "Here", "Note"))
                       for l in lines[:5])

        confidence = 0.85
        if comment_ratio > 0.3:
            confidence -= 0.2
        if has_prose:
            confidence -= 0.3

        return content, max(0.0, confidence)

    except httpx.HTTPStatusError as e:
        log.error(f"NIM HTTP {e.response.status_code}: {e.response.text[:200]}")
        return "", 0.0
    except Exception as e:
        log.error(f"NIM call error: {e}")
        return "", 0.0


def try_with_fallback(prompt: str, max_tokens: int = 4096) -> tuple[str, float, str]:
    """
    Try primary model first. If quality is poor, use fallback.
    Returns (content, confidence, model_used)
    """
    content, confidence = call_nim(prompt, PRIMARY_MODEL, max_tokens)

    if confidence >= MIN_CONFIDENCE and content:
        return content, confidence, PRIMARY_MODEL

    log.warning(f"Primary model confidence {confidence:.0%} — trying fallback {FALLBACK_MODEL}")
    content2, confidence2 = call_nim(prompt, FALLBACK_MODEL, max_tokens)

    if confidence2 > confidence and content2:
        return content2, confidence2, FALLBACK_MODEL

    # Return whichever was better
    if content and confidence >= 0.3:
        return content, confidence, PRIMARY_MODEL
    return content2, confidence2, FALLBACK_MODEL


# ── File operations ───────────────────────────────────────────

def find_file_in_repo(repo_path: str, file_path: str) -> Optional[Path]:
    """Find a file in the repo, trying multiple path variations."""
    candidates = [
        Path(repo_path) / file_path.lstrip("/"),
        Path(repo_path) / Path(file_path).name,
    ]
    # Also search recursively by filename
    fname = Path(file_path).name
    for match in Path(repo_path).rglob(fname):
        candidates.append(match)

    for c in candidates:
        if c.exists() and c.is_file():
            return c
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
            ["git", "push", authed, f"HEAD:{branch_name}", "--force"],
            cwd=tmpdir, check=True, capture_output=True, timeout=30
        )
        log.info(f"Pushed: {branch_name}")
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"Push failed: {e.stderr.decode()[:300] if e.stderr else str(e)}")
        return False


def open_pr(repo_url: str, branch_name: str, scan_run_id: int,
             fixed_files: list[dict], avg_confidence: float,
             model_used: str) -> Optional[str]:
    parts     = repo_url.rstrip("/").rstrip(".git").split("/")
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
> _SecureGuard AI Engine v3 · Primary: {PRIMARY_MODEL} · Fallback: {FALLBACK_MODEL}_"""

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
            return pr_url
        log.error(f"PR failed {r.status_code}: {r.text[:300]}")
    except Exception as e:
        log.error(f"PR error: {e}")
    return None


# ── Main ──────────────────────────────────────────────────────

def run_ai_fix_engine(scan_run_id: int, repo_url: str,
                       commit_sha: str) -> dict:
    log.info(f"AI Fix Engine v3 — scan #{scan_run_id}")

    if not NVIDIA_API_KEY:
        return {"status": "skipped", "reason": "NVIDIA_API_KEY not set"}

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
            is_requirements = "requirements" in file_path.lower() or file_path.endswith(".txt")
            if is_requirements:
                prompt = build_sca_prompt(file_path, file_content, findings)
            else:
                prompt = build_fix_prompt(file_path, file_content, findings)

            # Call NIM with fallback
            fixed_content, confidence, model_used = try_with_fallback(
                prompt,
                max_tokens=max(2048, len(file_content.split()) * 3)
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
                log.warning(f"  NIM returned explanation instead of code for {file_path}")
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
        model_used = FALLBACK_MODEL if FALLBACK_MODEL in models_used else PRIMARY_MODEL

        # Open single PR
        pr_url = open_pr(repo_url, branch_name, scan_run_id,
                          fixed_files, avg_conf, model_used)
        if pr_url:
            mark_all_pr_opened(scan_run_id, pr_url, avg_conf)
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
