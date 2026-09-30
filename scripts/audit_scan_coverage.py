"""Compare current Gitea repositories and webhooks with orchestrator scans."""

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
from gateway_client import fetch_json


def _request(url: str, token: str = "", env_path=Path(".env")):
    return fetch_json(url, token, env_path, timeout=20)


def _env_value(path: Path, name: str) -> str:
    matches = [
        line.partition("=")[2].strip().strip("\"'")
        for line in path.read_text().splitlines()
        if line.startswith(name + "=")
    ]
    if len(matches) != 1 or not matches[0]:
        raise ValueError(f"Expected one nonempty {name} in {path}")
    return matches[0]


def _repo_key(scan: dict) -> str:
    path = urlparse(str(scan.get("repo_url") or "")).path
    parts = [part for part in path.removesuffix(".git").split("/") if part]
    return "/".join(parts[-2:]) if len(parts) >= 2 else str(scan.get("repo_name") or "")


def _age(created: str | None) -> str:
    if not created:
        return "unknown"
    try:
        when = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        hours = max(0, int((datetime.now(timezone.utc) - when).total_seconds() // 3600))
        return f"{hours}h"
    except ValueError:
        return "unknown"


def audit(gitea_url: str, orchestrator_url: str, token: str, env_path=None, pipeline_commit='') -> str:
    request = _request if env_path is None else lambda url, token="": _request(url, token, env_path)
    repos = []
    page = 1
    while True:
        batch = request(f"{gitea_url}/api/v1/user/repos?limit=100&page={page}", token)
        if not isinstance(batch, list):
            raise ValueError("Gitea repository response was not a list")
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    scans = request(f"{orchestrator_url}/api/scans?limit=500&summary_only=true")
    if not isinstance(scans, list):
        raise ValueError("Orchestrator scans response was not a list")
    latest = {}
    by_branch = {}
    for scan in scans:
        key = _repo_key(scan)
        branch_key = (key, scan.get('branch'))
        if branch_key not in by_branch or int(scan.get('id') or 0) > int(by_branch[branch_key].get('id') or 0):
            by_branch[branch_key] = scan
        if key and (key not in latest or int(scan.get("id") or 0) > int(latest[key].get("id") or 0)):
            latest[key] = scan

    lines = [
        "# Repository scan coverage",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Gitea repositories: {len(repos)}",
        f"Scan records returned: {len(scans)} (API limit 500)",
        "",
        "| Repository | Push webhook | Latest scan | Status | Age | Scanned commit | Branch head | Pipeline commit | Current coverage |",
        "|---|---|---:|---|---:|---|---|---|---|",
    ]
    current = set()
    for repo in sorted(repos, key=lambda item: item.get("full_name") or ""):
        full_name = str(repo.get("full_name") or "")
        current.add(full_name)
        owner, name = full_name.split("/", 1)
        hooks = request(
            f"{gitea_url}/api/v1/repos/{quote(owner)}/{quote(name)}/hooks?limit=100",
            token,
        )
        if not isinstance(hooks, list):
            raise ValueError(f"Webhook response was not a list for {full_name}")
        push_hooks = [
            hook for hook in hooks
            if hook.get("active") and "push" in (hook.get("events") or [])
        ]
        scan = latest.get(full_name, {})
        branch = repo.get('default_branch')
        if branch:
            scan = by_branch.get((full_name, branch), {})
        head = ''
        if branch:
            branch_data = request(f'{gitea_url}/api/v1/repos/{quote(owner)}/{quote(name)}/branches/{quote(branch, safe="")}', token)
            head = branch_data.get('commit', {}).get('id', '')
        scanned = str(scan.get('commit_sha') or '')
        pipeline = str(scan.get('pipeline_commit') or '')
        covered = bool(push_hooks and head and scanned == head and scan.get('branch') == branch
                       and scan.get('status') in {'complete', 'pr_opened'}
                       and (not pipeline_commit or pipeline == pipeline_commit))
        name_cell = full_name.replace("|", "\\|")
        status = str(scan.get("status") or "NO SCAN").replace("|", "\\|")
        lines.append(
            f"| {name_cell} | {'yes' if push_hooks else 'NO'} | "
            f"{scan.get('id') or '—'} | {status} | {_age(scan.get('created_at'))} | "
            f"{scanned[:12] or '—'} | {head[:12] or '—'} | {pipeline[:12] or 'unrecorded'} | {'PASS' if covered else 'PENDING'} |"
        )

    older = sorted(set(latest) - current)
    lines += ["", "## Scan history without a current repository", ""]
    lines += [f"- {name}" for name in older] or ["- None"]
    lines += [
        "",
        "A configured webhook does not prove delivery. Review each Gitea hook's",
        "recent deliveries, trigger one accepted-branch push, and confirm a",
        "completed scan on the exact commit before checking off coverage.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--gitea", default="https://localhost:3000")
    parser.add_argument("--orchestrator", default="https://localhost:3000/dashboard")
    parser.add_argument("--output", type=Path, default=Path("reports/coverage-snapshot.md"))
    parser.add_argument('--pipeline-commit', default='', help='Require this shared pipeline commit for current coverage')
    parser.add_argument('--require-complete', action='store_true', help='Exit nonzero when any current target needs verification')
    args = parser.parse_args()
    token = _env_value(args.env, "GITEA_TOKEN")
    report = audit(args.gitea.rstrip("/"), args.orchestrator.rstrip("/"), token, args.env, args.pipeline_commit)
    os.umask(0o077)
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(f"Coverage report: {args.output}")
    return 1 if args.require_complete and '| PENDING |' in report else 0


if __name__ == "__main__":
    raise SystemExit(main())
