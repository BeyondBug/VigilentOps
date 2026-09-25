"""Compare current Gitea repositories and webhooks with orchestrator scans."""

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


def _request(url: str, token: str = ""):
    headers = {"Authorization": f"token {token}"} if token else {}
    with urlopen(Request(url, headers=headers), timeout=20) as response:
        return json.load(response)


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


def audit(gitea_url: str, orchestrator_url: str, token: str) -> str:
    repos = []
    page = 1
    while True:
        batch = _request(f"{gitea_url}/api/v1/user/repos?limit=100&page={page}", token)
        if not isinstance(batch, list):
            raise ValueError("Gitea repository response was not a list")
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    scans = _request(f"{orchestrator_url}/api/scans?limit=500&summary_only=true")
    if not isinstance(scans, list):
        raise ValueError("Orchestrator scans response was not a list")
    latest = {}
    for scan in scans:
        key = _repo_key(scan)
        if key and (key not in latest or int(scan.get("id") or 0) > int(latest[key].get("id") or 0)):
            latest[key] = scan

    lines = [
        "# Repository scan coverage",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Gitea repositories: {len(repos)}",
        f"Scan records returned: {len(scans)} (API limit 500)",
        "",
        "| Repository | Push webhook | Latest scan | Status | Age |",
        "|---|---|---:|---|---:|",
    ]
    current = set()
    for repo in sorted(repos, key=lambda item: item.get("full_name") or ""):
        full_name = str(repo.get("full_name") or "")
        current.add(full_name)
        owner, name = full_name.split("/", 1)
        hooks = _request(
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
        name_cell = full_name.replace("|", "\\|")
        status = str(scan.get("status") or "NO SCAN").replace("|", "\\|")
        lines.append(
            f"| {name_cell} | {'yes' if push_hooks else 'NO'} | "
            f"{scan.get('id') or '—'} | {status} | {_age(scan.get('created_at'))} |"
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
    parser.add_argument("--gitea", default="http://127.0.0.1:3000")
    parser.add_argument("--orchestrator", default="http://127.0.0.1:8000")
    parser.add_argument("--output", type=Path, default=Path("reports/coverage-snapshot.md"))
    args = parser.parse_args()
    token = _env_value(args.env, "GITEA_TOKEN")
    report = audit(args.gitea.rstrip("/"), args.orchestrator.rstrip("/"), token)
    os.umask(0o077)
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(f"Coverage report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
