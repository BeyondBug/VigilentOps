"""Export a scan's stored findings for private, manual triage on the lab server."""

import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from gateway_client import fetch_json


FINDING_FIELDS = (
    "id", "scanner", "finding_class", "severity", "cvss_score",
    "rule_id", "cve_id", "title", "description", "file_path",
    "line_start", "fix_status", "pr_url",
    "package", "installed_version", "fixed_version", "image",
)
GROUP_FIELDS = (
    "group", "advisory_or_rule", "file_path", "record_count", "scanners",
    "severities", "finding_ids", "package", "installed_version",
    "fixed_version", "image", "disposition", "owner", "review_date", "notes",
    "impact", "mitigation", "evidence", "tested_commit", "verification_scan_id", "duplicate_of", "planned_fix",
)


def csv_safe(value):
    """Prevent spreadsheet formula execution when a private CSV is opened."""
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def review_key(finding: dict) -> tuple[str, ...]:
    """Suggest review groups; this does not prove records are duplicates."""
    identifier = finding.get("cve_id") or finding.get("rule_id") or finding.get("title") or "unknown"
    base = str(identifier), str(finding.get("file_path") or "")
    artifact = tuple(str(finding.get(name) or '') for name in ('package', 'installed_version', 'image'))
    return base + artifact if any(artifact) else base


def export(scan: dict, directory: Path) -> None:
    findings = scan.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Scan API did not return a findings list")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any((directory / name).exists() for name in ("findings.csv", "review-groups.csv", "summary.md")):
        raise FileExistsError("Output files already exist; choose an unused directory")

    with (directory / "findings.csv").open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FINDING_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            writer.writerow({key: csv_safe(finding.get(key)) for key in FINDING_FIELDS})

    groups: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for finding in findings:
        groups[review_key(finding)].append(finding)
    with (directory / "review-groups.csv").open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GROUP_FIELDS)
        writer.writeheader()
        for number, (key, items) in enumerate(sorted(groups.items()), 1):
            row = {
                "group": number,
                "advisory_or_rule": key[0],
                "file_path": key[1],
                "record_count": len(items),
                "scanners": ", ".join(sorted({str(item.get("scanner") or "") for item in items})),
                "severities": ", ".join(sorted({str(item.get("severity") or "") for item in items})),
                "finding_ids": ", ".join(str(item.get("id")) for item in items),
                "package": items[0].get("package"),
                "installed_version": items[0].get("installed_version"),
                "fixed_version": ", ".join(sorted({str(item["fixed_version"]) for item in items if item.get("fixed_version")})),
                "image": items[0].get("image"),
                "disposition": "open",
            }
            writer.writerow({name: csv_safe(row.get(name)) for name in GROUP_FIELDS})

    severities = Counter(str(item.get("severity") or "UNKNOWN") for item in findings)
    scanners = Counter(str(item.get("scanner") or "unknown") for item in findings)
    summary = [
        f"# Scan {scan.get('id')} triage export",
        "",
        f"Repository: {scan.get('repo_name') or 'unknown'}",
        f"Commit: {scan.get('commit_sha') or 'unknown'}",
        f"Status: {scan.get('status') or 'unknown'}",
        f"Finding records: {len(findings)}",
        f"Suggested review groups: {len(groups)}",
        "",
        "These groups are a review aid, not a count of unique vulnerabilities.",
        "Package/version/image columns retain available scanner metadata.",
        "Historical rows and formats without that data remain blank; confirm them during review.",
        "Keep the CSV files private because scanner descriptions may contain secrets.",
        "",
        "## Severity records",
    ]
    summary += [f"- {name}: {count}" for name, count in sorted(severities.items())]
    summary += ["", "## Scanner records"]
    summary += [f"- {name}: {count}" for name, count in sorted(scanners.items())]
    (directory / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print(f"Exported {len(findings)} records to {directory}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_id", type=int)
    parser.add_argument("--api", default="https://localhost:3000/dashboard")
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output or Path("reports") / "triage" / f"scan-{args.scan_id}"
    scan = fetch_json(f"{args.api.rstrip('/')}/api/scans/{args.scan_id}", env_path=args.env)
    if scan.get("id") != args.scan_id:
        raise ValueError("Scan API returned a different scan ID")
    export(scan, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
