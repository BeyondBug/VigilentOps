"""Validate the report contract for a SecureGuard Jenkins scan.

Run this in a scanner container on the lab server, not on the development
device. Required reports must exist, be nonempty, and have the expected shape.
"""

import argparse
import json
import sys
from pathlib import Path


REQUIRED_SARIF = (
    "semgrep.sarif",
    "gitleaks.sarif",
    "trivy-deps.sarif",
    "grype.sarif",
    "osv.sarif",
    "dep-check.sarif",
    "hadolint.sarif",
    "shellcheck.sarif",
)
OPTIONAL_SARIF = ("checkov.sarif", "snyk.sarif", "trivy-image.sarif", "dockle.sarif")


def _load(path: Path):
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"{path.name}: report is missing or empty")
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name}: invalid JSON: {exc}") from exc


def _sarif(path: Path) -> int:
    data = _load(path)
    if not isinstance(data, dict) or data.get("version") != "2.1.0":
        raise ValueError(f"{path.name}: expected SARIF version 2.1.0")
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError(f"{path.name}: SARIF runs must be a nonempty list")
    if any(not isinstance(run, dict) or not isinstance(run.get("results"), list)
           or any(not isinstance(result, dict) for result in run.get('results', []))
           for run in runs):
        raise ValueError(f"{path.name}: SARIF results must be lists")
    for run in runs:
        invocations = run.get('invocations', [])
        if not isinstance(invocations, list):
            raise ValueError(f'{path.name}: scanner invocations must be a list')
        for invocation in invocations:
            if not isinstance(invocation, dict) or invocation.get("executionSuccessful") is False:
                raise ValueError(f"{path.name}: scanner invocation failed")
        properties = run.get('properties', {})
        if not isinstance(properties, dict):
            raise ValueError(f'{path.name}: run properties must be an object')
        if properties.get('coverage') == 'not_applicable':
            tool = path.stem
            expected_exit = 128 if tool == 'osv' else 0
            if (tool not in {'osv', 'hadolint', 'shellcheck'} or run['results']
                    or not any(item.get('exitCode') == expected_exit and item.get('executionSuccessful') is True
                               for item in invocations)
                    or (tool != 'osv' and properties.get('scanned_file_count') != 0)):
                raise ValueError(f'{path.name}: invalid not-applicable coverage')
    return sum(len(run.get("results", [])) for run in runs)


def normalize_osv_report(reports: Path, exit_code: int) -> None:
    """OSV exit 128 means no supported packages, never a clean vulnerability scan."""
    path = reports / "osv.sarif"
    if exit_code in (0, 1):
        _sarif(path)
        return
    if exit_code != 128:
        raise ValueError(f"OSV scanner failed with exit code {exit_code}")
    if path.exists() and path.stat().st_size and _sarif(path):
        raise ValueError("OSV returned no-packages status with nonempty findings")
    path.write_text(json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "osv-scanner", "version": "2.4.0"}},
            "results": [],
            "invocations": [{"executionSuccessful": True, "exitCode": 128}],
            "properties": {
                "coverage": "not_applicable",
                "reason": "OSV found no supported package sources; this is not a clean scan.",
            },
        }],
    }) + "\n", encoding="utf-8")


def validate_reports(reports: Path, has_python: bool = False,
                     snyk_enabled: bool = False) -> list[str]:
    """Return concise report summaries or raise ValueError."""
    if not reports.is_dir():
        raise ValueError(f"Report directory does not exist: {reports}")
    required_sarif = list(REQUIRED_SARIF)
    image_built = (reports / "image-built.marker").is_file()
    if snyk_enabled:
        required_sarif.append("snyk.sarif")
    if image_built:
        required_sarif.append("trivy-image.sarif")
        required_sarif.append("dockle.sarif")
    summary = []
    for filename in required_sarif:
        count = _sarif(reports / filename)
        if filename in {'osv.sarif', 'hadolint.sarif', 'shellcheck.sarif'} and any(
            run.get("properties", {}).get("coverage") == "not_applicable"
            for run in _load(reports / filename)["runs"]
        ):
            reason = 'no supported package sources' if filename == 'osv.sarif' else 'no applicable source files'
            summary.append(f"{filename}: NOT APPLICABLE ({reason})")
        else:
            summary.append(f"{filename}: {count} results")

    if has_python:
        bandit = _load(reports / "bandit.json")
        if (not isinstance(bandit, dict) or not isinstance(bandit.get("results"), list)
                or any(not isinstance(item, dict) for item in bandit['results'])):
            raise ValueError("bandit.json: expected a results list")
        if bandit.get('errors'):
            raise ValueError('bandit.json: selected files could not be analyzed')
        summary.append(f"bandit.json: {len(bandit['results'])} results")

    sbom = _load(reports / "syft-sbom.json")
    if (not isinstance(sbom, dict) or not str(sbom.get("spdxVersion", "")).startswith("SPDX-")
            or not isinstance(sbom.get('packages'), list)):
        raise ValueError("syft-sbom.json: expected an SPDX document")
    summary.append("syft-sbom.json: valid SPDX")

    for filename in OPTIONAL_SARIF:
        if (filename == "snyk.sarif" and snyk_enabled) or (
            filename in ("trivy-image.sarif", "dockle.sarif") and image_built
        ):
            continue
        path = reports / filename
        if path.is_file() and path.stat().st_size:
            summary.append(f"{filename}: {_sarif(path)} results")
        else:
            summary.append(f"{filename}: optional report absent")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path)
    parser.add_argument("--python", action="store_true")
    parser.add_argument("--snyk", action="store_true")
    parser.add_argument("--normalize-osv-exit-code", type=int)
    args = parser.parse_args()
    try:
        if args.normalize_osv_exit_code is not None:
            normalize_osv_report(args.reports, args.normalize_osv_exit_code)
            print(f"OSV report contract recorded (exit {args.normalize_osv_exit_code})")
            return 0
        for line in validate_reports(args.reports, args.python, args.snyk):
            print(line)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
