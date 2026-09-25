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
)
OPTIONAL_SARIF = ("checkov.sarif", "snyk.sarif", "trivy-image.sarif")
OPTIONAL_JSON = ("dockle.json",)


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
    if not isinstance(runs, list):
        raise ValueError(f"{path.name}: SARIF runs must be a list")
    if any(not isinstance(run, dict) or not isinstance(run.get("results", []), list)
           for run in runs):
        raise ValueError(f"{path.name}: SARIF results must be lists")
    return sum(len(run.get("results", [])) for run in runs)


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
    summary = []
    for filename in required_sarif:
        count = _sarif(reports / filename)
        summary.append(f"{filename}: {count} results")

    if has_python:
        bandit = _load(reports / "bandit.json")
        if not isinstance(bandit, dict) or not isinstance(bandit.get("results"), list):
            raise ValueError("bandit.json: expected a results list")
        summary.append(f"bandit.json: {len(bandit['results'])} results")

    sbom = _load(reports / "syft-sbom.json")
    if not isinstance(sbom, dict) or not str(sbom.get("spdxVersion", "")).startswith("SPDX-"):
        raise ValueError("syft-sbom.json: expected an SPDX document")
    summary.append("syft-sbom.json: valid SPDX")

    for filename in OPTIONAL_SARIF:
        if (filename == "snyk.sarif" and snyk_enabled) or (
            filename == "trivy-image.sarif" and image_built
        ):
            continue
        path = reports / filename
        if path.is_file() and path.stat().st_size:
            summary.append(f"{filename}: {_sarif(path)} results")
        else:
            summary.append(f"{filename}: optional report absent")
    if image_built:
        _load(reports / "dockle.json")
        summary.append("dockle.json: valid JSON")
    for filename in OPTIONAL_JSON:
        if filename == "dockle.json" and image_built:
            continue
        path = reports / filename
        if path.is_file() and path.stat().st_size:
            _load(path)
            summary.append(f"{filename}: valid JSON")
        else:
            summary.append(f"{filename}: optional report absent")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path)
    parser.add_argument("--python", action="store_true")
    parser.add_argument("--snyk", action="store_true")
    args = parser.parse_args()
    try:
        for line in validate_reports(args.reports, args.python, args.snyk):
            print(line)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
