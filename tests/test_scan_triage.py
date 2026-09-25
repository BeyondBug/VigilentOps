"""Triage export checks to run on the lab server."""

import csv
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from export_scan_triage import export, review_key


class ScanTriageTests(unittest.TestCase):
    def test_export_preserves_records_and_escapes_spreadsheet_formulas(self):
        scan = {
            "id": 7, "repo_name": "example", "commit_sha": "abc", "status": "complete",
            "findings": [
                {"id": 1, "scanner": "grype", "severity": "HIGH",
                 "cve_id": "CVE-2026-1234", "file_path": "package-lock.json",
                 "description": "=HYPERLINK(\"bad\")"},
                {"id": 2, "scanner": "trivy-deps", "severity": "HIGH",
                 "cve_id": "CVE-2026-1234", "file_path": "package-lock.json"},
            ],
        }
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "scan-7"
            export(scan, output)
            with (output / "findings.csv").open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            with (output / "review-groups.csv").open(newline="") as handle:
                groups = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]["record_count"], "2")
            self.assertTrue(rows[0]["description"].startswith("'="))

    def test_review_key_is_only_a_candidate_group(self):
        self.assertEqual(
            review_key({"cve_id": "CVE-2026-1234", "file_path": "image"}),
            ("CVE-2026-1234", "image"),
        )


if __name__ == "__main__":
    unittest.main()
