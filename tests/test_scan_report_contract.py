"""Report contract checks to run on the lab server."""

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_scan_reports import REQUIRED_SARIF, validate_reports


class ReportContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.reports = Path(self.temp.name)
        sarif = {"version": "2.1.0", "runs": [{"results": []}]}
        for filename in REQUIRED_SARIF:
            (self.reports / filename).write_text(json.dumps(sarif))
        (self.reports / "syft-sbom.json").write_text(
            json.dumps({"spdxVersion": "SPDX-2.3", "packages": []})
        )

    def test_valid_empty_result_reports_are_accepted(self):
        summary = validate_reports(self.reports)
        self.assertIn("semgrep.sarif: 0 results", summary)

    def test_missing_required_scanner_report_fails(self):
        (self.reports / "trivy-deps.sarif").unlink()
        with self.assertRaisesRegex(ValueError, "trivy-deps.sarif"):
            validate_reports(self.reports)

    def test_invalid_sarif_fails(self):
        (self.reports / "grype.sarif").write_text('{"runs": []}')
        with self.assertRaisesRegex(ValueError, "SARIF version"):
            validate_reports(self.reports)

    def test_python_and_configured_snyk_become_required(self):
        with self.assertRaisesRegex(ValueError, "snyk.sarif"):
            validate_reports(self.reports, snyk_enabled=True)
        with self.assertRaisesRegex(ValueError, "bandit.json"):
            validate_reports(self.reports, has_python=True)

    def test_built_image_requires_both_image_reports(self):
        (self.reports / "image-built.marker").touch()
        with self.assertRaisesRegex(ValueError, "trivy-image.sarif"):
            validate_reports(self.reports)
        (self.reports / "trivy-image.sarif").write_text(
            json.dumps({"version": "2.1.0", "runs": [{"results": []}]})
        )
        with self.assertRaisesRegex(ValueError, "dockle.sarif"):
            validate_reports(self.reports)


if __name__ == "__main__":
    unittest.main()
