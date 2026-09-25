"""Coverage report checks to run on the lab server."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import audit_scan_coverage


class ScanCoverageTests(unittest.TestCase):
    def test_reports_missing_scans_and_old_repository_history(self):
        def respond(url, token=""):
            if "/user/repos" in url:
                return [
                    {"full_name": "BeyondBug/one"},
                    {"full_name": "BeyondBug/two"},
                ]
            if "/repos/BeyondBug/one/hooks" in url:
                return [{"active": True, "events": ["push"]}]
            if "/repos/BeyondBug/two/hooks" in url:
                return []
            if "/api/scans" in url:
                return [
                    {"id": 2, "repo_url": "http://gitea/BeyondBug/one.git",
                     "status": "complete"},
                    {"id": 1, "repo_url": "http://gitea/BeyondBug/old.git",
                     "status": "failed"},
                ]
            raise AssertionError(url)

        with patch.object(audit_scan_coverage, "_request", side_effect=respond):
            report = audit_scan_coverage.audit("http://gitea", "http://api", "token")
        self.assertIn("| BeyondBug/one | yes | 2 | complete |", report)
        self.assertIn("| BeyondBug/two | NO | — | NO SCAN |", report)
        self.assertIn("- BeyondBug/old", report)


if __name__ == "__main__":
    unittest.main()
