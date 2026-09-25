import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "ai-engine"))

from report_parsers import parse_bandit, parse_sarif
from fix_validation import parses_ok


class ReportParserTests(unittest.TestCase):
    def test_sarif_preserves_cve_and_location(self):
        report = {"runs": [{
            "tool": {"driver": {"rules": [{"id": "CVE-2026-12345", "name": "Unsafe package"}]}},
            "results": [{
                "ruleId": "CVE-2026-12345",
                "level": "error",
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "requirements.txt"},
                    "region": {"startLine": 3},
                }}],
            }],
        }]}
        finding = parse_sarif(report, "osv")[0]
        self.assertEqual(finding["cve_id"], "CVE-2026-12345")
        self.assertEqual(finding["finding_class"], "sca")
        self.assertEqual(finding["file_path"], "requirements.txt")
        self.assertEqual(finding["line_start"], 3)

    def test_bandit_normalizes_source_path(self):
        report = {"results": [{
            "test_id": "B101", "test_name": "assert_used", "issue_severity": "HIGH",
            "filename": "/src/app.py", "line_number": 5,
        }]}
        finding = parse_bandit(report)[0]
        self.assertEqual(finding["file_path"], "app.py")
        self.assertEqual(finding["finding_class"], "sast")


class FixValidationTests(unittest.TestCase):
    def test_invalid_python_is_rejected(self):
        self.assertFalse(parses_ok("app.py", "def broken(:\n"))

    def test_invalid_json_is_rejected(self):
        self.assertFalse(parses_ok("config.json", "{broken}"))


if __name__ == "__main__":
    unittest.main()
