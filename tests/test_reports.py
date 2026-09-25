import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "ai-engine"))

from report_parsers import parse_bandit, parse_sarif, validate_report_shape
from fix_validation import parses_ok


class ReportParserTests(unittest.TestCase):
    def test_report_shape_rejects_unparsed_json(self):
        with self.assertRaises(ValueError):
            validate_report_shape({"message": "scanner failed"}, "osv")
        with self.assertRaises(ValueError):
            validate_report_shape({"results": "failed"}, "bandit")

    def test_valid_zero_finding_sarif_is_accepted(self):
        validate_report_shape({"version": "2.1.0", "runs": [{"results": []}]}, "osv")

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

    def test_dockle_sarif_becomes_container_configuration_finding(self):
        report = {"runs": [{
            "tool": {"driver": {"rules": [{
                "id": "CIS-DI-0001",
                "shortDescription": {"text": "Create a user for the container"},
            }]}},
            "results": [{
                "ruleId": "CIS-DI-0001", "level": "warning",
                "message": {"text": "Last user should not be root"},
            }],
        }]}
        finding = parse_sarif(report, "dockle")[0]
        self.assertEqual(finding["finding_class"], "iac")
        self.assertEqual(finding["rule_id"], "CIS-DI-0001")
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["title"], "Create a user for the container")
        self.assertEqual(finding["description"], "Last user should not be root")


class FixValidationTests(unittest.TestCase):
    def test_invalid_python_is_rejected(self):
        self.assertFalse(parses_ok("app.py", "def broken(:\n"))

    def test_invalid_json_is_rejected(self):
        self.assertFalse(parses_ok("config.json", "{broken}"))


if __name__ == "__main__":
    unittest.main()
