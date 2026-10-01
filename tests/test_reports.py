import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "ai-engine"))

from report_parsers import parse_bandit, parse_sarif, validate_report_shape
from fix_validation import parses_ok


class ReportParserTests(unittest.TestCase):
    def test_osv_artifact_coordinates_include_scoped_package_names(self):
        for artifact, name, version in [('anyio@4.9.0', 'anyio', '4.9.0'),
                                         ('@example/client@1.2.3', '@example/client', '1.2.3')]:
            report = {'runs': [{'results': [{'ruleId': 'CVE-2026-63374',
                'message': {'text': f"Package '{artifact}' is vulnerable to 'CVE-2026-63374'."}}]}]}
            finding = parse_sarif(report, 'osv')[0]
            self.assertEqual((finding['package'], finding['installed_version']), (name, version))

    def test_report_shape_rejects_unparsed_json(self):
        with self.assertRaises(ValueError):
            validate_report_shape({"message": "scanner failed"}, "osv")
        with self.assertRaises(ValueError):
            validate_report_shape({"results": "failed"}, "bandit")

    def test_valid_zero_finding_sarif_is_accepted(self):
        validate_report_shape({"version": "2.1.0", "runs": [{"results": []}]}, "osv")

    def test_empty_runs_and_failed_invocation_are_rejected(self):
        for runs in ([], [{"results": [], "invocations": [{"executionSuccessful": False}]}]):
            with self.assertRaises(ValueError):
                validate_report_shape({"version": "2.1.0", "runs": runs}, "osv")

    def test_trivy_critical_package_and_image_metadata_are_preserved(self):
        report = {"runs": [{"properties": {"imageName": "lab/image:123"},
            "tool": {"driver": {"rules": [{"id": "CVE-2026-12345",
                "name": "OsPackageVulnerability", "shortDescription": {"text": "Affected library"},
                "properties": {"security-severity": "9.8"}}]}},
            "results": [{"ruleId": "CVE-2026-12345", "level": "error",
                "message": {"text": "Package: example\nInstalled Version: 1.0\nFixed Version: 1.1\nSeverity: CRITICAL"}}]}]}
        finding = parse_sarif(report, "trivy-image")[0]
        self.assertEqual(finding['severity'], 'CRITICAL')
        self.assertEqual(finding['cvss_score'], 9.8)
        self.assertEqual(finding['package'], 'example')
        self.assertEqual(finding['installed_version'], '1.0')
        self.assertEqual(finding['fixed_version'], '1.1')
        self.assertEqual(finding['image'], 'lab/image:123')

    def test_grype_advisory_suffix_is_not_a_cve_identifier(self):
        report = {'runs': [{'tool': {'driver': {'rules': [{
            'id': 'CVE-2026-12345-example', 'help': {'text': 'Package: example\nVersion: 1.0\nFix Version: 1.1\nSeverity: high'},
        }]}}, 'results': [{'ruleId': 'CVE-2026-12345-example'}]}]}
        finding = parse_sarif(report, 'grype')[0]
        self.assertEqual(finding['cve_id'], 'CVE-2026-12345')
        self.assertEqual(finding['installed_version'], '1.0')

    def test_trivy_secrets_receive_secret_class_for_comment_redaction(self):
        report = {'runs': [{'tool': {'driver': {'rules': [{'id': 'test-secret', 'name': 'Secret'}]}},
                            'results': [{'ruleId': 'test-secret', 'level': 'error'}]}]}
        self.assertEqual(parse_sarif(report, 'trivy-deps')[0]['finding_class'], 'secret')

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
