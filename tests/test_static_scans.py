"""Static scanner integration checks, to run only on Kali."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'ai-engine'))
from run_static_scans import discover_files, make_report, native_findings, run_tool
from report_parsers import parse_sarif, validate_report_shape


class StaticScanTests(unittest.TestCase):
    def test_discovery_includes_nested_files_and_excludes_dependencies_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'nested').mkdir()
            (root / 'nested/Dockerfile.dev').write_text('FROM scratch\n')
            (root / 'run script.sh').write_text('echo hi\n')
            (root / 'launcher').write_text('#!/usr/bin/env bash\necho hi\n')
            (root / 'node_modules').mkdir()
            (root / 'node_modules/ignored.sh').write_text('echo hi\n')
            (root / 'alias.sh').symlink_to(root / 'run script.sh')
            found = discover_files(root)
        self.assertEqual(found['hadolint'], ['nested/Dockerfile.dev'])
        self.assertEqual(set(found['shellcheck']), {'run script.sh', 'launcher'})

    def test_native_execution_errors_and_empty_failures_are_rejected(self):
        for status, payload in [(2, {'comments': []}), (1, {'comments': []}), (0, {'error': 'bad'})]:
            with self.assertRaises(ValueError):
                native_findings('shellcheck', payload, status)

    def test_sarif_maps_lint_findings_without_claiming_a_vulnerability(self):
        report = make_report('shellcheck', ['run script.sh'], [{
            'file': '/src/run script.sh', 'line': 4, 'column': 2,
            'level': 'warning', 'code': 2086, 'message': 'Double quote to prevent globbing.',
        }])
        validate_report_shape(report, 'shellcheck')
        finding = parse_sarif(report, 'shellcheck')[0]
        self.assertEqual(finding['rule_id'], 'SC2086')
        self.assertEqual(finding['severity'], 'LOW')
        self.assertEqual(finding['finding_class'], 'quality')
        self.assertEqual(finding['file_path'], 'run script.sh')
        self.assertIsNone(finding['cve_id'])

    def test_absent_files_are_explicitly_not_applicable(self):
        for tool in ('hadolint', 'shellcheck'):
            report = make_report(tool, [], [])
            validate_report_shape(report, tool)
            self.assertEqual(report['runs'][0]['properties']['coverage'], 'not_applicable')

    def test_report_cannot_reference_a_file_outside_the_scanned_set(self):
        with self.assertRaises(ValueError):
            make_report('hadolint', ['Dockerfile'], [{
                'file': '/etc/passwd', 'line': 1, 'column': 1, 'level': 'error',
                'code': 'DL1000', 'message': 'Invalid file',
            }])

    def test_command_uses_isolated_readonly_containers_and_cleanup(self):
        native = [{'file': '/src/Dockerfile', 'line': 1, 'column': 1,
                   'level': 'warning', 'code': 'DL3006', 'message': 'Pin image version.'}]
        with patch('run_static_scans.subprocess.run', side_effect=[
            subprocess.CompletedProcess([], 1, json.dumps(native), ''),
            subprocess.CompletedProcess([], 0, '', ''),
        ]) as command:
            records = run_tool('hadolint', ['Dockerfile'], '/host/source', '/host/policy.yaml')
        arguments = command.call_args_list[0].args[0]
        self.assertIn('--read-only', arguments)
        self.assertIn('none', arguments)
        self.assertIn('/host/source:/src:ro', arguments)
        self.assertIn('/host/policy.yaml:/policy.yaml:ro', arguments)
        self.assertEqual(len(records), 1)
        self.assertEqual(command.call_args_list[1].args[0][:3], ['docker', 'rm', '-f'])

    def test_timeout_still_removes_the_child_container(self):
        with patch('run_static_scans.subprocess.run', side_effect=[
            subprocess.TimeoutExpired(['docker', 'run'], 600),
            subprocess.CompletedProcess([], 0, '', ''),
        ]) as command:
            with self.assertRaisesRegex(ValueError, 'timeout'):
                run_tool('shellcheck', ['script.sh'], '/host/source', '/host/policy.yaml')
        self.assertEqual(command.call_args_list[1].args[0][:3], ['docker', 'rm', '-f'])
