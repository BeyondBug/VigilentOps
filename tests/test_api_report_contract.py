"""Exercise failed uploads, completion gates and retry idempotency on Kali."""

import importlib
import json
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ai-engine'))
from db import Base, Finding, ScanRun, ScanReport
from report_parsers import REQUIRED_TOOLS


class ApiReportContractTests(unittest.TestCase):
    def setUp(self):
        self.main = importlib.import_module('main')
        self.engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine)
        @contextmanager
        def database():
            session = self.sessions()
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()
        for name, value in [('get_db_session', database), ('API_KEY', 'isolated-test-key')]:
            active = patch.object(self.main, name, value)
            active.start()
            self.addCleanup(active.stop)
        self.client = TestClient(self.main.app)
        self.addCleanup(self.client.close)
        self.addCleanup(self.engine.dispose)
        self.headers = {'X-API-Key': 'isolated-test-key'}
        result = self.client.post('/api/scans', headers=self.headers, json={
            'repo_url': 'http://sg-gitea:3000/BeyondBug/example.git',
            'commit_sha': 'a' * 40, 'branch': 'main',
        })
        self.assertEqual(result.status_code, 200)
        self.scan = result.json()['id']

    def upload(self, tool, body):
        return self.client.post(f'/api/scans/{self.scan}/reports/{tool}', headers=self.headers, json=body)

    def test_malformed_scan_coordinates_are_validation_errors(self):
        valid = {'repo_url': 'http://sg-gitea:3000/BeyondBug/example.git', 'commit_sha': 'a' * 40, 'branch': 'main'}
        for field, value in [('repo_url', None), ('repo_url', 'http://attacker.example:3000/owner/repo.git'),
                             ('commit_sha', 'HEAD'), ('commit_sha', {}), ('branch', []),
                             ('pipeline_commit', 'short-sha'), ('repo_name', {})]:
            response = self.client.post('/api/scans', headers=self.headers, json={**valid, field: value})
            self.assertEqual(response.status_code, 422)
        with self.sessions() as session:
            self.assertEqual(session.query(ScanRun).count(), 1)

    def test_invalid_scan_identifier_is_a_validation_error(self):
        self.assertEqual(self.client.get('/api/scans/not-an-id').status_code, 422)

    def test_incomplete_or_failed_scan_cannot_queue_ai(self):
        path = f'/api/scans/{self.scan}'
        self.assertEqual(self.client.post(path + '/fix', headers=self.headers).status_code, 409)
        self.assertEqual(self.client.patch(path, headers=self.headers, json={'status': 'failed'}).status_code, 200)
        self.assertEqual(self.client.post(path + '/fix', headers=self.headers).status_code, 409)
        self.assertEqual(self.client.patch(path, headers=self.headers, json={'status': 'complete'}).status_code, 409)

    def test_invalid_upload_is_non_success_and_creates_no_findings(self):
        for body in ({'version': '2.1.0', 'runs': []}, {'error': 'failed'}):
            self.assertEqual(self.upload('osv', body).status_code, 422)
        with self.sessions() as session:
            self.assertEqual(session.query(Finding).count(), 0)
            self.assertEqual(session.query(ScanReport).count(), 0)

    def test_incomplete_scan_cannot_be_finalized(self):
        result = self.client.patch(f'/api/scans/{self.scan}', headers=self.headers, json={'status': 'complete'})
        self.assertEqual(result.status_code, 409)
        with self.sessions() as session:
            self.assertEqual(session.get(ScanRun, self.scan).status, 'running')

    def test_api_key_is_required_for_report_writes(self):
        response = self.client.post(f'/api/scans/{self.scan}/reports/osv', json={
            'version': '2.1.0', 'runs': [{'results': []}],
        })
        self.assertEqual(response.status_code, 401)
        with self.sessions() as session:
            self.assertEqual(session.query(ScanReport).count(), 0)

    def test_conditional_reports_cannot_be_removed_from_the_contract(self):
        expected = sorted(REQUIRED_TOOLS | {'bandit', 'dockle', 'trivy-image'})
        path = f'/api/scans/{self.scan}'
        self.assertEqual(self.client.patch(path, headers=self.headers, json={'required_reports': expected}).status_code, 200)
        self.assertEqual(self.client.patch(path, headers=self.headers,
                         json={'required_reports': sorted(REQUIRED_TOOLS)}).status_code, 422)
        for tool in REQUIRED_TOOLS:
            body = {'spdxVersion': 'SPDX-2.3', 'packages': []} if tool == 'syft-sbom' else {'version': '2.1.0', 'runs': [{'results': []}]}
            self.assertEqual(self.upload(tool, body).status_code, 200)
        self.assertEqual(self.client.patch(path, headers=self.headers, json={'status': 'complete'}).status_code, 409)

    def test_not_applicable_claim_requires_the_osv_exit_code(self):
        body = {'version': '2.1.0', 'runs': [{'results': [], 'properties': {'coverage': 'not_applicable'}}]}
        self.assertEqual(self.upload('osv', body).status_code, 422)
        body['runs'][0]['invocations'] = [{'executionSuccessful': True, 'exitCode': 128}]
        self.assertEqual(self.upload('osv', body).status_code, 200)
        reports = self.client.get(f'/api/scans/{self.scan}').json()['reports']
        self.assertEqual(reports[0]['coverage'], 'not_applicable')
        self.assertEqual(self.upload('semgrep', body).status_code, 422)

    def test_lint_no_file_receipts_preserve_not_applicable_coverage(self):
        for tool in ('hadolint', 'shellcheck'):
            body = {'version': '2.1.0', 'runs': [{'results': [],
                'properties': {'coverage': 'not_applicable', 'scanned_file_count': 0},
                'invocations': [{'executionSuccessful': True, 'exitCode': 0}]}]}
            self.assertEqual(self.upload(tool, body).status_code, 200)
        reports = self.client.get(f'/api/scans/{self.scan}').json()['reports']
        self.assertEqual({row['tool'] for row in reports}, {'hadolint', 'shellcheck'})
        self.assertTrue(all(row['coverage'] == 'not_applicable' and row['finding_count'] == 0 for row in reports))

    def test_repeated_upload_is_idempotent_and_conflicting_content_is_rejected(self):
        body = {'results': [{'test_id': 'B602', 'test_name': 'shell', 'issue_severity': 'HIGH', 'filename': '/src/app.py'}]}
        self.assertEqual(self.upload('bandit', body).status_code, 200)
        self.assertEqual(self.upload('bandit', body).status_code, 200)
        self.assertEqual(self.upload('bandit', {'results': []}).status_code, 409)
        with self.sessions() as session:
            self.assertEqual(session.query(Finding).count(), 1)
            self.assertEqual(session.get(ScanRun, self.scan).total_findings, 1)

    def test_complete_contract_can_be_finalized(self):
        for tool in REQUIRED_TOOLS:
            body = {'spdxVersion': 'SPDX-2.3', 'packages': []} if tool == 'syft-sbom' else {'version': '2.1.0', 'runs': [{'results': []}]}
            self.assertEqual(self.upload(tool, body).status_code, 200)
        self.assertEqual(self.client.patch(f'/api/scans/{self.scan}', headers=self.headers, json={'status': 'complete'}).status_code, 200)
        reports = self.client.get(f'/api/scans/{self.scan}').json()['reports']
        self.assertEqual({report['tool'] for report in reports}, REQUIRED_TOOLS)
        self.assertEqual(self.client.patch(f'/api/scans/{self.scan}', headers=self.headers,
                         json={'required_reports': sorted(REQUIRED_TOOLS | {'bandit'})}).status_code, 409)

    def test_all_reports_without_finalization_cannot_queue_ai(self):
        for tool in REQUIRED_TOOLS:
            body = {'spdxVersion': 'SPDX-2.3', 'packages': []} if tool == 'syft-sbom' else {'version': '2.1.0', 'runs': [{'results': []}]}
            self.assertEqual(self.upload(tool, body).status_code, 200)
        with patch('tasks.run_ai_fix.delay') as queue:
            self.assertEqual(self.client.post(f'/api/scans/{self.scan}/fix', headers=self.headers).status_code, 409)
        queue.assert_not_called()

    def test_accepted_scan_survives_a_later_workflow_failure(self):
        for tool in REQUIRED_TOOLS:
            body = {'spdxVersion': 'SPDX-2.3', 'packages': []} if tool == 'syft-sbom' else {'version': '2.1.0', 'runs': [{'results': []}]}
            self.assertEqual(self.upload(tool, body).status_code, 200)
        path = f'/api/scans/{self.scan}'
        self.assertEqual(self.client.patch(path, headers=self.headers, json={'status': 'complete'}).status_code, 200)
        self.assertEqual(self.client.patch(path, headers=self.headers, json={'status': 'failed'}).status_code, 409)
        self.assertEqual(self.client.get(path).json()['status'], 'complete')

    def test_scan_list_includes_no_file_receipts_without_loading_findings_in_summary_mode(self):
        body = {'version': '2.1.0', 'runs': [{'results': [],
            'properties': {'coverage': 'not_applicable', 'scanned_file_count': 0},
            'invocations': [{'executionSuccessful': True, 'exitCode': 0}]}]}
        self.assertEqual(self.upload('hadolint', body).status_code, 200)
        for path in ('/api/scans', '/api/scans?summary_only=true'):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()[0]['reports'][0]['coverage'], 'not_applicable')

    def test_health_and_cve_errors_do_not_return_private_exception_details(self):
        with patch.object(self.main, 'get_db_session', side_effect=RuntimeError('fixture-private-password')):
            for path in ('/health', '/api/cves'):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 503)
                self.assertNotIn('fixture-private-password', response.text)

    def test_finding_pages_filter_literal_search_and_preserve_summary_totals(self):
        with self.sessions() as session:
            session.add_all([
                Finding(scan_run_id=self.scan, scanner='bandit', severity='HIGH', title='literal 50%_value', rule_id='B602'),
                Finding(scan_run_id=self.scan, scanner='bandit', severity='LOW', title='ordinary', fix_status='pr_opened'),
                Finding(scan_run_id=self.scan, scanner='osv', severity='HIGH', title='dependency'),
            ])
            session.commit()
        first = self.client.get('/api/findings?limit=2').json()
        second = self.client.get('/api/findings?limit=2&offset=2').json()
        self.assertEqual(first['total'], 3)
        self.assertEqual(len(first['findings']), 2)
        self.assertEqual(len(second['findings']), 1)
        self.assertTrue({row['id'] for row in first['findings']}.isdisjoint(row['id'] for row in second['findings']))
        self.assertEqual(first['scanners'], ['bandit', 'osv'])
        self.assertEqual(self.client.get('/api/findings', params={'search': '%_'}).json()['total'], 1)
        self.assertEqual(self.client.get('/api/findings?severity=HIGH&scanner=bandit').json()['total'], 1)
        summary = self.client.get('/api/scans?summary_only=true').json()[0]
        self.assertEqual(summary['findings'], [])
        self.assertEqual(summary['scanner_counts'], {'bandit': 2, 'osv': 1})
        self.assertEqual(summary['severity_counts'], {'HIGH': 2, 'LOW': 1})
        self.assertEqual(summary['proposed_finding_count'], 1)

    def test_finding_pages_validate_bounds_and_recent_scan_scope(self):
        for params in ({'limit': 201}, {'offset': -1}, {'scan_id': 0}, {'severity': 'invalid'}, {'search': 'x' * 201}):
            self.assertEqual(self.client.get('/api/findings', params=params).status_code, 422)
        self.assertEqual(self.client.get('/api/findings?scan_id=999999').status_code, 404)
        with self.sessions() as session:
            session.add(Finding(scan_run_id=self.scan, title='old finding', severity='HIGH'))
            session.add_all([ScanRun(repo_url='http://sg-gitea:3000/BeyondBug/example.git', commit_sha='b' * 40) for _ in range(100)])
            session.commit()
        self.assertEqual(self.client.get('/api/findings').json()['total'], 0)
        self.assertEqual(self.client.get(f'/api/findings?scan_id={self.scan}').json()['total'], 1)
