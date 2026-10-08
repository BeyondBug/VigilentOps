"""Evidence review, severity preservation, verification and queue regression checks."""
import unittest
from datetime import datetime, date, timedelta
from unittest.mock import patch
import test_api_report_contract as fixture
from db import Finding, ScanRun, ScanReport
from report_parsers import REQUIRED_TOOLS


class FindingReviewTests(unittest.TestCase):
    def setUp(self):
        fixture.ApiReportContractTests.setUp(self)
        with self.sessions() as db:
            finding = Finding(scan_run_id=self.scan, scanner='bandit', rule_id='B602',
                              severity='HIGH', title='Shell injection', file_path='app.py',
                              cve_id='CVE-2026-12345', finding_class='sast')
            db.add(finding)
            db.flush()
            self.finding = finding.id
        self.path = f'/api/findings/{self.finding}/review'
        self.body = {'status': 'confirmed', 'owner': 'Test operator', 'version': 0,
                     'evidence': 'Reproduced with a controlled shell command fixture.'}

    def test_requires_auth_evidence_and_current_version(self):
        self.assertEqual(self.client.patch(self.path, json=self.body).status_code, 401)
        for change in ({'evidence': ''}, {'owner': ''}, {'version': True}, {'status': 'hidden'}, {'surprise': 1}):
            self.assertEqual(self.client.patch(self.path, json={**self.body, **change}, headers=self.headers).status_code, 422)
        result = self.client.patch(self.path, json=self.body, headers=self.headers)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()['severity'], 'HIGH')
        self.assertEqual(result.json()['review_version'], 1)
        self.assertEqual(self.client.patch(self.path, json=self.body, headers=self.headers).status_code, 409)
        history = self.client.get(f'/api/findings/{self.finding}/reviews').json()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['evidence'], self.body['evidence'])
        page = self.client.get('/api/findings?review_status=confirmed').json()
        self.assertEqual(page['total'], 1)
        self.assertEqual(self.client.get('/api/findings?review_status=false_positive').json()['total'], 0)
        self.assertEqual(self.client.get('/api/findings?review_status=invalid').status_code, 422)

    def test_risk_acceptance_requires_impact_mitigation_and_review_date(self):
        body = {**self.body, 'status': 'accepted_risk'}
        self.assertEqual(self.client.patch(self.path, json=body, headers=self.headers).status_code, 422)
        details = {'impact': 'Internal fixture only', 'mitigation': 'Network isolated', 'review_date': str(date.today() - timedelta(days=1))}
        self.assertEqual(self.client.patch(self.path, json={**body, 'details': details}, headers=self.headers).status_code, 422)
        details['review_date'] = str(date.today() + timedelta(days=30))
        self.assertEqual(self.client.patch(self.path, json={**body, 'details': details}, headers=self.headers).status_code, 200)

    def test_fixed_requires_same_repo_completed_scan_scanner_and_absent_finding(self):
        with self.sessions() as db:
            original = db.get(ScanRun, self.scan)
            verification = ScanRun(repo_url=original.repo_url, commit_sha='b'*40, branch='main',
                                   status='complete', finished_at=datetime.utcnow(), required_reports=sorted(REQUIRED_TOOLS))
            db.add(verification)
            db.flush()
            verification_id = verification.id
            for tool in REQUIRED_TOOLS:
                db.add(ScanReport(scan_run_id=verification_id, tool=tool, sha256='0'*64, finding_count=0, coverage='scanned'))
        body = {**self.body, 'status': 'fixed', 'details': {'tested_commit': 'b'*40, 'verification_scan_id': verification_id}}
        self.assertEqual(self.client.patch(self.path, json=body, headers=self.headers).status_code, 422)
        with self.sessions() as db:
            db.add(ScanReport(scan_run_id=verification_id, tool='bandit', sha256='1'*64, finding_count=0, coverage='scanned'))
            duplicate = Finding(scan_run_id=verification_id, scanner='bandit', rule_id='B602', severity='HIGH', file_path='app.py', cve_id='CVE-2026-12345')
            db.add(duplicate)
            db.flush()
            duplicate_id = duplicate.id
        self.assertEqual(self.client.patch(self.path, json=body, headers=self.headers).status_code, 409)
        with self.sessions() as db:
            db.delete(db.get(Finding, duplicate_id))
        response = self.client.patch(self.path, json=body, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)

    def test_cve_summary_reads_database_findings_without_scan_payloads(self):
        response = self.client.get('/api/cves/summary?limit=1')
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data['total'], 1)
        self.assertEqual(data['cves'][0]['id'], 'CVE-2026-12345')
        self.assertEqual(data['cves'][0]['severity'], 'HIGH')
        self.assertEqual(data['cves'][0]['count'], 1)
        self.assertEqual(self.client.get('/api/cves/summary?offset=1').json()['cves'], [])

    def accepted_scan(self):
        with self.sessions() as db:
            scan = db.get(ScanRun, self.scan)
            scan.status, scan.finished_at = 'complete', datetime.utcnow()
            for tool in REQUIRED_TOOLS:
                db.add(ScanReport(scan_run_id=self.scan, tool=tool, sha256='0'*64, finding_count=0, coverage='scanned'))

    def test_repeated_fix_requests_enqueue_only_once_and_return_same_id(self):
        self.accepted_scan()
        with patch('tasks.run_ai_fix.apply_async') as queue:
            first = self.client.post(f'/api/scans/{self.scan}/fix', headers=self.headers)
            second = self.client.post(f'/api/scans/{self.scan}/fix', headers=self.headers)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()['job_id'], second.json()['job_id'])
        queue.assert_called_once()

    def test_broker_failure_rolls_back_reservation_and_returns_503(self):
        self.accepted_scan()
        with patch('tasks.run_ai_fix.apply_async', side_effect=ConnectionError('private broker details')):
            result = self.client.post(f'/api/scans/{self.scan}/fix', headers=self.headers)
        self.assertEqual(result.status_code, 503)
        self.assertNotIn('private broker details', result.text)
        with self.sessions() as db:
            self.assertIsNone(db.get(ScanRun, self.scan).ai_task_id)
