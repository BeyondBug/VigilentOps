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
            db.commit()
        self.path = f'/api/findings/{self.finding}/review'
        self.body = {'status': 'confirmed', 'owner': 'Test operator', 'version': 0,
                     'evidence': 'Reproduced with a controlled shell command fixture.',
                     'details': {'tested_commit': 'a'*40, 'verification_method': 'controlled_reproduction',
                                 'artifact': 'app.py', 'proof_reference': 'private-fixture-test.log',
                                 'reproduction_steps': 'Run controlled input through the isolated shell fixture.',
                                 'observed_impact': 'Controlled input reached shell execution.'}}

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
            db.commit()
        body = {**self.body, 'status': 'fixed', 'details': {'tested_commit': 'b'*40, 'verification_scan_id': verification_id}}
        self.assertEqual(self.client.patch(self.path, json=body, headers=self.headers).status_code, 422)
        with self.sessions() as db:
            db.add(ScanReport(scan_run_id=verification_id, tool='bandit', sha256='1'*64, finding_count=0, coverage='scanned'))
            duplicate = Finding(scan_run_id=verification_id, scanner='bandit', rule_id='B602', severity='HIGH', title='Shell injection', file_path='app.py', cve_id='CVE-2026-12345')
            db.add(duplicate)
            db.flush()
            duplicate_id = duplicate.id
            db.commit()
        self.assertEqual(self.client.patch(self.path, json=body, headers=self.headers).status_code, 409)
        with self.sessions() as db:
            db.delete(db.get(Finding, duplicate_id))
            db.commit()
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

    def test_category_filters_keep_quality_separate_without_hiding_raw_records(self):
        with self.sessions() as db:
            db.add(Finding(scan_run_id=self.scan, scanner='hadolint', rule_id='DL3006',
                           severity='HIGH', title='Pin base image', finding_class='quality'))
            db.add(Finding(scan_run_id=self.scan, scanner='legacy', severity='LOW',
                           title='Unclassified historical alert'))
            db.commit()
        self.assertEqual(self.client.get('/api/findings').json()['total'], 3)
        security = self.client.get('/api/findings?finding_class=sast').json()
        self.assertEqual(security['total'], 1)
        self.assertEqual(security['total_in_scope'], 3)
        quality = self.client.get('/api/findings?finding_class=quality').json()
        self.assertEqual(quality['findings'][0]['rule_id'], 'DL3006')
        self.assertEqual(self.client.get('/api/findings?finding_class=unknown').json()['total'], 1)
        self.assertEqual(self.client.get('/api/findings?finding_class=invalid').status_code, 422)
        self.assertEqual(self.client.get('/api/findings?finding_class=quality&severity=LOW').json()['total'], 0)

    def test_search_matches_advisory_package_image_and_escapes_wildcards(self):
        with self.sessions() as db:
            finding = db.get(Finding, self.finding)
            finding.package = 'fixture-package'
            finding.image = 'fixture-image@sha256:abc'
            db.commit()
        for term in ('CVE-2026-12345', 'fixture-package', 'fixture-image'):
            self.assertEqual(self.client.get('/api/findings', params={'search': term}).json()['total'], 1)
        self.assertEqual(self.client.get('/api/findings', params={'search': '%'}).json()['total'], 0)
        self.assertEqual(self.client.get('/api/findings', params={'search': '_'}).json()['total'], 0)

    def test_cve_summary_distinguishes_missing_score_from_zero(self):
        self.assertIsNone(self.client.get('/api/cves/summary').json()['cves'][0]['score'])
        with self.sessions() as db:
            db.get(Finding, self.finding).cvss_score = 0.0
            db.commit()
        self.assertEqual(self.client.get('/api/cves/summary').json()['cves'][0]['score'], 0.0)

    def test_grouping_preserves_versions_artifacts_reviews_and_raw_members(self):
        base = dict(scan_run_id=self.scan, finding_class='sca', cve_id='CVE-2026-99999',
                    package='fixture-package', installed_version='1.0', fixed_version='1.1',
                    image='fixture@sha256:abc', file_path='site-packages/fixture',
                    severity='HIGH', title='Controlled dependency alert', review_status='unverified')
        with self.sessions() as db:
            first = Finding(**base, scanner='trivy-image')
            db.add(first)
            db.flush()
            group_id = first.id
            db.add(Finding(**base, scanner='grype'))
            for change in ({'installed_version': '0.9'}, {'image': 'other@sha256:def'},
                           {'file_path': 'other/location'}, {'review_status': 'confirmed'},
                           {'severity': 'LOW'}, {'fixed_version': '2.0'}, {'package': 'other'},
                           {'finding_class': 'sast'}, {'installed_version': None}):
                db.add(Finding(**{**base, **change}, scanner='trivy-image'))
            # Incomplete records remain separate even when their remaining fields match.
            db.add(Finding(**{**base, 'installed_version': None}, scanner='grype'))
            db.commit()
        raw = self.client.get('/api/findings').json()
        grouped = self.client.get('/api/findings?group_duplicates=true').json()
        self.assertEqual(raw['total'], 13)
        self.assertEqual(grouped['total'], 12)
        self.assertEqual(grouped['total_records'], raw['total'])
        group = next(row for row in grouped['findings'] if row['id'] == group_id)
        self.assertEqual(group['group_record_count'], 2)
        members = self.client.get('/api/findings', params={'group_id': group_id}).json()
        self.assertEqual(members['total'], 2)
        self.assertEqual({row['scanner'] for row in members['findings']}, {'trivy-image', 'grype'})
        self.assertFalse(members['grouped'])
        self.assertEqual(self.client.get('/api/findings', params={'group_id': group_id, 'offset': 1, 'limit': 1}).json()['findings'][0]['scanner'], 'grype')
        self.assertEqual(self.client.get('/api/findings?group_duplicates=true&limit=1').json()['total'], 12)
        self.assertEqual(self.client.get('/api/findings?group_id=999999').status_code, 404)
        self.assertEqual(self.client.get('/api/findings?group_id=0').status_code, 422)
        self.assertEqual(self.client.get('/api/findings?scanner=grype&group_duplicates=true').json()['total'], 2)

    def test_grouping_never_combines_scans_or_unlocated_dependency_records(self):
        with self.sessions() as db:
            scan = db.get(ScanRun, self.scan)
            other = ScanRun(repo_url=scan.repo_url, commit_sha='c'*40, branch='main')
            db.add(other)
            db.flush()
            other_id = other.id
            for scan_id in (self.scan, other_id):
                db.add(Finding(scan_run_id=scan_id, scanner='grype', finding_class='sca',
                               cve_id='CVE-2026-22222', package='fixture', installed_version='1.0',
                               image='fixture@sha256:abc', severity='HIGH', title='Located alert'))
            for tool in ('grype', 'trivy-image'):
                db.add(Finding(scan_run_id=self.scan, scanner=tool, finding_class='sca',
                               cve_id='CVE-2026-22222', package='fixture', installed_version='1.0',
                               severity='HIGH', title='Artifact unknown'))
            db.commit()
        self.assertEqual(self.client.get('/api/findings?group_duplicates=true').json()['total'], 5)
        self.assertEqual(self.client.get('/api/findings', params={'scan_id': other_id, 'group_id': self.finding}).status_code, 404)

    def test_confirmed_requires_exact_reproduction_evidence_and_cannot_promote_quality(self):
        for key in self.body['details']:
            details = {name: value for name, value in self.body['details'].items() if name != key}
            self.assertEqual(self.client.patch(self.path, json={**self.body, 'details': details}, headers=self.headers).status_code, 422)
        for change in ({'tested_commit': 'b'*40}, {'artifact': 'other.py'},
                       {'verification_method': 'ai_confidence'}, {'observed_impact': ' ' * 20}):
            response = self.client.patch(self.path, json={**self.body, 'details': {**self.body['details'], **change}}, headers=self.headers)
            self.assertEqual(response.status_code, 422)
        with self.sessions() as db:
            finding = db.get(Finding, self.finding)
            self.assertEqual(finding.review_version, 0)
            finding.finding_class = 'quality'
            db.commit()
        self.assertEqual(self.client.patch(self.path, json=self.body, headers=self.headers).status_code, 422)

    def test_verified_view_preserves_unverified_and_legacy_records_with_honest_counts(self):
        with self.sessions() as db:
            db.add(Finding(scan_run_id=self.scan, scanner='legacy', severity='HIGH',
                           finding_class='sast', title='Legacy confirmation', review_status='confirmed'))
            db.commit()
        page = self.client.get('/api/findings?verified_only=true').json()
        self.assertEqual(page['total'], 0)
        self.assertEqual(page['total_in_scope'], 2)
        raw = self.client.get('/api/findings').json()['findings']
        self.assertEqual(raw[1]['verification_level'], 'review_only')
        self.assertEqual(self.client.patch(self.path, json=self.body, headers=self.headers).status_code, 200)
        confirmed = self.client.get('/api/findings?verified_only=true&limit=1').json()
        self.assertEqual(confirmed['verified_in_scope'], 1)
        self.assertEqual(confirmed['total'], 1)
        self.assertEqual(confirmed['findings'][0]['verification_level'], 'evidence_confirmed')
        self.assertEqual(self.client.get('/api/findings?verified_only=true&offset=1').json()['findings'], [])
        summary = self.client.get('/api/scans?summary_only=true').json()[0]
        self.assertEqual(summary['verified_finding_count'], 1)
        self.assertEqual(summary['verified_severity_counts'], {'HIGH': 1})
        self.assertEqual(summary['severity_counts']['HIGH'], 2)
        self.assertEqual(self.client.get('/api/cves/summary?verified_only=true').json()['total'], 1)

    def test_unverified_alerts_do_not_queue_models_or_send_high_severity_notifications(self):
        with self.sessions() as db:
            scan = db.get(ScanRun, self.scan)
            scan.status, scan.finished_at = 'complete', datetime.utcnow()
            for tool in REQUIRED_TOOLS:
                db.add(ScanReport(scan_run_id=self.scan, tool=tool, sha256='0'*64, finding_count=0, coverage='scanned'))
            db.commit()
        with patch('tasks.run_ai_fix.apply_async') as queue, patch('notifier.Notifier') as notifier:
            result = self.client.post(f'/api/scans/{self.scan}/fix', headers=self.headers)
            self.assertEqual(result.json()['status'], 'awaiting_verification')
            self.assertEqual(self.client.post(f'/api/scans/{self.scan}/notify', headers=self.headers).json()['status'], 'no_verified_high_findings')
        queue.assert_not_called()
        notifier.assert_not_called()
        with self.sessions() as db:
            self.assertIsNone(db.get(ScanRun, self.scan).ai_task_id)

    def test_verified_notifications_are_mocked_and_disposition_revokes_eligibility(self):
        self.accepted_scan()
        with patch('notifier.Notifier') as notifier:
            notifier.return_value.send_alert.return_value = {'fixture': True}
            result = self.client.post(f'/api/scans/{self.scan}/notify', headers=self.headers)
            self.assertEqual(result.status_code, 200)
            notifier.return_value.send_alert.assert_called_once()
        body = {**self.body, 'status': 'false_positive', 'version': 1, 'details': {}}
        self.assertEqual(self.client.patch(self.path, json=body, headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get('/api/findings?verified_only=true').json()['total'], 0)
        self.assertEqual(self.client.get('/api/cves/summary?verified_only=true').json()['total'], 0)
        self.assertEqual(self.client.get('/api/scans?summary_only=true').json()[0]['verified_finding_count'], 0)

    def accepted_scan(self):
        result = self.client.patch(self.path, json=self.body, headers=self.headers)
        self.assertEqual(result.status_code, 200, result.text)
        with self.sessions() as db:
            scan = db.get(ScanRun, self.scan)
            scan.status, scan.finished_at = 'complete', datetime.utcnow()
            for tool in REQUIRED_TOOLS:
                db.add(ScanReport(scan_run_id=self.scan, tool=tool, sha256='0'*64, finding_count=0, coverage='scanned'))
            db.commit()

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
