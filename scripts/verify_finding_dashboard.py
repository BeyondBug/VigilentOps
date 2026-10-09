#!/usr/bin/env python3
"""Kali-only browser smoke test of a built dashboard with controlled API fixtures.

Requires Docker, Chromium and Playwright. No live credentials or API writes.
Backend grouping semantics are covered by tests/test_finding_review.py.
"""
import argparse
import functools
import http.server
import json
from pathlib import Path
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit


def verify(image, chromium):
    from playwright.sync_api import sync_playwright

    first = {
        'id': 1, 'scanner': 'trivy-image', 'severity': 'HIGH',
        'title': 'Controlled package alert', 'review_status': 'unverified',
        'finding_class': 'sca', 'cvss_score': None, 'package': 'fixture-package',
        'installed_version': '1.0', 'fixed_version': '1.1',
        'image': 'fixture@sha256:abc', 'repo': 'fixture',
        'description': 'Controlled scanner description',
    }
    second = {**first, 'id': 2, 'scanner': 'grype', 'title': 'Second scanner alert'}
    scan = {
        'id': 999, 'repo_name': 'fixture', 'status': 'complete',
        'created_at': '2026-10-08T00:00:00Z', 'total_findings': 2,
        'high_count': 2, 'critical_count': 0, 'ai_task_status': 'failed',
        'ai_task_id': 'controlled-failed-task', 'reports': [], 'required_reports': [],
    }
    errors = []

    def mock(route):
        url = urlsplit(route.request.url)
        params = parse_qs(url.query)
        if url.path.endswith('/api/findings'):
            grouped = params.get('group_duplicates') == ['true'] and 'group_id' not in params
            rows = [] if params.get('verified_only') == ['true'] else ([{**first, 'group_record_count': 2}] if grouped else [first, second])
            route.fulfill(json={
                'findings': rows, 'total': len(rows), 'total_records': 2,
                'total_in_scope': 2, 'verified_in_scope': 0, 'grouped': grouped, 'scanners': ['trivy-image', 'grype'],
            })
        elif url.path.endswith('/api/scans'):
            route.fulfill(json=[scan])
        elif url.path.endswith('/health'):
            route.fulfill(json={'status': 'ok'})
        elif url.path.endswith('/cves/recent') or url.path.endswith('/api/cves/summary'):
            cves = [
                {'id': 'CVE-FIXTURE', 'cve_id': 'CVE-FIXTURE', 'severity': 'HIGH',
                 'score': None, 'cvss_score': None, 'description': 'Controlled advisory',
                 'count': 1, 'repos': ['fixture']},
                {'id': 'CVE-ZERO', 'cve_id': 'CVE-ZERO', 'severity': 'LOW',
                 'score': 0, 'cvss_score': 0},
            ]
            route.fulfill(json=cves if url.path.endswith('/cves/recent') else {'cves': [] if params.get('verified_only') == ['true'] else cves, 'total': 0 if params.get('verified_only') == ['true'] else 2})
        else:
            route.continue_()

    with tempfile.TemporaryDirectory(prefix='sg-product-ui-') as directory:
        container = subprocess.check_output(['docker', 'create', image], text=True).strip()
        try:
            subprocess.run(['docker', 'cp', container + ':/usr/share/nginx/html',
                            str(Path(directory) / 'dashboard')], check=True)
        finally:
            subprocess.run(['docker', 'rm', container], check=True, stdout=subprocess.DEVNULL)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, executable_path=chromium,
                                             args=['--no-sandbox'])
                try:
                    page = browser.new_page()
                    page.on('pageerror', lambda error: errors.append(str(error)))
                    page.route('**/*', mock)
                    page.goto(f'http://127.0.0.1:{server.server_port}/dashboard/')
                    page.get_by_role('button', name='Findings', exact=False).click()
                    page.get_by_text('No evidence-confirmed findings match this view.', exact=False).wait_for()
                    page.get_by_label('Show all scanner alerts (includes unverified)').check()
                    page.get_by_text(first['title'], exact=True).wait_for()
                    with page.expect_request(lambda r: 'finding_class=sca' in r.url):
                        page.get_by_label('Finding category').select_option('sca')
                    page.get_by_text(first['title'], exact=True).click()
                    for text in ('CVSS: Not reported', first['package'], first['image'], first['description']):
                        page.get_by_text(text, exact=True).wait_for()
                    page.get_by_text('Scanner alert awaiting evidence review.', exact=False).wait_for()
                    page.get_by_label('Group matching dependency alerts').check()
                    page.get_by_text('1 display groups from 2 matching scanner records.', exact=False).wait_for()
                    page.get_by_text('Representative alert', exact=True).wait_for()
                    with page.expect_request(lambda r: 'group_id=1' in r.url):
                        page.get_by_role('button', name='View all 2 scanner records').click()
                    page.get_by_text(second['title'], exact=True).wait_for()
                    page.get_by_role('button', name='Back to findings').click()
                    page.get_by_role('button', name='View all 2 scanner records').wait_for()
                    page.get_by_role('button', name='Scan History', exact=False).click()
                    page.get_by_text('fixture', exact=True).first.click()
                    page.get_by_text('controlled-failed-task', exact=True).wait_for()
                    page.get_by_text('AI review failed.', exact=False).wait_for()
                    page.get_by_role('button', name='CVE Feed', exact=False).click()
                    page.get_by_text('CVSS Not reported', exact=True).wait_for()
                    page.get_by_text('CVSS 0', exact=True).wait_for()
                    with page.expect_request(lambda r: '/api/cves/summary' in r.url and 'verified_only=true' in r.url):
                        page.get_by_role('button', name='SCAN FINDINGS', exact=False).click()
                    page.get_by_label('Show all scanner alerts (includes unverified)').check()
                    page.get_by_text('CVSS Not reported', exact=True).wait_for()
                    page.get_by_text('CVSS 0', exact=True).wait_for()
                    if errors:
                        raise AssertionError(errors)
                finally:
                    browser.close()
        finally:
            server.shutdown()
            server.server_close()
    print(json.dumps({'result': 'passed', 'image': image, 'page_errors': errors,
                      'checks': ['confirmed-only default and raw alert access', 'category transport', 'artifact evidence', 'group drill-down and back',
                                 'AI failure visibility', 'missing and zero CVSS in both CVE views']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Built candidate dashboard Docker image')
    parser.add_argument('--chromium', default='/usr/bin/chromium')
    args = parser.parse_args()
    verify(args.image, args.chromium)
