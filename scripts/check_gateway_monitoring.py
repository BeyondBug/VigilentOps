"""Kali-only authenticated gateway, Grafana query and Prometheus acceptance checks."""

import argparse
import base64
import json
import os
import ssl
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from configure_gateway import read_env


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    options = parser.parse_args()
    os.umask(0o077)
    options.output.parent.mkdir(parents=True, exist_ok=True)
    env = read_env(Path('.env'))
    # Use the known local origin; credentials must never follow a redirect.
    base = 'https://localhost:3000'
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context(
        cafile='secrets/gateway/ca.pem')), NoRedirect())

    def auth(user, password):
        return 'Basic ' + base64.b64encode((user + ':' + password).encode()).decode()

    gateway = auth(env['PROXY_AUTH_USER'], env['PROXY_AUTH_PASSWORD'])
    grafana = auth(env.get('GRAFANA_ADMIN_USER', 'admin'), env['GRAFANA_ADMIN_PASSWORD'])

    def request(path, credential=None, body=None):
        headers = {'Content-Type': 'application/json'}
        if credential:
            headers['Authorization'] = credential
        query = Request(base + path, headers=headers,
                        data=json.dumps(body).encode() if body is not None else None)
        try:
            with opener.open(query, timeout=60) as response:
                raw = response.read()
                try:
                    data = json.loads(raw)
                except ValueError:
                    data = None
                return response.status, data
        except HTTPError as error:
            return error.code, None

    checks = []
    authenticated_paths = {'/dashboard/': '/dashboard/',
                           '/jenkins/': '/jenkins/api/json',
                           '/prometheus/': '/prometheus/api/v1/status/buildinfo'}
    for path in ('/dashboard/', '/jenkins/', '/prometheus/'):
        status, _ = request(path)
        checks.append({'check': 'anonymous ' + path, 'pass': status == 401, 'http_status': status})
        status, _ = request(authenticated_paths[path], gateway)
        checks.append({'check': 'authenticated ' + path, 'pass': status == 200, 'http_status': status})
    status, _ = request('/jenkins/generic-webhook-trigger/invoke', gateway)
    checks.append({'check': 'public webhook blocked', 'pass': status == 404, 'http_status': status})
    status, targets = request('/prometheus/api/v1/targets', gateway)
    active = (targets or {}).get('data', {}).get('activeTargets', [])
    checks.append({'check': 'all configured Prometheus targets up',
                   'pass': status == 200 and len(active) >= 8 and all(t.get('health') == 'up' for t in active),
                   'targets': [{'job': t.get('labels', {}).get('job'), 'health': t.get('health')} for t in active]})

    status, sources = request('/grafana/api/datasources', grafana)
    if status != 200 or not isinstance(sources, list):
        raise SystemExit('Grafana datasource access failed; inspect credentials privately')
    source_by_name = {source['name']: source for source in sources}
    dashboard = json.loads(Path('monitoring/grafana/dashboards/secureguard-main.json').read_text())
    queries, panels = [], {}
    for element in dashboard['spec']['elements'].values():
        panel = element.get('spec', {})
        for item in panel.get('data', {}).get('spec', {}).get('queries', []):
            spec = item['spec']
            query = spec['query']
            source = source_by_name[query['datasource']['name']]
            reference = f"panel{panel['id']}_{spec['refId']}"
            queries.append({**query['spec'], 'refId': reference,
                            'datasource': {'uid': source['uid'], 'type': source['type']},
                            'intervalMs': 30000, 'maxDataPoints': 500})
            panels[reference] = panel['title']
    status, response = request('/grafana/api/ds/query', grafana,
                               {'from': 'now-6h', 'to': 'now', 'queries': queries})
    results = (response or {}).get('results', {})
    for query in queries:
        ref = query['refId']
        result = results.get(ref, {})
        frames = result.get('frames', [])
        checks.append({'check': 'Grafana ' + panels[ref], 'ref_id': ref,
                       'pass': status == 200 and ref in results and not result.get('error') and bool(frames),
                       'frame_count': len(frames)})
    options.output.write_text(json.dumps({'scope': 'HTTP, datasource frames and target health; not visual or end-to-end scan acceptance',
                                         'checks': checks}, indent=2) + '\n')
    options.output.chmod(0o600)
    for check in checks:
        print(('PASS ' if check['pass'] else 'FAIL ') + check['check'])
    if not queries or not all(check['pass'] for check in checks):
        raise SystemExit('Gateway/monitoring acceptance incomplete; inspect the private report')


if __name__ == '__main__':
    main()
