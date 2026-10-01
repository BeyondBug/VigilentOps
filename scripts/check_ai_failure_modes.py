"""Server-only Celery/HTTP acceptance fixture; no real provider, repository or DB writes."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, '/app')
from celery.contrib.testing.worker import start_worker
import fix_engine
import tasks


SOURCE = 'import subprocess\ndef execute(command):\n    return subprocess.call(command, shell=True)\n'


class Provider(BaseHTTPRequestHandler):
    mode = 'limited'
    calls = 0
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        type(self).calls += 1
        if self.mode in ('limited', 'body_limited'):
            self.send_response(200 if self.mode == 'body_limited' else 429)
            self.send_header('Retry-After', '1')
            payload = {'error': {'code': 429, 'message': 'controlled fixture rate limit',
                                 'metadata': {'error_type': 'rate_limit_exceeded'}}}
        else:
            self.send_response(200)
            content = SOURCE.replace('shell=True', 'shell=False') if self.path == '/valid' else 'invalid python ???'
            payload = {'choices': [{'message': {'content': content}}]}
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())
    def log_message(self, *arguments):
        pass


def clone_fixture(*arguments):
    directory = tempfile.mkdtemp(prefix='sg_acceptance_repo_')
    subprocess.run(['git', 'init', '-q', directory], check=True, capture_output=True)
    Path(directory, 'app.py').write_text(SOURCE)
    return directory


def main():
    server = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f'http://127.0.0.1:{server.server_port}'
    queue = 'sg-acceptance-' + uuid.uuid4().hex
    fixture = [{'id': -1, 'scanner': 'bandit', 'rule_id': 'B602', 'severity': 'HIGH',
                'file_path': 'app.py', 'branch': 'main'}]
    previous_retries = tasks.run_ai_fix.max_retries
    tasks.run_ai_fix.max_retries = 1
    results = []
    try:
        with patch.object(fix_engine, 'get_all_findings', return_value=fixture), \
             patch.object(fix_engine, 'clone_repo', side_effect=clone_fixture), \
             patch.object(fix_engine, 'mark_pr_opened') as mark, \
             patch.object(fix_engine, 'open_pr') as publish, \
             start_worker(tasks.app, queues=[queue], pool='solo', concurrency=1, perform_ping_check=False):
            model = {'model': 'fixture', 'key': 'fixture-key', 'url': endpoint + '/limited'}
            for mode in ('limited', 'body_limited'):
                Provider.mode = mode
                with patch.object(fix_engine, 'MODELS', [model]), \
                     patch.object(fix_engine, 'MODEL_COOLDOWNS', fix_engine.RouteCooldowns()):
                    result = tasks.run_ai_fix.apply_async(args=[-1, 'http://sg-gitea:3000/fixture/fixture.git', 'HEAD'], queue=queue)
                    results.append(result)
                    seen_retry = False
                    deadline = time.monotonic() + 40
                    while not result.ready() and time.monotonic() < deadline:
                        seen_retry |= result.state == 'RETRY'
                        time.sleep(0.1)
                    assert result.state == 'FAILURE' and seen_retry, '429 must defer and exhaust retries clearly'
                    label = 'HTTP 200 error body' if mode == 'body_limited' else 'HTTP 429'
                    print(f'{label}: Celery RETRY followed by bounded FAILURE: PASS')
            Provider.mode = 'invalid'
            with patch.object(fix_engine, 'MODELS', [{**model, 'url': endpoint + '/invalid'}]):
                result = tasks.run_ai_fix.apply_async(args=[-1, 'http://sg-gitea:3000/fixture/fixture.git', 'HEAD'], queue=queue)
                results.append(result)
                payload = result.get(timeout=30)
                assert payload['status'] == 'no_proposal'
                print('Malformed provider output leaves no proposal: PASS')
            with patch.object(fix_engine, 'MODELS', [
                {**model, 'url': endpoint + '/invalid'}, {**model, 'url': endpoint + '/valid', 'model': 'valid-fixture'},
            ]):
                content, used = fix_engine.try_with_fallback('app.py', SOURCE, fixture)
                assert used == 'valid-fixture' and 'shell=False' in content
                print('Invalid output falls back to a Bandit-validated candidate: PASS')
            mark.assert_not_called()
            publish.assert_not_called()
            print('No finding-state update, external provider call or PR publication: PASS')
    finally:
        tasks.run_ai_fix.max_retries = previous_retries
        for result in results:
            result.forget()
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
