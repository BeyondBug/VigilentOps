"""Kali-only model compatibility fixture; sends synthetic code, never repository files."""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ai-engine'))
import httpx
from model_pool import load_model_pool
from llm_response import extract_llm_content
from fix_validation import parses_ok, preserves_python_interface, validates_security_change


SOURCE = 'import subprocess\ndef execute(command):\n    return subprocess.call(command, shell=True)\n'
PROMPT = ('Return only the complete Python file. The command argument is a list of arguments. '
          'Remove shell interpretation without suppressing checks or changing the execute(command) interface.\n'
          + SOURCE)


def check_route(route):
    start = time.monotonic()
    result = {'model': route['model'], 'status': 'failed'}
    try:
        response = httpx.post(route['url'], headers={'Authorization': 'Bearer ' + route['key']},
                              json={'model': route['model'], 'messages': [{'role': 'user', 'content': PROMPT}],
                                    'temperature': 0.1, 'max_tokens': 512}, timeout=45)
        result['http_status'] = response.status_code
        if response.status_code != 200:
            result['reason'] = f'HTTP {response.status_code}; inspect entitlement/quota privately'
            return result
        try:
            candidate = extract_llm_content(response.json())
        except (ValueError, TypeError, AttributeError):
            result['reason'] = 'Unsupported, empty, truncated or malformed response'
            return result
        if (not parses_ok('app.py', candidate) or candidate.strip() == SOURCE.strip()
                or len(candidate.splitlines()) < len(SOURCE.splitlines()) * 0.7
                or not preserves_python_interface(SOURCE, candidate)):
            result['reason'] = 'Synthetic candidate failed syntax/change/interface gates'
            return result
        valid, reason = validates_security_change(SOURCE, candidate, [{'scanner': 'bandit', 'rule_id': 'B602'}])
        result['status'] = 'fixture_pass' if valid else 'failed'
        result['reason'] = reason
        return result
    except httpx.RequestError as error:
        result['reason'] = 'Transport failure: ' + type(error).__name__
        return result
    finally:
        result['elapsed_seconds'] = round(time.monotonic() - start, 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    routes = load_model_pool(os.environ)
    if not routes:
        raise SystemExit('No complete model routes configured; no requests sent')
    os.umask(0o077)
    options.output.parent.mkdir(parents=True, exist_ok=True)
    results = []
    for route in routes:
        result = check_route(route)
        results.append(result)
        # No raw response, endpoint, API key, candidate or source is printed.
        print(f"{result['model']}: {result['status']}", flush=True)
    options.output.write_text(json.dumps({'date': datetime.now(timezone.utc).isoformat(),
        'scope': 'Synthetic compatibility fixture only; real PR acceptance remains required',
        'results': results}, indent=2) + '\n')
    options.output.chmod(0o600)
    if any(result['status'] != 'fixture_pass' for result in results):
        raise SystemExit('Some configured routes failed; review the private report and adjust the pool')
    print('All configured routes passed this fixture; real repository fixes remain unverified')


if __name__ == '__main__':
    main()
