"""Record an operator's evidence from Kali without putting API keys in the browser."""
import argparse
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('finding_id', type=int)
    parser.add_argument('status', choices=['unverified', 'confirmed', 'false_positive', 'accepted_risk', 'fixed'])
    parser.add_argument('--owner', required=True)
    parser.add_argument('--version', required=True, type=int)
    parser.add_argument('--evidence-file', required=True, type=Path)
    parser.add_argument('--details-file', type=Path, help='Optional JSON verification or risk exception details')
    args = parser.parse_args()
    body = {'status': args.status, 'owner': args.owner, 'version': args.version,
            'evidence': args.evidence_file.read_text(),
            'details': json.loads(args.details_file.read_text()) if args.details_file else {}}
    script = '''import os, sys, urllib.request, urllib.error
request = urllib.request.Request('http://127.0.0.1:8000/api/findings/' + sys.argv[1] + '/review',
    data=sys.stdin.buffer.read(), method='PATCH',
    headers={'Content-Type': 'application/json', 'X-API-Key': os.environ['SG_API_KEY']})
try:
    with urllib.request.urlopen(request, timeout=20) as response:
        print(response.read().decode())
except urllib.error.HTTPError as error:
    print(error.read().decode(), file=sys.stderr)
    sys.exit(1)
'''
    subprocess.run(['docker', 'exec', '-i', 'sg-orchestrator', 'python', '-c', script,
                    str(args.finding_id)], input=json.dumps(body), text=True, check=True)


if __name__ == '__main__':
    main()
