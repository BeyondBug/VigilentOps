#!/bin/bash
docker exec sg-wazuh cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | \
python3 -c "
import sys, json, time, urllib.request, os

STATE = '/tmp/loki_pos'
try:
    pos = int(open(STATE).read())
except:
    pos = 0

lines = sys.stdin.read()
new_lines = lines[pos:].strip().splitlines()
new_lines = [l.strip() for l in new_lines if l.strip()]

if new_lines:
    values = [[str(int(time.time_ns()) + i*1000), line] for i,line in enumerate(new_lines)]
    payload = json.dumps({'streams': [{'stream': {'job': 'wazuh', 'host': 'sg-wazuh'}, 'values': values}]}).encode()
    try:
        req = urllib.request.Request('http://localhost:3100/loki/api/v1/push',
            data=payload, headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=5)
        open(STATE, 'w').write(str(pos + sum(len(l)+1 for l in new_lines)))
        print(f'Shipped {len(new_lines)} Wazuh alerts to Loki')
    except Exception as e:
        print(f'Loki push error: {e}')
"
