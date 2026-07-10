#!/usr/bin/env python3
"""Simple Wazuh alert shipper to Loki. Runs every 30s."""
import json, time, urllib.request, os

LOKI_URL    = "http://localhost:3100/loki/api/v1/push"
ALERTS_FILE = "/var/lib/docker/volumes/secureguard_wazuh_logs/_data/alerts/alerts.json"
STATE_FILE  = "/tmp/loki_shipper_pos"

def get_position():
    try: return int(open(STATE_FILE).read().strip())
    except: return 0

def save_position(pos):
    open(STATE_FILE, 'w').write(str(pos))

def push_to_loki(lines):
    if not lines: return
    values = [[str(int(time.time_ns()) + i*1000), line] for i,line in enumerate(lines)]
    payload = json.dumps({"streams":[{"stream":{"job":"wazuh","source":"alerts"},"values":values}]}).encode()
    try:
        req = urllib.request.Request(LOKI_URL, data=payload, headers={"Content-Type":"application/json"})
        urllib.request.urlopen(req, timeout=10)
        print(f"Shipped {len(lines)} lines to Loki")
    except Exception as e:
        print(f"Loki push error: {e}")

while True:
    try:
        pos = get_position()
        with open(ALERTS_FILE, 'r', errors='ignore') as f:
            f.seek(pos)
            new_lines = [l.strip() for l in f if l.strip()]
            new_pos = f.tell()
        if new_lines:
            push_to_loki(new_lines)
            save_position(new_pos)
        else:
            save_position(new_pos)
    except Exception as e:
        print(f"Error: {e}")
    time.sleep(30)
