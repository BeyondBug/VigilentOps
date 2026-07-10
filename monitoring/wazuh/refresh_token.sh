#!/bin/bash
# Refreshes Wazuh JWT, updates Grafana datasource secret AND panel #100's header

GRAFANA_USER="admin"
GRAFANA_PASS="VR@b3y0nd"
DS_UID="efqke9w9a1xxcb"
DASH_UID="secureguard-unified"

# 1. Get a fresh Wazuh token
TOKEN=$(curl -sk -u wazuh:wazuh -X POST "https://localhost:55000/security/user/authenticate" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

if [ -z "$TOKEN" ]; then
    echo "ERROR: failed to get Wazuh token at $(date)"
    exit 1
fi

# 2. Update the datasource secret (kept for consistency / other future queries)
docker exec sg-grafana sh -c "
curl -s -X PUT http://localhost:3000/api/datasources/uid/${DS_UID} \
  -u '${GRAFANA_USER}:${GRAFANA_PASS}' \
  -H 'Content-Type: application/json' \
  -d '{
    \"name\":\"Wazuh API\",
    \"type\":\"yesoreyeram-infinity-datasource\",
    \"access\":\"proxy\",
    \"jsonData\":{\"datasource_mode\":\"basic\",\"tlsSkipVerify\":true},
    \"secureJsonData\":{\"bearerToken\":\"${TOKEN}\"}
  }'
" > /dev/null

# 3. Pull the full dashboard JSON
docker exec sg-grafana sh -c "
curl -s http://localhost:3000/api/dashboards/uid/${DASH_UID} -u '${GRAFANA_USER}:${GRAFANA_PASS}'
" > /tmp/wazuh_dash_pull.json

# 4. Patch panel 100's Authorization header with the fresh token, save back
python3 << PYEOF
import json

with open("/tmp/wazuh_dash_pull.json") as f:
    data = json.load(f)

dash = data["dashboard"]
patched = False

for p in dash.get("panels", []):
    if p.get("id") == 100:
        for target in p.get("targets", []):
            headers = target.get("url_options", {}).get("headers", [])
            new_headers = [h for h in headers if h.get("key") != "Authorization"]
            new_headers.append({"key": "Authorization", "value": "Bearer ${TOKEN}"})
            target.setdefault("url_options", {})["headers"] = new_headers
            patched = True

if not patched:
    print("WARNING: panel 100 not found or no targets to patch")

payload = {
    "dashboard": dash,
    "overwrite": True,
    "folderUid": data.get("meta", {}).get("folderUid", "secureguard")
}

with open("/tmp/wazuh_dash_update.json", "w") as f:
    json.dump(payload, f)

print("Dashboard patch prepared, patched:", patched)
PYEOF

# 5. Push the updated dashboard back
docker cp /tmp/wazuh_dash_update.json sg-grafana:/tmp/wazuh_dash_update.json
docker exec sg-grafana sh -c "
curl -s -X POST http://localhost:3000/api/dashboards/db \
  -u '${GRAFANA_USER}:${GRAFANA_PASS}' \
  -H 'Content-Type: application/json' \
  -d @/tmp/wazuh_dash_update.json
"

echo ""
echo "Wazuh token + panel header refreshed at $(date)"
