import json
import subprocess

GRAFANA_USER = "admin"
GRAFANA_PASS = "VR@b3y0nd"
DASH_UID = "secureguard-unified"

# Get a fresh token first
result = subprocess.run(
    ["curl", "-sk", "-u", "wazuh:wazuh", "-X", "POST",
     "https://localhost:55000/security/user/authenticate"],
    capture_output=True, text=True
)
token = json.loads(result.stdout)["data"]["token"]
print("Got fresh token")

# Pull current dashboard
pull = subprocess.run(
    ["docker", "exec", "sg-grafana", "sh", "-c",
     f"curl -s http://localhost:3000/api/dashboards/uid/{DASH_UID} -u '{GRAFANA_USER}:{GRAFANA_PASS}'"],
    capture_output=True, text=True
)
data = json.loads(pull.stdout)
dash = data["dashboard"]

# Remove any leftover panel 100 just in case, then re-add cleanly
dash["panels"] = [p for p in dash["panels"] if p.get("id") != 100]

wazuh_panel = {
    "id": 100,
    "type": "gauge",
    "title": "wazuh",
    "gridPos": {"x": 0, "y": 1000, "w": 24, "h": 8},
    "datasource": {"type": "yesoreyeram-infinity-datasource", "uid": "efqke9w9a1xxcb"},
    "fieldConfig": {
        "defaults": {
            "min": 0,
            "max": 100,
            "thresholds": {
                "steps": [
                    {"color": "red", "value": None},
                    {"color": "yellow", "value": 50},
                    {"color": "green", "value": 75}
                ]
            }
        }
    },
    "options": {
        "showThresholdLabels": False,
        "showThresholdMarkers": True,
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True}
    },
    "targets": [
        {
            "refId": "A",
            "datasource": {"type": "yesoreyeram-infinity-datasource", "uid": "efqke9w9a1xxcb"},
            "type": "json",
            "source": "url",
            "format": "table",
            "url": "https://sg-wazuh:55000/sca/000",
            "root_selector": "data.affected_items",
            "url_options": {
                "method": "GET",
                "data": "",
                "headers": [
                    {"key": "Authorization", "value": f"Bearer {token}"}
                ]
            },
            "parser": "backend"
        }
    ]
}

dash["panels"].append(wazuh_panel)

payload = {
    "dashboard": dash,
    "overwrite": True,
    "folderUid": data.get("meta", {}).get("folderUid", "secureguard")
}

with open("/tmp/add_wazuh_panel.json", "w") as f:
    json.dump(payload, f)

print(f"Total panels now: {len(dash['panels'])}")
print("Saved payload to /tmp/add_wazuh_panel.json")
