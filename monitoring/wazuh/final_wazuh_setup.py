import json
import subprocess

GRAFANA_USER = "admin"
GRAFANA_PASS = "VR@b3y0nd"
DASH_UID = "secureguard-unified"

# Fresh token
result = subprocess.run(
    ["curl", "-sk", "-u", "wazuh:wazuh", "-X", "POST",
     "https://localhost:55000/security/user/authenticate"],
    capture_output=True, text=True
)
token = json.loads(result.stdout)["data"]["token"]
print("Got fresh token")

# Pull current dashboard ONCE
pull = subprocess.run(
    ["docker", "exec", "sg-grafana", "sh", "-c",
     "curl -s http://localhost:3000/api/dashboards/uid/" + DASH_UID +
     " -u '" + GRAFANA_USER + ":" + GRAFANA_PASS + "'"],
    capture_output=True, text=True
)
data = json.loads(pull.stdout)
dash = data["dashboard"]

# Remove old 99 and 100, we'll re-add both fresh
dash["panels"] = [p for p in dash["panels"] if p.get("id") not in (99, 100)]

cve_panel = {
    "id": 99,
    "type": "table",
    "title": "CVEs Matched & Fixed by AI Engine",
    "gridPos": {"x": 0, "y": 51, "w": 24, "h": 8},
    "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
    "fieldConfig": {"defaults": {"custom": {"align": "left"}}},
    "targets": [{
        "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
        "expr": "secureguard_cve_fixed_total",
        "instant": True,
        "format": "table"
    }],
    "transformations": [{
        "id": "organize",
        "options": {
            "renameByName": {"cve_id": "CVE", "package": "Package/File", "severity": "Severity", "Value": "Times Fixed"},
            "excludeByName": {"__name__": True, "Time": True, "instance": True, "job": True}
        }
    }]
}

wazuh_panel = {
    "id": 100,
    "type": "gauge",
    "title": "Wazuh SCA Compliance",
    "gridPos": {"x": 0, "y": 59, "w": 24, "h": 8},
    "datasource": {"type": "yesoreyeram-infinity-datasource", "uid": "efqke9w9a1xxcb"},
    "fieldConfig": {
        "defaults": {
            "min": 0, "max": 100, "unit": "short",
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {"color": "red", "value": None},
                    {"color": "yellow", "value": 50},
                    {"color": "green", "value": 75}
                ]
            }
        },
        "overrides": []
    },
    "options": {
        "showThresholdLabels": False,
        "showThresholdMarkers": True,
        "orientation": "auto",
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True}
    },
    "targets": [{
        "refId": "A",
        "datasource": {"type": "yesoreyeram-infinity-datasource", "uid": "efqke9w9a1xxcb"},
        "type": "json",
        "source": "url",
        "format": "table",
        "url": "https://sg-wazuh:55000/sca/000",
        "root_selector": "data.affected_items",
        "columns": [],
        "filters": [],
        "computed_columns": [],
        "url_options": {
            "method": "GET",
            "data": "",
            "headers": [{"key": "Authorization", "value": "Bearer " + token}],
            "params": []
        },
        "parser": "backend"
    }]
}

dash["panels"].append(cve_panel)
dash["panels"].append(wazuh_panel)

payload = {
    "dashboard": dash,
    "overwrite": True,
    "folderUid": data.get("meta", {}).get("folderUid", "secureguard")
}

with open("/tmp/final_wazuh_setup.json", "w") as f:
    json.dump(payload, f)

print("Total panels:", len(dash["panels"]))
