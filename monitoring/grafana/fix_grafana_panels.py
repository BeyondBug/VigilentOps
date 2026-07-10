"""
fix_grafana_panels.py
─────────────────────
Fixes all Grafana dashboard issues in one pass:
1. Moves panel 99 (CVEs) from y=1000 to y=51
2. Updates Wazuh SCA panel to use proxy URL (no auth needed)
3. Adds Wazuh Loki log panel
4. Saves as provisioned file so it survives restarts

Run from: ~/secureguard/
  python3 monitoring/grafana/fix_grafana_panels.py
"""
import json
import subprocess

GRAFANA_USER = "admin"
GRAFANA_PASS = "VR@b3y0nd"
DASH_UID     = "secureguard-unified"
PROXY_URL    = "http://sg-wazuh-proxy:8002"

# ── Pull live dashboard ───────────────────────────────────────
print("Pulling live dashboard...")
pull = subprocess.run(
    ["docker", "exec", "sg-grafana", "sh", "-c",
     f"curl -s http://localhost:3000/api/dashboards/uid/{DASH_UID} "
     f"-u '{GRAFANA_USER}:{GRAFANA_PASS}'"],
    capture_output=True, text=True
)
data = json.loads(pull.stdout)
dash = data["dashboard"]
meta = data.get("meta", {})

# ── Remove stray/broken panels (99, 100) and rebuild ─────────
dash["panels"] = [p for p in dash["panels"]
                  if p.get("id") not in (99, 100)]

# Find max Y of remaining panels
max_y = max(
    p.get("gridPos", {}).get("y", 0) + p.get("gridPos", {}).get("h", 0)
    for p in dash["panels"]
)
print(f"Max Y of existing panels: {max_y}")

# ── Panel 99: CVEs Fixed by AI Engine (Prometheus table) ─────
panel_cve = {
    "id":    99,
    "type":  "table",
    "title": "CVEs Matched & Fixed by AI Engine",
    "description": "CVEs detected and auto-fixed by SecureGuard AI per scan run",
    "gridPos": {"x": 0, "y": max_y, "w": 24, "h": 8},
    "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
    "fieldConfig": {
        "defaults": {"custom": {"align": "left"}},
        "overrides": [
            {
                "matcher": {"id": "byName", "options": "severity"},
                "properties": [
                    {"id": "custom.displayMode", "value": "color-background"},
                    {"id": "mappings", "value": [
                        {"type": "value", "options": {
                            "CRITICAL": {"color": "red"},
                            "HIGH":     {"color": "orange"},
                            "MEDIUM":   {"color": "yellow"},
                        }}
                    ]}
                ]
            }
        ]
    },
    "options": {
        "footer": {"show": False},
        "sortBy": [{"displayName": "Value", "desc": True}]
    },
    "targets": [
        {
            "datasource": {"type": "prometheus", "uid": "PBFA97CFB590B2093"},
            "expr":       'secureguard_cve_fixed_total',
            "instant":    True,
            "format":     "table",
            "refId":      "A",
            "legendFormat": ""
        }
    ],
    "transformations": [
        {
            "id": "organize",
            "options": {
                "renameByName": {
                    "cve_id":  "CVE ID",
                    "package": "Package / File",
                    "severity":"Severity",
                    "Value":   "Times Fixed",
                    "job":     "Service"
                },
                "excludeByName": {
                    "__name__": True,
                    "Time":     True,
                    "instance": True
                }
            }
        }
    ]
}

# ── Panel 100: Wazuh SCA Compliance (via proxy — no auth) ────
panel_wazuh_sca = {
    "id":    100,
    "type":  "gauge",
    "title": "Wazuh SCA Compliance — CIS Ubuntu 20.04",
    "description": "Score from Wazuh SCA scan via auth proxy (no token refresh needed)",
    "gridPos": {"x": 0, "y": max_y + 8, "w": 12, "h": 8},
    "datasource": {"type": "yesoreyeram-infinity-datasource", "uid": "efqke9w9a1xxcb"},
    "fieldConfig": {
        "defaults": {
            "min": 0, "max": 100, "unit": "short",
            "displayName": "${__field.labels.policy_id}",
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {"color": "red",    "value": None},
                    {"color": "yellow", "value": 50},
                    {"color": "green",  "value": 75},
                ]
            }
        },
        "overrides": []
    },
    "options": {
        "showThresholdLabels":  False,
        "showThresholdMarkers": True,
        "orientation":          "auto",
        "reduceOptions":        {"calcs": ["lastNotNull"], "values": True}
    },
    "targets": [
        {
            "refId":      "A",
            "datasource": {"type": "yesoreyeram-infinity-datasource",
                           "uid":  "efqke9w9a1xxcb"},
            "type":          "json",
            "source":        "url",
            "format":        "table",
            "url":           f"{PROXY_URL}/sca/000",
            "root_selector": "data.affected_items",
            "columns": [
                {"selector": "policy_id", "text": "Policy",   "type": "string"},
                {"selector": "score",     "text": "Score",    "type": "number"},
                {"selector": "pass",      "text": "Pass",     "type": "number"},
                {"selector": "fail",      "text": "Fail",     "type": "number"},
                {"selector": "total_checks", "text": "Total", "type": "number"},
            ],
            "url_options": {
                "method":  "GET",
                "data":    "",
                "headers": [],
                "params":  []
            },
            "filters":          [],
            "computed_columns": [],
            "parser":           "backend"
        }
    ]
}

# ── Panel 101: Wazuh SCA Details table ───────────────────────
panel_wazuh_detail = {
    "id":    101,
    "type":  "table",
    "title": "Wazuh SCA Details",
    "gridPos": {"x": 12, "y": max_y + 8, "w": 12, "h": 8},
    "datasource": {"type": "yesoreyeram-infinity-datasource", "uid": "efqke9w9a1xxcb"},
    "fieldConfig": {
        "defaults": {"custom": {"align": "left"}},
        "overrides": [
            {
                "matcher": {"id": "byName", "options": "Score"},
                "properties": [
                    {"id": "custom.displayMode", "value": "color-background"},
                    {"id": "thresholds", "value": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "red",    "value": None},
                            {"color": "yellow", "value": 50},
                            {"color": "green",  "value": 75},
                        ]
                    }}
                ]
            }
        ]
    },
    "options": {"footer": {"show": False}},
    "targets": [
        {
            "refId":         "A",
            "datasource":    {"type": "yesoreyeram-infinity-datasource",
                              "uid":  "efqke9w9a1xxcb"},
            "type":          "json",
            "source":        "url",
            "format":        "table",
            "url":           f"{PROXY_URL}/sca/000",
            "root_selector": "data.affected_items",
            "columns": [
                {"selector": "name",        "text": "Policy",  "type": "string"},
                {"selector": "score",       "text": "Score",   "type": "number"},
                {"selector": "pass",        "text": "Pass",    "type": "number"},
                {"selector": "fail",        "text": "Fail",    "type": "number"},
                {"selector": "total_checks","text": "Total",   "type": "number"},
                {"selector": "start_scan",  "text": "Last Scan","type": "string"},
            ],
            "url_options": {"method": "GET", "data": "", "headers": [], "params": []},
            "filters": [], "computed_columns": [], "parser": "backend"
        }
    ]
}

# ── Panel 102: Wazuh Logs from Loki ──────────────────────────
panel_wazuh_logs = {
    "id":    102,
    "type":  "logs",
    "title": "Wazuh Security Alerts — Live Log Stream",
    "description": "Real-time Wazuh alerts via Loki",
    "gridPos": {"x": 0, "y": max_y + 16, "w": 24, "h": 10},
    "datasource": {"type": "loki", "uid": "cfquw2wogvcaod"},
    "options": {
        "showTime":       True,
        "showLabels":     True,
        "showCommonLabels": False,
        "wrapLogMessage": True,
        "prettifyLogMessage": False,
        "enableLogDetails": True,
        "sortOrder":      "Descending",
        "dedupStrategy":  "none"
    },
    "targets": [
        {
            "datasource": {"type": "loki", "uid": "cfquw2wogvcaod"},
            "expr":       '{job="wazuh"}',
            "refId":      "A",
            "legendFormat": ""
        }
    ]
}

# Add all new panels
for p in [panel_cve, panel_wazuh_sca, panel_wazuh_detail, panel_wazuh_logs]:
    dash["panels"].append(p)

print(f"Total panels: {len(dash['panels'])}")

# ── Save to provisioned file ──────────────────────────────────
out_path = "/home/cys15/secureguard/monitoring/grafana/dashboards/secureguard-main.json"
with open(out_path, "w") as f:
    json.dump(dash, f, indent=2)
print(f"Saved to {out_path}")

# ── Also push via API so it's live immediately ────────────────
payload = {
    "dashboard": dash,
    "overwrite": True,
    "folderUid": meta.get("folderUid", "secureguard")
}
with open("/tmp/grafana_fix.json", "w") as f:
    json.dump(payload, f)

subprocess.run(["docker", "cp", "/tmp/grafana_fix.json",
                "sg-grafana:/tmp/grafana_fix.json"], check=True)
push = subprocess.run(
    ["docker", "exec", "sg-grafana", "sh", "-c",
     f"curl -s -X POST http://localhost:3000/api/dashboards/db "
     f"-u '{GRAFANA_USER}:{GRAFANA_PASS}' "
     f"-H 'Content-Type: application/json' "
     f"-d @/tmp/grafana_fix.json"],
    capture_output=True, text=True
)
result = json.loads(push.stdout)
print(f"API push: {result.get('status')} | version: {result.get('version')}")

# ── Copy to Grafana container's dashboard folder ──────────────
subprocess.run(["docker", "cp", out_path,
                "sg-grafana:/var/lib/grafana/dashboards/secureguard-main.json"])
subprocess.run(["docker", "exec", "-u", "root", "sg-grafana",
                "chown", "472:472",
                "/var/lib/grafana/dashboards/secureguard-main.json"])
print("Done. Reload localhost:3002 to see changes.")
