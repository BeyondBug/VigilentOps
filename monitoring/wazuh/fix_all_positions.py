import json
import subprocess

GRAFANA_USER = "admin"
GRAFANA_PASS = "VR@b3y0nd"
DASH_UID = "secureguard-unified"

pull = subprocess.run(
    ["docker", "exec", "sg-grafana", "sh", "-c",
     "curl -s http://localhost:3000/api/dashboards/uid/" + DASH_UID +
     " -u '" + GRAFANA_USER + ":" + GRAFANA_PASS + "'"],
    capture_output=True, text=True
)
data = json.loads(pull.stdout)
dash = data["dashboard"]

for p in dash["panels"]:
    if p.get("id") == 99:
        p["gridPos"] = {"x": 0, "y": 51, "w": 24, "h": 8}
        print("Fixed panel 99 -> y=51")
    if p.get("id") == 100:
        p["gridPos"] = {"x": 0, "y": 59, "w": 24, "h": 8}
        print("Fixed panel 100 -> y=59")

payload = {
    "dashboard": dash,
    "overwrite": True,
    "folderUid": data.get("meta", {}).get("folderUid", "secureguard")
}

with open("/tmp/fix_all_positions.json", "w") as f:
    json.dump(payload, f)
