import json
import subprocess

GRAFANA_USER = "admin"
GRAFANA_PASS = "VR@b3y0nd"
DASH_UID = "secureguard-unified"

pull = subprocess.run(
    ["docker", "exec", "sg-grafana", "sh", "-c",
     f"curl -s http://localhost:3000/api/dashboards/uid/{DASH_UID} -u '{GRAFANA_USER}:{GRAFANA_PASS}'"],
    capture_output=True, text=True
)
data = json.loads(pull.stdout)
dash = data["dashboard"]

# Find the max Y among panels EXCLUDING panel 100 itself
max_y = 0
for p in dash["panels"]:
    if p.get("id") == 100:
        continue
    gp = p.get("gridPos", {})
    bottom = gp.get("y", 0) + gp.get("h", 0)
    if bottom > max_y:
        max_y = bottom

print(f"Real max_y excluding panel 100: {max_y}")

# Reposition panel 100 to sit right after that
for p in dash["panels"]:
    if p.get("id") == 100:
        p["gridPos"] = {"x": 0, "y": max_y, "w": 24, "h": 8}
        print("Repositioned panel 100 to y =", max_y)

payload = {
    "dashboard": dash,
    "overwrite": True,
    "folderUid": data.get("meta", {}).get("folderUid", "secureguard")
}

with open("/tmp/fix_wazuh_position.json", "w") as f:
    json.dump(payload, f)
