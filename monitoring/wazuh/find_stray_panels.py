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

print("All panels:")
for p in data["dashboard"]["panels"]:
    gp = p.get("gridPos", {})
    y = gp.get("y", 0)
    flag = "  <-- STRAY" if y > 100 else ""
    print("id=%s y=%s h=%s title=%s%s" % (p.get("id"), y, gp.get("h"), p.get("title"), flag))
