import json, subprocess

GRAFANA_USER = "admin"
GRAFANA_PASS = "VR@b3y0nd"
DASH_UID = "secureguard-unified"

token = json.loads(subprocess.run(
    ["curl", "-sk", "-u", "wazuh:wazuh", "-X", "POST",
     "https://localhost:55000/security/user/authenticate"],
    capture_output=True, text=True).stdout)["data"]["token"]

pull = subprocess.run(
    ["docker", "exec", "sg-grafana", "sh", "-c",
     "curl -s http://localhost:3000/api/dashboards/uid/" + DASH_UID +
     " -u '" + GRAFANA_USER + ":" + GRAFANA_PASS + "'"],
    capture_output=True, text=True)
data = json.loads(pull.stdout)
dash = data["dashboard"]

changed = False
for p in dash["panels"]:
    if p.get("id") == 100:
        for t in p.get("targets", []):
            for h in t.get("url_options", {}).get("headers", []):
                if h.get("key") == "Authorization":
                    h["value"] = "Bearer " + token
                    changed = True

if not changed:
    print("Panel 100 header not found - skipping save")
else:
    payload = {"dashboard": dash, "overwrite": True,
               "folderUid": data.get("meta", {}).get("folderUid", "secureguard")}
    with open("/tmp/safe_refresh.json", "w") as f:
        json.dump(payload, f)
    subprocess.run(["docker", "cp", "/tmp/safe_refresh.json", "sg-grafana:/tmp/safe_refresh.json"])
    push = subprocess.run(
        ["docker", "exec", "sg-grafana", "sh", "-c",
         "curl -s -X POST http://localhost:3000/api/dashboards/db -u '" +
         GRAFANA_USER + ":" + GRAFANA_PASS +
         "' -H 'Content-Type: application/json' -d @/tmp/safe_refresh.json"],
        capture_output=True, text=True)
    print(push.stdout)
print("Done")
