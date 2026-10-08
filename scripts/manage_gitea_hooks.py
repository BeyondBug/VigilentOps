"""Plan/apply private Jenkins hook credentials, or retry failed scans on Kali."""

import argparse
import json
import ssl
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

from configure_gateway import read_env
from gateway_client import fetch_json


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise ValueError('Gitea API redirects are refused to protect private credentials')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--apply", action="store_true", help="Update matching Jenkins hooks")
    parser.add_argument("--test", action="store_true", help="Trigger accepted-branch test deliveries")
    parser.add_argument("--failed-only", action="store_true", help="Select latest failed target scans")
    options = parser.parse_args()
    env = read_env(options.env)
    base = env["PUBLIC_URL"].rstrip("/")
    origin = urlparse(base)
    if (origin.scheme != 'https' or not origin.hostname or origin.port != 3000
            or origin.username or origin.password or origin.path or origin.query or origin.fragment):
        raise ValueError('PUBLIC_URL must be the HTTPS gateway origin on port 3000')
    settings = json.loads(Path("secrets/jenkins/bootstrap.json").read_text())
    context = ssl.create_default_context(cafile="secrets/gateway/ca.pem")
    opener = build_opener(HTTPSHandler(context=context), NoRedirect())

    def api(path, method="GET", body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        token = env.get("GITEA_TOKEN", "").strip()
        if token and token != "your_gitea_personal_access_token":
            headers["Authorization"] = "token " + token
        else:
            raise ValueError('Configure a private GITEA_TOKEN before managing hooks')
            
        request = Request(base + "/api/v1/" + path, method=method, data=data, headers=headers)
        with opener.open(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else None

    latest = {}
    if options.failed_only:
        scans = fetch_json(base + "/dashboard/api/scans?limit=500&summary_only=true",
                           env_path=options.env)
        for scan in scans:
            key = urlparse(scan.get("repo_url", "")).path.removesuffix(".git").strip("/")
            branch_key = (key, scan.get('branch'))
            if branch_key not in latest or scan["id"] > latest[branch_key]["id"]:
                latest[branch_key] = scan
    page = 1
    while True:
        repos = api(f"user/repos?limit=100&page={page}")
        for repo in repos:
            name = repo["full_name"]
            branch = repo["default_branch"]
            if options.failed_only and latest.get((name, branch), {}).get("status") != "failed":
                continue
            if branch not in {"main", "develop", "master"}:
                print(f"{name}: skipped (default branch is outside pipeline scope)")
                continue
            path = "repos/" + quote(name, safe="/") + "/hooks"
            hooks = api(path + "?limit=100")
            matches = [hook for hook in hooks if hook.get("active") and "push" in hook.get("events", [])
                       and urlparse(hook.get("config", {}).get("url", "")).path
                       in {"/generic-webhook-trigger/invoke", "/jenkins/generic-webhook-trigger/invoke"}]
            if len(matches) != 1:
                raise ValueError(f"{name}: expected exactly one active Jenkins push hook")
            hook = matches[0]
            config = dict(hook["config"])
            parsed = urlparse(config["url"])
            if parsed.hostname not in {"sg-jenkins", "jenkins", "172.18.0.100"} or parsed.username or parsed.password:
                raise ValueError(f"{name}: Jenkins hook is outside the private Docker hosts")
            query = [(key, value) for key, value in parse_qsl(parsed.query) if key.lower() != "token"]
            query.append(("token", settings["webhook_token"]))
            config["url"] = urlunparse(("http", "sg-jenkins:8080", "/jenkins/generic-webhook-trigger/invoke",
                                       "", urlencode(query), ""))
            if options.apply:
                api(path + "/" + str(hook["id"]), "PATCH", {
                    "config": config, "active": True, "events": hook["events"],
                })
            print(f"{name}: {'updated' if options.apply else 'planned'} private Jenkins hook")
            if options.test:
                api(path + "/" + str(hook["id"]) + "/tests?ref="
                    + quote("refs/heads/" + branch, safe=""), "POST")
                print(f"{name}: test delivery queued for {branch}; verify build/scan result separately")
        if len(repos) < 100:
            break
        page += 1


if __name__ == "__main__":
    main()
