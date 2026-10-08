"""Prepare private Jenkins accounts and webhook credentials on the lab server."""

import argparse
import json
import os
import re
import secrets
from pathlib import Path

from configure_gateway import read_env


def prepare(env_path=Path(".env"), directory=Path("secrets/jenkins")):
    env = read_env(env_path)
    username = env.get("PROXY_AUTH_USER", "")
    password = env.get("PROXY_AUTH_PASSWORD", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username) or not password:
        raise ValueError("Configure the gateway login before preparing Jenkins security")
    if any(character in password for character in "\r\n"):
        raise ValueError("Invalid gateway password")
    os.umask(0o077)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    config = directory / "bootstrap.json"
    previous = json.loads(config.read_text()) if config.exists() else {}
    values = {
        "admin_user": username,
        "admin_password": password,
        "metrics_user": "sg-metrics",
        "metrics_password": previous.get("metrics_password") or secrets.token_urlsafe(32),
        "webhook_token": previous.get("webhook_token") or secrets.token_urlsafe(48),
    }
    token = env.get('GITEA_TOKEN', '').strip()
    if token and token != 'your_gitea_personal_access_token':
        values['gitea_username'] = env.get('GITEA_GIT_USERNAME', 'oauth2')
        values['gitea_token'] = token
    if username == values["metrics_user"]:
        raise ValueError("Administrator and metrics account must be different")
    config.write_text(json.dumps(values) + "\n")
    config.chmod(0o600)
    metrics = directory / "metrics-password"
    metrics.write_text(values["metrics_password"])
    # Only this file is mounted into Prometheus. Its parent is private on host.
    metrics.chmod(0o644)
    print(f"Private Jenkins bootstrap prepared; administrator: {username}")
    print("Existing webhook/metrics credentials retained; no secrets printed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--directory", type=Path, default=Path("secrets/jenkins"))
    options = parser.parse_args()
    prepare(options.env, options.directory)
