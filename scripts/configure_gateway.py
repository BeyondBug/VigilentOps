"""Prepare private TLS and gateway credentials on the Linux deployment server."""

import argparse
import ipaddress
import os
import re
import secrets
import subprocess
from pathlib import Path
from urllib.parse import urlparse


def read_env(path):
    values = {}
    for line in path.read_text().splitlines():
        if line and not line.lstrip().startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip("\"'")
    return values


def update_env(path, changes):
    lines = path.read_text().splitlines()
    updated = set()
    for number, line in enumerate(lines):
        key = line.partition("=")[0]
        if key in changes:
            lines[number] = f"{key}={changes[key]}"
            updated.add(key)
    lines += [f"{key}={value}" for key, value in changes.items() if key not in updated]
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o600)


def openssl(*args, stdin=None):
    result = subprocess.run(
        ["openssl", *map(str, args)], input=stdin, text=True,
        capture_output=True, check=True,
    )
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-url", required=True, help="https://server-address:3000")
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--directory", type=Path, default=Path("secrets/gateway"))
    args = parser.parse_args()
    parsed = urlparse(args.public_url)
    if (parsed.scheme != "https" or parsed.port != 3000 or not parsed.hostname
            or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        parser.error("Use an HTTPS origin on port 3000 with no path or credentials")
    host = parsed.hostname
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
        parser.error("Unsupported server hostname")
    os.umask(0o077)
    args.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    values = read_env(args.env)
    username = values.get("PROXY_AUTH_USER") or "secureguard"
    password = values.get("PROXY_AUTH_PASSWORD") or secrets.token_urlsafe(32)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username) or any(c in password for c in "\r\n"):
        parser.error("Invalid proxy username or password")
    directory = args.directory.resolve()
    ca_key, ca_cert = directory / "ca-key.pem", directory / "ca.pem"
    if ca_key.exists() != ca_cert.exists():
        parser.error("Incomplete existing CA; recover its matching certificate and key first")
    if not ca_cert.exists():
        openssl("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256",
                "-days", "3650", "-subj", "/CN=VigilentOps Lab CA",
                "-keyout", ca_key, "-out", ca_cert,
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    try:
        ipaddress.ip_address(host)
        host_san = f"IP:{host}"
    except ValueError:
        host_san = f"DNS:{host}"
    ext = directory / "server.ext"
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName={host_san},DNS:localhost,DNS:sg-gateway,IP:127.0.0.1\n"
    )
    server_key, csr, server_cert = (
        directory / "server-key.pem", directory / "server.csr", directory / "server.pem"
    )
    openssl("req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256",
            "-subj", "/CN=VigilentOps Gateway", "-keyout", server_key, "-out", csr)
    openssl("x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
            "-CAcreateserial", "-days", "365", "-sha256", "-extfile", ext, "-out", server_cert)
    (directory / "fullchain.pem").write_text(server_cert.read_text() + ca_cert.read_text())
    hashed = openssl("passwd", "-6", "-stdin", stdin=password + "\n").strip()
    (directory / "htpasswd").write_text(f"{username}:{hashed}\n")
    update_env(args.env, {
        "PUBLIC_URL": args.public_url.rstrip("/"),
        "PROXY_AUTH_USER": username,
        "PROXY_AUTH_PASSWORD": password,
    })
    # The host directory stays private. Nginx workers must read the mounted
    # password hashes; the TLS private key is read only by the root master.
    for path in (ca_cert, server_cert, directory / "fullchain.pem", directory / "htpasswd"):
        path.chmod(0o644)
    print(f"Gateway configured for {args.public_url.rstrip('/')}")
    print(f"Dashboard/Prometheus username: {username}; password stored only in {args.env}")
    print(f"Trust the public CA certificate: {ca_cert}")
    print("Private keys and htpasswd stay in the ignored secrets/gateway directory.")


if __name__ == "__main__":
    main()
