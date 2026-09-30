"""Use the private lab CA and gateway login for server-side read-only tools."""

import json
import ssl
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import (
    HTTPSHandler, HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm,
    HTTPRedirectHandler, Request, build_opener,
)

from configure_gateway import read_env


class CredentialRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urlparse(req.full_url), urlparse(newurl)
        if req.has_header("Authorization") and (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise ValueError("Refusing to forward authentication to another origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_json(url, token="", env_path=Path(".env"), timeout=30):
    values = read_env(env_path) if env_path.exists() else {}
    ca = Path("secrets/gateway/ca.pem")
    context = ssl.create_default_context(cafile=str(ca) if ca.exists() else None)
    handlers = [HTTPSHandler(context=context), CredentialRedirectHandler()]
    parsed = urlparse(url)
    public = urlparse(values.get("PUBLIC_URL", ""))
    allowed_origins = {(public.scheme, public.netloc), ("https", "localhost:3000"), ("https", "127.0.0.1:3000")}
    protected_prefix = next((prefix for prefix in ('/dashboard/', '/jenkins/', '/prometheus/')
                             if parsed.path.startswith(prefix)), None)
    if (not token and (parsed.scheme, parsed.netloc) in allowed_origins
            and parsed.scheme == "https" and protected_prefix
            and values.get("PROXY_AUTH_PASSWORD")):
        passwords = HTTPPasswordMgrWithDefaultRealm()
        passwords.add_password(None, f"{parsed.scheme}://{parsed.netloc}{protected_prefix}",
                               values.get("PROXY_AUTH_USER", "secureguard"), values["PROXY_AUTH_PASSWORD"])
        handlers.append(HTTPBasicAuthHandler(passwords))
    request = Request(url, headers={"Authorization": f"token {token}"} if token else {})
    with build_opener(*handlers).open(request, timeout=timeout) as response:
        return json.load(response)
