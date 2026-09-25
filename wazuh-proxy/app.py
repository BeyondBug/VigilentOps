"""
Wazuh Auth Proxy
─────────────────
Sits between Grafana and the Wazuh API.
Grafana hits this proxy with NO auth header.
This proxy fetches a fresh Wazuh JWT (cached for 14 min), attaches it,
and forwards the request to the real Wazuh API.
"""

import os
import re
import ssl
import time
import httpx
from fastapi import FastAPI, HTTPException, Request, Response
import uvicorn

app = FastAPI(title="Wazuh Auth Proxy")

WAZUH_URL  = os.getenv("WAZUH_URL", "https://sg-wazuh:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASS = os.getenv("WAZUH_PASS", "")
WAZUH_CA_CERT = os.getenv("WAZUH_CA_CERT", "/etc/wazuh/certs/api.crt")

if not WAZUH_PASS:
    raise RuntimeError("WAZUH_PASS must be configured")

# The bundled Wazuh API certificate is self-signed and has only localhost in
# its SAN. Trust this exact certificate as a local CA; the proxy reaches it by
# its Compose hostname, so hostname checking cannot be used with that cert.
# Replace the certificate and enable hostname checking when the API is issued
# a certificate with a matching DNS SAN.
TLS_CONTEXT = ssl.create_default_context(cafile=WAZUH_CA_CERT)
TLS_CONTEXT.check_hostname = False

_token_cache = {"token": None, "expires_at": 0}


def get_fresh_token() -> str:
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"]:
        return _token_cache["token"]
    r = httpx.post(
        f"{WAZUH_URL}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=TLS_CONTEXT,
        timeout=15,
    )
    r.raise_for_status()
    token = r.json()["data"]["token"]
    _token_cache["token"]      = token
    _token_cache["expires_at"] = now + (14 * 60)
    return token


# ── Health check ───────────────────────────────────────────────
@app.get("/_proxy_health")
async def health():
    try:
        token = get_fresh_token()
        return {"status": "ok", "token_cached": bool(token)}
    except Exception:
        raise HTTPException(status_code=503, detail="Wazuh authentication unavailable")


# ── Read-only SCA proxy for Grafana ────────────────────────────
@app.get("/sca/{agent_id}")
async def proxy(agent_id: str, request: Request):
    if not re.fullmatch(r"[0-9]{1,12}", agent_id):
        raise HTTPException(status_code=404, detail="Unknown endpoint")
    token  = get_fresh_token()
    url    = f"{WAZUH_URL}/sca/{agent_id}"
    params = dict(request.query_params)

    async with httpx.AsyncClient(verify=TLS_CONTEXT, timeout=30) as client:
        resp = await client.request(
            "GET",
            url,
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)  # nosec B104: Docker peers need this bind.
