"""
Wazuh Auth Proxy
─────────────────
Sits between Grafana and the Wazuh API.
Grafana hits this proxy with NO auth header.
This proxy fetches a fresh Wazuh JWT (cached for 14 min), attaches it,
and forwards the request to the real Wazuh API.
"""

import os
import time
import httpx
from fastapi import FastAPI, Request, Response
import uvicorn

app = FastAPI(title="Wazuh Auth Proxy")

WAZUH_URL  = os.getenv("WAZUH_URL", "https://sg-wazuh:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASS = os.getenv("WAZUH_PASS", "wazuh")

_token_cache = {"token": None, "expires_at": 0}


def get_fresh_token() -> str:
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"]:
        return _token_cache["token"]
    r = httpx.post(
        f"{WAZUH_URL}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    token = r.json()["data"]["token"]
    _token_cache["token"]      = token
    _token_cache["expires_at"] = now + (14 * 60)
    return token


# ── Health check MUST come before the wildcard route ─────────
@app.get("/_proxy_health")
async def health():
    try:
        token = get_fresh_token()
        return {"status": "ok", "token_cached": bool(token)}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ── Wildcard proxy — catches everything else ──────────────────
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(path: str, request: Request):
    token  = get_fresh_token()
    url    = f"{WAZUH_URL}/{path}"
    params = dict(request.query_params)
    body   = await request.body()

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.request(
            request.method,
            url,
            params=params,
            content=body if body else None,
            headers={"Authorization": f"Bearer {token}"},
        )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
