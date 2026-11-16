"""Bearer-authenticated HTTP gateway for the remote demo server."""

from __future__ import annotations

import hmac
import os

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response

_UPSTREAM = "http://127.0.0.1:8000/generate"
_MAX_REQUEST_BYTES = 64 * 1024

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/generate")
async def generate(
    request: Request,
    authorization: str | None = Header(default=None),
) -> Response:
    token = os.environ.get("ARGUS_GTC_AGENT_TOKEN", "")
    expected = f"Bearer {token}"
    if not token or not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="invalid agent token")

    body = await request.body()
    if len(body) > _MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail="request is too large")

    try:
        async with httpx.AsyncClient(timeout=110.0) as client:
            upstream = await client.post(
                _UPSTREAM,
                content=body,
                headers={"Content-Type": request.headers.get("content-type", "application/json")},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="agent runtime is unavailable") from exc

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "application/json"),
    )
