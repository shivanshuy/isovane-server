"""Optional API-key auth. Enabled when ISOVANE_API_KEY is set."""

from __future__ import annotations

import os
import secrets

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

_EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}


def configured_api_key() -> str | None:
    key = os.environ.get("ISOVANE_API_KEY", "").strip()
    return key or None


def extract_api_key(request: Request) -> str | None:
    header = request.headers.get("x-api-key")
    if header and header.strip():
        return header.strip()
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return None


class ApiKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        expected = configured_api_key()
        if expected is None:
            return await call_next(request)
        path = request.url.path
        if path in _EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)
        provided = extract_api_key(request)
        if not provided or not secrets.compare_digest(provided, expected):
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized — provide X-Api-Key or Authorization: Bearer"},
            )
        return await call_next(request)
