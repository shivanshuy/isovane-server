"""FastAPI: workspace REST and /gates. The LangGraph server is separate."""

from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from isovane_serve.routes import router

app = FastAPI(title="isovane-server", version="0.1.0")

_cors_origins = os.environ.get(
    "CORS_ALLOW_ORIGINS",
    "http://127.0.0.1:5317,http://localhost:5317",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in _cors_origins if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "isovane-server"}


def main() -> None:
    host = os.environ.get("ISOVANE_HOST", "127.0.0.1")
    port = int(os.environ.get("ISOVANE_PORT", "8092"))
    uvicorn.run(
        "isovane_serve.main:app",
        host=host,
        port=port,
        reload=os.environ.get("ISOVANE_RELOAD", "").lower() in ("1", "true", "yes"),
    )
