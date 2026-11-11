"""Extract analyzable architecture text from diagram images via Ollama / OpenAI vision."""

from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from isovane_serve.model_config import (
    active_provider,
    arc_image_extract_model,
    load_model_config,
    openai_api_key,
)

log = logging.getLogger("isovane.vision_diagram")

VISION_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}

_EXTRACT_PROMPT = """You are reconstructing a software / AI-agent architecture diagram from an image.

Goal: recreate the diagram as faithfully as possible as boxes + arrows (labels, kinds, connections, rough layout).
A human will then fix any extraction mistakes and later change the diagram to remediate security issues.

Return ONLY this structure (no markdown fences):

DIAGRAM:
- One edge per line: A --> B
- Name every box/cloud/cylinder/actor you can read (UI, agents, MCP, tools, DBs, LLM vendors, logs, HITL)
- Preserve exact readable words: OpenAI, Anthropic, Bedrock, PII, HITL, MCP, shell, refund, email, RAG, vector, ZDR

NODES:
- bullet list of every component label (same wording as on the image when readable)

TRUST / NOTES:
- bullets only for what the drawing implies (missing HITL, multi-cloud, PII egress, untrusted ingress, wildcard tools, observability sinks)

GRAPH_JSON:
{"nodes":[{"id":"ui1","label":"Chat UI","kind":"ui","x":40,"y":40},{"id":"agent1","label":"Orchestrator agent","kind":"agent","x":220,"y":40}],"edges":[{"from":"ui1","to":"agent1","kind":"link"}]}

Rules for GRAPH_JSON (highest priority):
- recreate topology first: every visible box and every visible arrow
- kind must be one of: ui, agent, mcp, tool, llm, data, hitl, unknown
- ids: short stable tokens, no spaces
- label: closest readable text from the image (do not invent brands that are not shown)
- x,y: approximate left-to-right / top-to-bottom canvas coords in pixels (origin top-left, x+=180 per column, y+=96 per row)
- if a label is blurry, still emit a best-effort node rather than dropping it
"""


class VisionDiagramError(RuntimeError):
    """Vision provider failed to extract diagram text."""


def mime_for_filename(filename: str) -> str:
    ext = Path(filename or "").suffix.lower()
    return {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
    }.get(ext, "image/png")


def extract_diagram_text_from_image(
    data: bytes,
    filename: str,
    *,
    provider: str | None = None,
) -> dict[str, Any]:
    """Call the configured vision model and return extracted text + metadata."""
    if not data:
        raise VisionDiagramError("Empty image upload.")
    ext = Path(filename or "").suffix.lower()
    if ext not in VISION_IMAGE_EXTENSIONS:
        raise VisionDiagramError(
            f"Vision extract supports PNG/JPG/WebP/GIF/BMP, not '{ext or 'unknown'}'."
        )

    chosen = (provider or active_provider()).strip().lower()
    model = arc_image_extract_model()
    b64 = base64.b64encode(data).decode("ascii")
    mime = mime_for_filename(filename)

    if chosen == "openai":
        text = _extract_openai(b64, mime, model)
    else:
        text = _extract_ollama(b64, model)

    cleaned = (text or "").strip()
    if not cleaned:
        raise VisionDiagramError(f"{chosen} returned empty diagram text.")
    return {
        "text": cleaned,
        "provider": chosen,
        "model": model,
        "filename": filename,
    }


def _post_json(url: str, payload: dict[str, Any], *, headers: dict[str, str], timeout: int) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:800]
        raise VisionDiagramError(f"HTTP {exc.code} from {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise VisionDiagramError(f"Could not reach {url}: {exc.reason}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise VisionDiagramError(f"Non-JSON response from {url}") from exc
    if not isinstance(data, dict):
        raise VisionDiagramError(f"Unexpected JSON shape from {url}")
    return data


def _extract_ollama(image_b64: str, model: str) -> str:
    cfg = load_model_config()["ollama"]
    url = f"{cfg['base_url']}/api/chat"
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {
                "role": "user",
                "content": _EXTRACT_PROMPT,
                "images": [image_b64],
            }
        ],
    }
    data = _post_json(url, payload, headers={}, timeout=int(cfg["timeout_seconds"]))
    message = data.get("message") if isinstance(data.get("message"), dict) else {}
    content = message.get("content") or data.get("response") or ""
    return str(content)


def _extract_openai(image_b64: str, mime: str, model: str) -> str:
    key = openai_api_key()
    if not key:
        raise VisionDiagramError(
            "OpenAI provider selected but no API key. Set OPENAI_API_KEY or ISOVANE_OPENAI_API_KEY."
        )
    cfg = load_model_config()["openai"]
    url = f"{cfg['base_url']}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": _EXTRACT_PROMPT},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime};base64,{image_b64}"},
                    },
                ],
            }
        ],
    }
    data = _post_json(
        url,
        payload,
        headers={"Authorization": f"Bearer {key}"},
        timeout=int(cfg["timeout_seconds"]),
    )
    choices = data.get("choices") or []
    if not choices:
        raise VisionDiagramError("OpenAI returned no choices.")
    message = (choices[0] or {}).get("message") or {}
    return str(message.get("content") or "")
