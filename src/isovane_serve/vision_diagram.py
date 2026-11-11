"""Extract analyzable architecture text from diagram images via Ollama / OpenAI vision."""

from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Any

from isovane_serve.http_client import post_json
from isovane_serve.model_config import (
    active_provider,
    arc_image_extract_model,
    load_model_config,
    openai_api_key,
)
from isovane_serve.yaml_config import load_prompts

log = logging.getLogger("isovane.vision_diagram")

VISION_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}


class VisionDiagramError(RuntimeError):
    """Vision provider failed to extract diagram text."""


def _extract_prompt() -> str:
    text = load_prompts().get("vision_extract") or ""
    if not text:
        raise VisionDiagramError(
            "Missing vision_extract prompt in config/prompts.yaml"
        )
    return text


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


def _extract_ollama(image_b64: str, model: str) -> str:
    cfg = load_model_config()["ollama"]
    url = f"{cfg['base_url']}/api/chat"
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {
                "role": "user",
                "content": _extract_prompt(),
                "images": [image_b64],
            }
        ],
    }
    try:
        data = post_json(url, payload, headers={}, timeout=int(cfg["timeout_seconds"]))
    except RuntimeError as exc:
        raise VisionDiagramError(str(exc)) from exc
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
                    {"type": "text", "text": _extract_prompt()},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime};base64,{image_b64}"},
                    },
                ],
            }
        ],
    }
    try:
        data = post_json(
            url,
            payload,
            headers={"Authorization": f"Bearer {key}"},
            timeout=int(cfg["timeout_seconds"]),
        )
    except RuntimeError as exc:
        raise VisionDiagramError(str(exc)) from exc
    choices = data.get("choices") or []
    if not choices:
        raise VisionDiagramError("OpenAI returned no choices.")
    message = (choices[0] or {}).get("message") or {}
    return str(message.get("content") or "")
