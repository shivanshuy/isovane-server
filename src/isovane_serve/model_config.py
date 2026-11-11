"""Load MODEL_PROVIDER + per-provider model names from config/models.yaml."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml

from isovane_serve.paths import MODELS_YAML

Provider = Literal["ollama", "openai"]

_DEFAULT_PATH = MODELS_YAML


def _as_provider(raw: str | None) -> Provider:
    value = (raw or "ollama").strip().lower()
    if value in {"openai", "open_ai", "oai"}:
        return "openai"
    return "ollama"


def _pick(section: dict[str, Any], *keys: str, default: str) -> str:
    for key in keys:
        value = section.get(key)
        if value:
            return str(value)
    return default


@lru_cache(maxsize=4)
def load_model_config(path: str | None = None) -> dict[str, Any]:
    target = Path(path) if path else Path(os.environ.get("ISOVANE_MODELS_CONFIG", str(_DEFAULT_PATH)))
    data: dict[str, Any] = {}
    if target.exists():
        loaded = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            data = loaded

    provider = _as_provider(os.environ.get("ISOVANE_MODEL_PROVIDER") or data.get("MODEL_PROVIDER"))
    ollama = dict(data.get("ollama") or {})
    openai = dict(data.get("openai") or {})

    ollama["base_url"] = (
        os.environ.get("ISOVANE_OLLAMA_BASE_URL")
        or ollama.get("base_url")
        or "http://127.0.0.1:11434"
    ).rstrip("/")
    # New keys + legacy arc_diagram_model alias
    ollama["arc_image_extract"] = (
        os.environ.get("ISOVANE_OLLAMA_ARC_IMAGE_EXTRACT")
        or os.environ.get("ISOVANE_OLLAMA_ARC_DIAGRAM_MODEL")
        or _pick(ollama, "arc_image_extract", "arc_diagram_model", default="llama3.2-vision")
    )
    ollama["arc_image_analyze"] = (
        os.environ.get("ISOVANE_OLLAMA_ARC_IMAGE_ANALYZE")
        or _pick(ollama, "arc_image_analyze", default="llama3.1:8b")
    )
    ollama["timeout_seconds"] = int(
        os.environ.get("ISOVANE_OLLAMA_TIMEOUT")
        or ollama.get("timeout_seconds")
        or 180
    )

    openai["base_url"] = (
        os.environ.get("ISOVANE_OPENAI_BASE_URL")
        or openai.get("base_url")
        or "https://api.openai.com/v1"
    ).rstrip("/")
    openai["arc_image_extract"] = (
        os.environ.get("ISOVANE_OPENAI_ARC_IMAGE_EXTRACT")
        or os.environ.get("ISOVANE_OPENAI_ARC_DIAGRAM_MODEL")
        or _pick(openai, "arc_image_extract", "arc_diagram_model", default="gpt-4o")
    )
    openai["arc_image_analyze"] = (
        os.environ.get("ISOVANE_OPENAI_ARC_IMAGE_ANALYZE")
        or _pick(openai, "arc_image_analyze", default="gpt-4o-mini")
    )
    openai["api_key_env"] = openai.get("api_key_env") or "OPENAI_API_KEY"
    openai["timeout_seconds"] = int(
        os.environ.get("ISOVANE_OPENAI_TIMEOUT")
        or openai.get("timeout_seconds")
        or 120
    )

    return {
        "MODEL_PROVIDER": provider,
        "ollama": ollama,
        "openai": openai,
        "config_path": str(target),
    }


def clear_model_config_cache() -> None:
    load_model_config.cache_clear()


def active_provider() -> Provider:
    return load_model_config()["MODEL_PROVIDER"]  # type: ignore[return-value]


def arc_image_extract_model() -> str:
    cfg = load_model_config()
    provider = cfg["MODEL_PROVIDER"]
    return str(cfg[provider]["arc_image_extract"])


def arc_image_analyze_model() -> str:
    cfg = load_model_config()
    provider = cfg["MODEL_PROVIDER"]
    return str(cfg[provider]["arc_image_analyze"])


def openai_api_key() -> str | None:
    cfg = load_model_config()
    env_name = str(cfg["openai"].get("api_key_env") or "OPENAI_API_KEY")
    return os.environ.get("ISOVANE_OPENAI_API_KEY") or os.environ.get(env_name) or None
