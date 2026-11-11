"""Shared C4/Isovane node-kind classification from config/kinds.yaml."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from isovane_serve.paths import CONFIG_DIR
from isovane_serve.yaml_config import load_yaml

KINDS_YAML = CONFIG_DIR / "kinds.yaml"


@lru_cache(maxsize=4)
def load_kinds_config(path: str | None = None) -> dict[str, Any]:
    data = load_yaml(str(path or KINDS_YAML))
    kinds = data.get("kinds") or []
    ordered: list[tuple[str, tuple[str, ...]]] = []
    for entry in kinds:
        if not isinstance(entry, dict):
            continue
        kid = str(entry.get("id") or "").strip()
        tokens = tuple(str(t).lower() for t in (entry.get("tokens") or []) if t)
        if kid and tokens:
            ordered.append((kid, tokens))
    a2a = tuple(str(t).lower() for t in (data.get("a2a_tokens") or []) if t)
    return {"kinds": ordered, "a2a_tokens": a2a}


def kind_for_label(label: str, *, default: str = "unknown") -> str:
    """Return ui|agent|mcp|tool|llm|data|hitl|… from label substrings."""
    lower = (label or "").lower()
    if not lower:
        return default
    for kid, tokens in load_kinds_config()["kinds"]:
        if any(t in lower for t in tokens):
            return kid
    return default


def kind_tokens(kind_id: str) -> tuple[str, ...]:
    for kid, tokens in load_kinds_config()["kinds"]:
        if kid == kind_id:
            return tokens
    return ()


def a2a_tokens() -> tuple[str, ...]:
    return load_kinds_config()["a2a_tokens"]


def clear_kinds_cache() -> None:
    load_kinds_config.cache_clear()
