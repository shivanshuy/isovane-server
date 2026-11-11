"""Cached YAML loaders for config/*.yaml — keep knobs out of Python modules."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from isovane_serve.paths import PROMPTS_YAML, SCAN_YAML


@lru_cache(maxsize=16)
def load_yaml(path: str) -> dict[str, Any]:
    target = Path(path)
    if not target.exists():
        return {}
    data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def clear_yaml_cache() -> None:
    load_yaml.cache_clear()
    load_prompts.cache_clear()
    load_scan_settings.cache_clear()


@lru_cache(maxsize=4)
def load_prompts(path: str | None = None) -> dict[str, str]:
    data = load_yaml(str(path or PROMPTS_YAML))
    return {
        "vision_extract": str(data.get("vision_extract") or "").strip(),
        "architecture_risk": str(data.get("architecture_risk") or "").strip(),
    }


@lru_cache(maxsize=4)
def load_scan_settings(path: str | None = None) -> dict[str, Any]:
    data = load_yaml(str(path or SCAN_YAML))
    skip = data.get("skip_dir_names") or []
    mcp = data.get("mcp") or {}
    ast = data.get("ast_taint") or {}
    code_exts = {str(x) for x in (data.get("code_exts") or [])}
    text_exts = {str(x) for x in (data.get("text_exts") or [])}
    upstream = [str(x) for x in (data.get("semgrep_upstream") or []) if x]
    return {
        "skip_dir_names": {str(x) for x in skip},
        "code_exts": code_exts,
        "text_exts": text_exts,
        "semgrep_upstream": upstream,
        "mcp": {
            "runners": {str(x).lower() for x in (mcp.get("runners") or [])},
            "auth_header_keys": {
                str(x).lower() for x in (mcp.get("auth_header_keys") or [])
            },
            "auth_field_keys": {
                str(x).lower() for x in (mcp.get("auth_field_keys") or [])
            },
        },
        "ast_taint": {
            "userish_names": {str(x).lower() for x in (ast.get("userish_names") or [])},
            "request_roots": {str(x) for x in (ast.get("request_roots") or [])},
            "request_attrs": {str(x) for x in (ast.get("request_attrs") or [])},
            "source_calls": {str(x) for x in (ast.get("source_calls") or [])},
            "prompt_sinks": {str(x) for x in (ast.get("prompt_sinks") or [])},
            "tool_sinks": {str(x).lower() for x in (ast.get("tool_sinks") or [])},
        },
    }


def skip_dir_names() -> set[str]:
    names = load_scan_settings()["skip_dir_names"]
    return set(names) if names else {
        ".git",
        "node_modules",
        ".venv",
        "dist",
        "build",
        "__pycache__",
        ".tox",
    }
