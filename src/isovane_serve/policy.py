"""Load YAML policy for the action gate."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from isovane_serve.models import PolicyConfig

from isovane_serve.paths import DEFAULT_POLICY_YAML

_DEFAULT_PATH = DEFAULT_POLICY_YAML
_cache: dict[str, PolicyConfig] = {}


def load_policy(path: str | Path | None = None) -> PolicyConfig:
    target = Path(path) if path else _DEFAULT_PATH
    key = str(target.resolve()) if target.exists() else "__builtin__"
    if key in _cache:
        return _cache[key]
    if target.exists():
        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        cfg = PolicyConfig.model_validate(data)
    else:
        cfg = PolicyConfig()
    _cache[key] = cfg
    return cfg


def policy_from_dict(data: dict[str, Any] | None) -> PolicyConfig:
    if not data:
        return PolicyConfig()
    return PolicyConfig.model_validate(data)


def clear_policy_cache() -> None:
    _cache.clear()


# Ensure sims pick up YAML edits during dev reloads
clear_policy_cache()
