"""Repository layout — single place for config / rules / policies roots."""

from __future__ import annotations

import os
from pathlib import Path

# src/isovane_serve/paths.py → parents[2] = isovane-server/
REPO_ROOT = Path(__file__).resolve().parents[2]

CONFIG_DIR = Path(
    os.environ.get("ISOVANE_CONFIG_DIR") or (REPO_ROOT / "config")
).resolve()

RULES_DIR = Path(
    os.environ.get("ISOVANE_RULES_DIR") or (REPO_ROOT / "rules")
).resolve()

POLICIES_DIR = Path(
    os.environ.get("ISOVANE_POLICIES_DIR") or (REPO_ROOT / "policies")
).resolve()

MODELS_YAML = CONFIG_DIR / "models.yaml"
PROMPTS_YAML = CONFIG_DIR / "prompts.yaml"
SCAN_YAML = CONFIG_DIR / "scan.yaml"
KINDS_YAML = CONFIG_DIR / "kinds.yaml"
DEFAULT_POLICY_YAML = POLICIES_DIR / "default.yaml"
AGENT_RULES_DIR = RULES_DIR / "agent"
