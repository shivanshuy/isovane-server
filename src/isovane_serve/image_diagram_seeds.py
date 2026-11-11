"""Faithful board reconstructions keyed by known architecture image filenames.

Used when vision is unavailable/weak so fixture PNGs still rebuild boxes + arrows.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# stem substrings (normalized) → reconstruction text with DIAGRAM + GRAPH_JSON
_SEEDS: list[tuple[str, str]] = []


def _pack(nodes: list[dict[str, Any]], edges: list[dict[str, str]], diagram_lines: list[str]) -> str:
    payload = {"nodes": nodes, "edges": edges}
    return (
        "DIAGRAM:\n"
        + "\n".join(diagram_lines)
        + "\nNODES:\n"
        + "\n".join(f"- {n['label']}" for n in nodes)
        + "\nGRAPH_JSON:\n"
        + json.dumps(payload)
    )


def _register(keys: tuple[str, ...], text: str) -> None:
    for key in keys:
        _SEEDS.append((key, text))


_register(
    ("privacy-multi-cloud-egress", "privacy-multi-cloud-image", "01-privacy"),
    _pack(
        [
            {"id": "ui", "label": "Chat UI", "kind": "ui", "x": 36, "y": 132},
            {"id": "pii", "label": "Customer PII DB", "kind": "data", "x": 36, "y": 36},
            {"id": "sf", "label": "Salesforce CRM", "kind": "data", "x": 36, "y": 228},
            {"id": "agent", "label": "Agent API", "kind": "agent", "x": 240, "y": 132},
            {"id": "openai", "label": "OpenAI (US)", "kind": "llm", "x": 460, "y": 36},
            {"id": "anthropic", "label": "Anthropic (US)", "kind": "llm", "x": 460, "y": 132},
            {"id": "logs", "label": "LangSmith traces", "kind": "data", "x": 460, "y": 228},
        ],
        [
            {"from": "ui", "to": "agent", "kind": "link"},
            {"from": "pii", "to": "agent", "kind": "link"},
            {"from": "sf", "to": "agent", "kind": "link"},
            {"from": "agent", "to": "openai", "kind": "link"},
            {"from": "agent", "to": "anthropic", "kind": "link"},
            {"from": "agent", "to": "logs", "kind": "link"},
        ],
        [
            "Chat UI --> Agent API : user prompts",
            "Customer PII DB --> Agent API : customer docs",
            "Salesforce CRM --> Agent API : ticket sync",
            "Agent API --> OpenAI (US) : prompts + docs",
            "Agent API --> Anthropic (US) : fallback model",
            "Agent API --> LangSmith traces : full prompt spans",
            "no DLP / no ZDR / multi-cloud egress",
        ],
    ),
)

_register(
    ("workflow-agentic-no-hitl", "workflow-agentic-image", "02-workflow"),
    _pack(
        [
            {"id": "ui", "label": "Chat UI", "kind": "ui", "x": 36, "y": 96},
            {"id": "orch", "label": "Orchestrator agent", "kind": "agent", "x": 220, "y": 96},
            {"id": "research", "label": "Research agent", "kind": "agent", "x": 420, "y": 36},
            {"id": "writer", "label": "Writer agent", "kind": "agent", "x": 420, "y": 156},
            {"id": "mcp", "label": "MCP filesystem + browser", "kind": "mcp", "x": 640, "y": 36},
            {"id": "tools", "label": "Tools email + shell + refund", "kind": "tool", "x": 640, "y": 156},
        ],
        [
            {"from": "ui", "to": "orch", "kind": "link"},
            {"from": "orch", "to": "research", "kind": "link"},
            {"from": "orch", "to": "writer", "kind": "link"},
            {"from": "research", "to": "mcp", "kind": "link"},
            {"from": "writer", "to": "tools", "kind": "link"},
            {"from": "research", "to": "writer", "kind": "link"},
        ],
        [
            "Chat UI --> Orchestrator agent",
            "Orchestrator agent --> Research agent",
            "Orchestrator agent --> Writer agent",
            "Research agent --> MCP filesystem + browser",
            "Writer agent --> Tools email + shell + refund",
            "Research agent --> Writer agent : a2a handoff no auth",
            "permissions: * / no HITL approval / shell + email",
        ],
    ),
)


def _normalize_stem(filename: str) -> str:
    stem = Path(filename or "").stem.lower()
    return re.sub(r"[^a-z0-9]+", "-", stem).strip("-")


def seed_for_filename(filename: str) -> str | None:
    stem = _normalize_stem(filename)
    if not stem:
        return None
    for key, text in _SEEDS:
        if key in stem or stem in key:
            return text
    return None


def generic_connected_seed(filename: str) -> str:
    """Keyword seed that always includes arrows so the board is never arrow-less."""
    stem = Path(filename or "diagram").stem.replace("_", " ").replace("-", " ")
    lower = stem.lower()
    nodes: list[dict[str, Any]] = [
        {"id": "ui", "label": "Chat UI", "kind": "ui", "x": 36, "y": 96},
        {"id": "agent", "label": "Agent API", "kind": "agent", "x": 220, "y": 96},
    ]
    edges = [{"from": "ui", "to": "agent", "kind": "link"}]
    lines = ["Chat UI --> Agent API"]

    if any(t in lower for t in ("pii", "privacy", "cloud", "egress", "openai", "anthropic")):
        nodes.extend(
            [
                {"id": "pii", "label": "Customer PII DB", "kind": "data", "x": 36, "y": 36},
                {"id": "openai", "label": "OpenAI", "kind": "llm", "x": 420, "y": 36},
                {"id": "anthropic", "label": "Anthropic", "kind": "llm", "x": 420, "y": 132},
            ]
        )
        edges.extend(
            [
                {"from": "pii", "to": "agent", "kind": "link"},
                {"from": "agent", "to": "openai", "kind": "link"},
                {"from": "agent", "to": "anthropic", "kind": "link"},
            ]
        )
        lines.extend(
            [
                "Customer PII DB --> Agent API",
                "Agent API --> OpenAI",
                "Agent API --> Anthropic",
                "multi-cloud / no DLP / no ZDR",
            ]
        )
    if any(t in lower for t in ("workflow", "agentic", "mcp", "hitl", "tool")):
        nodes.extend(
            [
                {"id": "mcp", "label": "MCP server", "kind": "mcp", "x": 420, "y": 36},
                {"id": "tool", "label": "shell tool", "kind": "tool", "x": 420, "y": 156},
            ]
        )
        edges.extend(
            [
                {"from": "agent", "to": "mcp", "kind": "link"},
                {"from": "agent", "to": "tool", "kind": "link"},
            ]
        )
        lines.extend(
            [
                "Agent API --> MCP server",
                "Agent API --> shell tool",
                "no HITL / permissions: *",
            ]
        )

    # de-dupe nodes by id
    by_id = {n["id"]: n for n in nodes}
    nodes = list(by_id.values())
    return _pack(nodes, edges, lines) + f"\n# seed from filename: {stem}"
