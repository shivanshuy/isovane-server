"""Trust Pattern Catalog — list + apply board rewrites."""

from __future__ import annotations

from typing import Any

from isovane_serve.architecture_graph import (
    board_boundaries,
    board_edges,
    board_nodes,
    normalize_graph,
)
from isovane_serve.board_mutate import apply_ops
from isovane_serve.paths import CONFIG_DIR
from isovane_serve.studio_models import TrustPattern
from isovane_serve.yaml_config import load_yaml


def list_patterns() -> list[TrustPattern]:
    rows = _raw_patterns()
    out: list[TrustPattern] = []
    for row in rows:
        out.append(
            TrustPattern(
                id=str(row.get("id") or ""),
                title=str(row.get("title") or row.get("id") or ""),
                summary=str(row.get("summary") or ""),
                remediation_id=str(row.get("remediation_id") or "") or None,
                owasp=[str(x) for x in (row.get("owasp") or []) if x],
                policy_snippet=str(row.get("policy_snippet") or "") or None,
            )
        )
    return [p for p in out if p.id]


def get_pattern(pattern_id: str) -> dict[str, Any] | None:
    for row in _raw_patterns():
        if str(row.get("id")) == pattern_id:
            return row
    return None


def apply_pattern(
    workspace_id: str,
    pattern_id: str,
    graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = get_pattern(pattern_id)
    if not row:
        return {"ok": False, "error": f"Unknown pattern: {pattern_id}"}

    from isovane_serve.persistence import get_board, save_board

    raw = graph
    if raw is None:
        saved = get_board(workspace_id) or {}
        raw = saved.get("graph") or saved.get("board") or saved
    g = normalize_graph(raw) if raw else None
    if not g:
        return {"ok": False, "error": "No board/graph to mutate"}

    ops = list(row.get("board_ops") or [])
    next_graph = apply_ops(g, ops, source=f"pattern:{pattern_id}")
    board = {
        "nodes": board_nodes(next_graph),
        "edges": board_edges(next_graph),
        "boundaries": board_boundaries(next_graph),
    }
    save_board(
        workspace_id,
        {
            "source": f"trust_pattern:{pattern_id}",
            "graph": next_graph,
            "board": board,
            "pattern": pattern_id,
            "policy_snippet": row.get("policy_snippet"),
        },
    )
    return {
        "ok": True,
        "workspace_id": workspace_id,
        "pattern_id": pattern_id,
        "title": row.get("title"),
        "graph": next_graph,
        "board": board,
        "policy_snippet": row.get("policy_snippet"),
        "hint": "Re-run Architecture analyze after applying the pattern.",
    }


def _raw_patterns() -> list[dict[str, Any]]:
    path = CONFIG_DIR / "trust-patterns.yaml"
    if not path.is_file():
        return []
    data = load_yaml(str(path)) or {}
    rows = data.get("patterns") or []
    return [r for r in rows if isinstance(r, dict)]
