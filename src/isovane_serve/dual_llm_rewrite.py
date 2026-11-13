"""Apply Dual-LLM / CaMeL board rewrite and persist."""

from __future__ import annotations

from typing import Any

from isovane_serve.board_mutate import apply_ops
from isovane_serve.architecture_graph import normalize_graph


def apply_dual_llm(
    workspace_id: str,
    graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rewrite board into privileged + quarantined LLMs; save board."""
    from isovane_serve.persistence import get_board, save_board

    raw = graph
    if raw is None:
        saved = get_board(workspace_id) or {}
        raw = saved.get("graph") or saved.get("board") or saved
    g = normalize_graph(raw) if raw else None
    if not g:
        return {"workspace_id": workspace_id, "ok": False, "error": "No board/graph to rewrite"}

    next_graph = apply_ops(g, [{"dual_llm": True}], source="dual_llm_apply")
    from isovane_serve.architecture_graph import board_boundaries, board_edges, board_nodes

    board = {
        "nodes": board_nodes(next_graph),
        "edges": board_edges(next_graph),
        "boundaries": board_boundaries(next_graph),
    }
    save_board(
        workspace_id,
        {
            "source": "dual_llm_apply",
            "graph": next_graph,
            "board": board,
            "pattern": "dual-llm",
        },
    )
    return {
        "workspace_id": workspace_id,
        "ok": True,
        "graph": next_graph,
        "board": board,
        "hint": "Re-run Architecture analyze on the rewritten board.",
    }
