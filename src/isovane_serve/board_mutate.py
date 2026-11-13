"""Apply Trust Pattern / Dual-LLM board rewrites to Structurizr-ish graphs."""

from __future__ import annotations

from typing import Any

from isovane_serve.architecture_graph import (
    board_boundaries,
    board_edges,
    board_nodes,
    graph_from_parts,
    normalize_graph,
)


def _parts(graph: dict[str, Any] | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    g = normalize_graph(graph) if graph else None
    if not g:
        return [], [], []
    return list(board_nodes(g)), list(board_edges(g)), list(board_boundaries(g))


def apply_ops(
    graph: dict[str, Any] | None,
    ops: list[dict[str, Any]],
    *,
    source: str = "trust_pattern",
) -> dict[str, Any]:
    nodes, edges, boundaries = _parts(graph)
    for op in ops:
        if not isinstance(op, dict):
            continue
        if op.get("dual_llm"):
            nodes, edges = _apply_dual_llm(nodes, edges)
            continue
        if op.get("mark_kind"):
            tag = str(op.get("tag") or "untrusted")
            for n in nodes:
                if str(n.get("kind")) == str(op["mark_kind"]):
                    label = str(n.get("label") or "")
                    if tag.lower() not in label.lower():
                        n["label"] = f"{label} [{tag}]".strip()
            continue
        if op.get("insert_boundary"):
            boundaries.append(
                {
                    "id": f"b-{op.get('insert_boundary')}",
                    "kind": str(op.get("insert_boundary")),
                    "label": str(op.get("label") or op.get("insert_boundary")),
                }
            )
            continue
        if op.get("tag_edges"):
            kind = str(op["tag_edges"])
            tag = str(op.get("tag") or "auth")
            for e in edges:
                if kind == "a2a" and "agent" in str(e.get("kind") or ""):
                    e["kind"] = f"{e.get('kind')}+{tag}"
                elif str(e.get("kind")) == kind:
                    e["kind"] = f"{e.get('kind')}+{tag}"
            continue
        if op.get("insert_kind"):
            nodes, edges = _insert_control(
                nodes,
                edges,
                kind=str(op["insert_kind"]),
                label=str(op.get("label") or op["insert_kind"]),
                rewire=str(op.get("rewire") or "agent_to_tools"),
                tag=str(op.get("tag") or ""),
            )
    return graph_from_parts(nodes, edges, source=source, boundaries=boundaries)


def _insert_control(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    kind: str,
    label: str,
    rewire: str,
    tag: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ctrl_id = f"ctrl-{tag or kind}-{len(nodes)}"
    ctrl = {
        "id": ctrl_id,
        "kind": kind if kind in {"hitl", "data", "agent", "llm"} else "hitl",
        "label": label,
        "x": 200,
        "y": 200,
    }
    nodes = list(nodes) + [ctrl]
    new_edges: list[dict[str, Any]] = []
    rewired = False
    for e in edges:
        frm_n = next((n for n in nodes if n["id"] == e.get("from")), None)
        to_n = next((n for n in nodes if n["id"] == e.get("to")), None)
        fk = str((frm_n or {}).get("kind") or "")
        tk = str((to_n or {}).get("kind") or "")
        hit = False
        if rewire == "agent_to_tools" and fk == "agent" and tk in {"tool", "mcp"}:
            hit = True
        elif rewire == "agent_to_agent" and fk == "agent" and tk == "agent":
            hit = True
        elif rewire == "agent_to_data" and fk == "agent" and tk == "data":
            hit = True
        elif rewire == "data_to_llm" and fk in {"data", "agent"} and tk == "llm":
            hit = True
        elif rewire == "ui_to_agent" and fk == "ui" and tk == "agent":
            hit = True
        if hit:
            new_edges.append({"from": e["from"], "to": ctrl_id, "kind": f"{e.get('kind')}→gate"})
            new_edges.append({"from": ctrl_id, "to": e["to"], "kind": f"gate→{e.get('kind')}"})
            rewired = True
        else:
            new_edges.append(e)
    if not rewired:
        # Attach control after first agent if nothing matched
        agents = [n for n in nodes if n.get("kind") == "agent"]
        tools = [n for n in nodes if n.get("kind") in {"tool", "mcp"}]
        if agents and tools:
            new_edges.append({"from": agents[0]["id"], "to": ctrl_id, "kind": "agent→gate"})
            new_edges.append({"from": ctrl_id, "to": tools[0]["id"], "kind": "gate→tool"})
    return nodes, new_edges


def _apply_dual_llm(
    nodes: list[dict[str, Any]], edges: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split into privileged LLM (tools) + quarantined LLM (no tools)."""
    nodes = list(nodes)
    edges = list(edges)
    priv_id = "llm-privileged"
    quar_id = "llm-quarantined"
    orch_id = "orchestrator"
    if not any(n.get("id") == priv_id for n in nodes):
        nodes.append({"id": priv_id, "kind": "llm", "label": "Privileged LLM (tools)", "x": 400, "y": 120})
    if not any(n.get("id") == quar_id for n in nodes):
        nodes.append({"id": quar_id, "kind": "llm", "label": "Quarantined LLM (no tools)", "x": 400, "y": 280})
    if not any(n.get("id") == orch_id for n in nodes):
        nodes.append({"id": orch_id, "kind": "hitl", "label": "Orchestrator (deterministic)", "x": 280, "y": 200})

    new_edges: list[dict[str, Any]] = []
    for e in edges:
        to_n = next((n for n in nodes if n["id"] == e.get("to")), None)
        frm_n = next((n for n in nodes if n["id"] == e.get("from")), None)
        tk = str((to_n or {}).get("kind") or "")
        fk = str((frm_n or {}).get("kind") or "")
        # Untrusted UI → quarantine only
        if fk == "ui" and tk == "agent":
            new_edges.append({"from": e["from"], "to": quar_id, "kind": "ui→quarantine"})
            new_edges.append({"from": quar_id, "to": orch_id, "kind": "symbols→orch"})
            continue
        # Tools only from privileged path via orchestrator
        if tk in {"tool", "mcp"} and fk in {"agent", "llm"}:
            new_edges.append({"from": priv_id, "to": orch_id, "kind": "plan→orch"})
            new_edges.append({"from": orch_id, "to": e["to"], "kind": "orch→tool"})
            continue
        new_edges.append(e)
    new_edges.append({"from": orch_id, "to": priv_id, "kind": "orch→privileged"})
    return nodes, new_edges
