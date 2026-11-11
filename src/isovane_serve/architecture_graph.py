"""Structurizr / C4 workspace as the single source of truth.

Industry format: Structurizr workspace JSON (C4 model).
Agent-security meaning lives in tags/properties (standard extension path):
  tags include: ui | agent | mcp | tool | llm | data | hitl

Flow:
  diagram image/text
    → Structurizr workspace
    → playground board (view of the same workspace)
    → user edits board
    → same Structurizr workspace
    → risk LLM / rules
"""

from __future__ import annotations

import json
import re
from typing import Any

SCHEMA_ID = "structurizr.workspace"
_KINDS = {"ui", "agent", "mcp", "tool", "llm", "data", "hitl", "unknown"}

# C4 element type hints (Structurizr tags) per Isovane kind
_KIND_C4 = {
    "ui": ("Software System", "ui"),
    "hitl": ("Person", "hitl"),
    "agent": ("Software System", "agent"),
    "mcp": ("Software System", "mcp"),
    "tool": ("Software System", "tool"),
    "llm": ("Software System", "llm"),
    "data": ("Software System", "data"),
    "unknown": ("Software System", "unknown"),
}


def empty_graph(*, source: str = "empty", filename: str | None = None) -> dict[str, Any]:
    return _workspace([], [], source=source, filename=filename, name="Architecture")


def normalize_graph(
    raw: dict[str, Any] | None,
    *,
    source: str = "normalize",
    filename: str | None = None,
) -> dict[str, Any]:
    """Accept Structurizr workspace OR legacy {nodes,edges}/board → Structurizr workspace."""
    data = raw if isinstance(raw, dict) else {}

    if _is_structurizr(data):
        nodes, edges = _board_parts_from_workspace(data)
        props = data.get("properties") if isinstance(data.get("properties"), dict) else {}
        return _workspace(
            nodes,
            edges,
            source=str(props.get("isovane.source") or source),
            filename=filename or props.get("isovane.filename"),
            name=str(data.get("name") or "Architecture"),
            description=str(data.get("description") or ""),
        )

    nodes_in = data.get("nodes") or []
    edges_in = data.get("edges") or []
    if not nodes_in and isinstance(data.get("board"), dict):
        nodes_in = data["board"].get("nodes") or []
        edges_in = data["board"].get("edges") or edges_in
    if not nodes_in and isinstance(data.get("graph"), dict) and not _is_structurizr(data["graph"]):
        nodes_in = data["graph"].get("nodes") or []
        edges_in = data["graph"].get("edges") or edges_in

    return graph_from_parts(nodes_in, edges_in, source=source, filename=filename)


def graph_from_parts(
    nodes: list[dict[str, Any]] | None,
    edges: list[dict[str, Any]] | None,
    *,
    source: str,
    filename: str | None = None,
) -> dict[str, Any]:
    used: set[str] = set()
    clean_nodes: list[dict[str, Any]] = []
    for item in nodes or []:
        if not isinstance(item, dict):
            continue
        label = _clean(str(item.get("label") or item.get("name") or item.get("id") or ""))
        if not label:
            continue
        nid = _clean_id(str(item.get("id") or "")) or _slug(label, used)
        if nid in used:
            nid = _slug(label, used)
        used.add(nid)
        kind = str(item.get("kind") or _kind_from_tags(item.get("tags")) or "unknown").lower().strip()
        if kind not in _KINDS:
            kind = "unknown"
        node: dict[str, Any] = {"id": nid, "label": label, "kind": kind}
        x, y = _num(item.get("x")), _num(item.get("y"))
        if x is None and isinstance(item.get("properties"), dict):
            x = _num(item["properties"].get("x"))
            y = _num(item["properties"].get("y")) if y is None else y
        if x is not None:
            node["x"] = x
        if y is not None:
            node["y"] = y
        if item.get("path"):
            node["path"] = str(item.get("path"))
        clean_nodes.append(node)

    id_set = {n["id"] for n in clean_nodes}
    clean_edges: list[dict[str, str]] = []
    for item in edges or []:
        if not isinstance(item, dict):
            continue
        frm = _clean_id(str(item.get("from") or item.get("sourceId") or ""))
        to = _clean_id(str(item.get("to") or item.get("destinationId") or ""))
        if not frm or not to or frm not in id_set or to not in id_set or frm == to:
            continue
        edge = {"from": frm, "to": to, "kind": str(item.get("kind") or "link")}
        if not any(e["from"] == frm and e["to"] == to for e in clean_edges):
            clean_edges.append(edge)

    return _workspace(clean_nodes, clean_edges, source=source, filename=filename)


def board_nodes(graph: dict[str, Any]) -> list[dict[str, Any]]:
    nodes, _ = _board_parts_from_workspace(normalize_graph(graph))
    return nodes


def board_edges(graph: dict[str, Any]) -> list[dict[str, str]]:
    _, edges = _board_parts_from_workspace(normalize_graph(graph))
    return edges


def graph_to_mermaid(graph: dict[str, Any]) -> str:
    nodes, edges = _board_parts_from_workspace(normalize_graph(graph))
    lines = ["flowchart LR"]
    for node in nodes:
        safe = re.sub(r"[^\w]", "_", str(node["id"]))
        label = str(node["label"]).replace('"', "'")
        kind = node.get("kind") or "unknown"
        lines.append(f'  {safe}["{label}"]:::{kind}')
    for edge in edges:
        a = re.sub(r"[^\w]", "_", str(edge["from"]))
        b = re.sub(r"[^\w]", "_", str(edge["to"]))
        lines.append(f"  {a} --> {b}")
    return "\n".join(lines)


def graph_to_analysis_text(graph: dict[str, Any]) -> str:
    """Derived text for rule engines; canonical blob is STRUCTURIZR_WORKSPACE."""
    g = normalize_graph(graph)
    nodes, edges = _board_parts_from_workspace(g)
    lines = ["DIAGRAM:"]
    id_label = {n["id"]: n["label"] for n in nodes}
    for edge in edges:
        lines.append(f"{id_label.get(edge['from'], edge['from'])} --> {id_label.get(edge['to'], edge['to'])}")
    lines.append("NODES:")
    for node in nodes:
        lines.append(f"- {node['label']} ({node['kind']})")
    lines.append("STRUCTURIZR_WORKSPACE:")
    lines.append(json.dumps(g, ensure_ascii=False))
    return "\n".join(lines)


def parse_architecture_graph(text: str) -> dict[str, Any] | None:
    """Extract Structurizr workspace (or legacy graph) from analyze/extract text."""
    raw = text or ""
    for marker in ("STRUCTURIZR_WORKSPACE:", "ARCHITECTURE_GRAPH:", "GRAPH_JSON:"):
        idx = raw.upper().find(marker.upper())
        if idx >= 0:
            blob = raw[idx + len(marker) :].strip()
            data = _loads_object(blob)
            if data:
                return normalize_graph(data, source="parse")
    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        candidate = raw[start : end + 1]
        if '"model"' in candidate or '"nodes"' in candidate:
            data = _loads_object(candidate)
            if data:
                return normalize_graph(data, source="parse")
    return None


def llm_payload(graph: dict[str, Any], *, mode: str = "both") -> dict[str, Any]:
    """Payload for risk LLM = the same Structurizr workspace (+ mode)."""
    g = normalize_graph(graph)
    return {
        "format": SCHEMA_ID,
        "mode": mode,
        "workspace": g,
        "mermaid": graph_to_mermaid(g),
        "kind_guide": {
            "ui": "user interface / chat",
            "agent": "AI agent / orchestrator",
            "mcp": "Model Context Protocol server",
            "tool": "tool / shell / email / refund",
            "llm": "external LLM vendor",
            "data": "database / CRM / logs",
            "hitl": "human-in-the-loop approval",
        },
    }


def _workspace(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, str]],
    *,
    source: str,
    filename: str | None,
    name: str = "Architecture",
    description: str = "Isovane architecture playground (C4 / Structurizr)",
) -> dict[str, Any]:
    people: list[dict[str, Any]] = []
    systems: list[dict[str, Any]] = []
    view_elements: list[dict[str, Any]] = []
    id_map: dict[str, str] = {}

    for index, node in enumerate(nodes, start=1):
        nid = str(node["id"])
        sid = str(index)
        id_map[nid] = sid
        kind = str(node.get("kind") or "unknown")
        c4_type, tag = _KIND_C4.get(kind, ("Software System", "unknown"))
        props: dict[str, str] = {"kind": kind}
        if node.get("x") is not None:
            props["x"] = str(int(float(node["x"])))
        if node.get("y") is not None:
            props["y"] = str(int(float(node["y"])))
        if node.get("path"):
            props["path"] = str(node["path"])

        element = {
            "id": sid,
            "name": str(node["label"]),
            "description": f"Isovane kind: {kind}",
            "tags": f"Element,{c4_type},{tag}",
            "properties": props,
        }
        if c4_type == "Person":
            people.append(element)
        else:
            systems.append(element)
        view_el: dict[str, Any] = {"id": sid}
        if node.get("x") is not None and node.get("y") is not None:
            view_el["x"] = int(float(node["x"]))
            view_el["y"] = int(float(node["y"]))
        view_elements.append(view_el)

    relationships: list[dict[str, Any]] = []
    view_rels: list[dict[str, Any]] = []
    for index, edge in enumerate(edges, start=len(nodes) + 1):
        src = id_map.get(str(edge["from"]))
        dst = id_map.get(str(edge["to"]))
        if not src or not dst:
            continue
        rid = str(index)
        relationships.append(
            {
                "id": rid,
                "sourceId": src,
                "destinationId": dst,
                "description": str(edge.get("kind") or "link"),
                "tags": "Relationship",
                "properties": {"kind": str(edge.get("kind") or "link")},
            }
        )
        view_rels.append({"id": rid})

    props: dict[str, str] = {"isovane.source": source, "structurizr.dsl": "false"}
    if filename:
        props["isovane.filename"] = str(filename)

    return {
        "id": 1,
        "name": name,
        "description": description,
        "model": {
            "people": people,
            "softwareSystems": systems,
            "relationships": relationships,
        },
        "views": {
            "systemLandscapeViews": [
                {
                    "key": "playground",
                    "description": "Editable Isovane architecture board",
                    "elements": view_elements,
                    "relationships": view_rels,
                    "automaticLayout": False,
                }
            ],
            "configuration": {
                "styles": {
                    "elements": [
                        {"tag": "ui", "background": "#dbeafe", "color": "#1e3a8a"},
                        {"tag": "agent", "background": "#ffedd5", "color": "#9a3412"},
                        {"tag": "mcp", "background": "#ede9fe", "color": "#5b21b6"},
                        {"tag": "tool", "background": "#fef3c7", "color": "#92400e"},
                        {"tag": "llm", "background": "#ccfbf1", "color": "#115e59"},
                        {"tag": "data", "background": "#e2e8f0", "color": "#334155"},
                        {"tag": "hitl", "background": "#dcfce7", "color": "#166534"},
                    ]
                }
            },
        },
        "properties": props,
    }


def _board_parts_from_workspace(workspace: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    model = workspace.get("model") if isinstance(workspace.get("model"), dict) else {}
    elements: list[dict[str, Any]] = []
    for group in ("people", "softwareSystems"):
        for item in model.get(group) or []:
            if isinstance(item, dict):
                elements.append(item)

    # Layout from landscape view if present
    layout: dict[str, tuple[float, float]] = {}
    views = workspace.get("views") if isinstance(workspace.get("views"), dict) else {}
    for view in views.get("systemLandscapeViews") or []:
        if not isinstance(view, dict):
            continue
        for el in view.get("elements") or []:
            if isinstance(el, dict) and el.get("id") is not None and el.get("x") is not None:
                layout[str(el["id"])] = (float(el["x"]), float(el.get("y") or 0))

    nodes: list[dict[str, Any]] = []
    sid_to_nid: dict[str, str] = {}
    used: set[str] = set()
    for item in elements:
        sid = str(item.get("id") or "")
        label = _clean(str(item.get("name") or sid))
        if not label:
            continue
        props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
        kind = str(props.get("kind") or _kind_from_tags(item.get("tags")) or "unknown").lower()
        if kind not in _KINDS:
            kind = "unknown"
        nid = _slug(label, used)
        used.add(nid)
        sid_to_nid[sid] = nid
        node: dict[str, Any] = {"id": nid, "label": label, "kind": kind}
        if sid in layout:
            node["x"], node["y"] = layout[sid]
        else:
            x, y = _num(props.get("x")), _num(props.get("y"))
            if x is not None:
                node["x"] = x
            if y is not None:
                node["y"] = y
        if props.get("path"):
            node["path"] = str(props["path"])
        nodes.append(node)

    edges: list[dict[str, str]] = []
    for rel in model.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        frm = sid_to_nid.get(str(rel.get("sourceId") or ""))
        to = sid_to_nid.get(str(rel.get("destinationId") or ""))
        if not frm or not to:
            continue
        props = rel.get("properties") if isinstance(rel.get("properties"), dict) else {}
        edges.append(
            {
                "from": frm,
                "to": to,
                "kind": str(props.get("kind") or rel.get("description") or "link"),
            }
        )
    return nodes, edges


def _is_structurizr(data: dict[str, Any]) -> bool:
    model = data.get("model")
    return isinstance(model, dict) and (
        "softwareSystems" in model or "people" in model or "relationships" in model
    )


def _kind_from_tags(tags: Any) -> str | None:
    parts = [p.strip().lower() for p in str(tags or "").split(",") if p.strip()]
    for kind in _KINDS:
        if kind in parts:
            return kind
    return None


def _clean(raw: str) -> str:
    return re.sub(r"\s+", " ", (raw or "").strip())


def _clean_id(raw: str) -> str:
    return re.sub(r"[^\w\-:.]+", "_", (raw or "").strip()).strip("_")


def _slug(label: str, used: set[str]) -> str:
    base = re.sub(r"[^a-zA-Z0-9]+", "_", label).strip("_").lower() or "node"
    base = base[:48]
    candidate = base
    n = 2
    while candidate in used:
        candidate = f"{base}_{n}"
        n += 1
    return candidate


def _num(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _loads_object(blob: str) -> dict[str, Any] | None:
    text = (blob or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        end = text.rfind("}")
        if end < 0:
            return None
        try:
            data = json.loads(text[: end + 1])
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None
