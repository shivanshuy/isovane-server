"""Parse architecture text / vision output into an editable board graph (nodes + edges + layout)."""

from __future__ import annotations

import json
import re
from typing import Any

from isovane_serve.arch_workflow import kind_for_label as _kind_for

# Left is non-greedy up to the arrow; right is greedy so "OpenAI (US)" is not truncated to "O".
_EDGE_RE = re.compile(
    r"[\"']?([A-Za-z0-9][^\"'\n]{0,80}?)\s*(?:-->|--+|==>|→|->)\s*[\"']?([A-Za-z0-9][^\"'\n:]{0,80})"
    r"(?:\s*:\s*([^\n]+))?",
)
_JSON_BLOCK = re.compile(r"GRAPH_JSON\s*:\s*(\{.*\})", re.I | re.S)


def _slug(label: str, used: set[str]) -> str:
    base = re.sub(r"[^a-zA-Z0-9]+", "_", (label or "node").strip()).strip("_").lower() or "node"
    base = base[:48]
    candidate = base
    n = 2
    while candidate in used:
        candidate = f"{base}_{n}"
        n += 1
    used.add(candidate)
    return candidate


def _clean_label(raw: str) -> str:
    return re.sub(r"\s+", " ", (raw or "").strip(" `\"'")).strip()


def _num(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_graph_json(text: str) -> dict[str, Any] | None:
    match = _JSON_BLOCK.search(text or "")
    blob = None
    if match:
        blob = match.group(1)
    else:
        # bare JSON object with nodes/edges
        start = (text or "").find("{")
        end = (text or "").rfind("}")
        if start >= 0 and end > start:
            candidate = text[start : end + 1]
            if '"nodes"' in candidate and '"edges"' in candidate:
                blob = candidate
    if not blob:
        return None
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        # try trim trailing prose after JSON
        try:
            data = json.loads(blob[: blob.rfind("}") + 1])
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict):
        return None
    return data


def _strip_graph_json(text: str) -> str:
    """Remove GRAPH_JSON payload so arrow regex cannot parse inside JSON strings."""
    match = _JSON_BLOCK.search(text or "")
    if not match:
        # bare trailing JSON object
        idx = (text or "").rfind('{"nodes"')
        if idx >= 0:
            return text[:idx]
        return text or ""
    return (text or "")[: match.start()] + (text or "")[match.end() :]


def graph_from_text(text: str, typed_nodes: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Build board inventory: nodes with x/y, edges, and mermaid export."""
    raw = text or ""
    used_ids: set[str] = set()
    nodes_by_label: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    parsed = parse_graph_json(raw)
    json_complete = bool(
        parsed
        and isinstance(parsed.get("nodes"), list)
        and parsed.get("nodes")
        and isinstance(parsed.get("edges"), list)
        and parsed.get("edges")
    )

    if parsed:
        for item in parsed.get("nodes") or []:
            if not isinstance(item, dict):
                continue
            label = _clean_label(str(item.get("label") or item.get("id") or ""))
            if not label:
                continue
            nid = re.sub(r"[^\w]+", "_", _clean_label(str(item.get("id") or ""))).strip("_") or _slug(
                label, used_ids
            )
            if nid in used_ids and str(item.get("id") or "") != nid:
                nid = _slug(label, used_ids)
            used_ids.add(nid)
            kind = str(item.get("kind") or _kind_for(label.lower()))
            nodes_by_label[label.lower()] = {
                "id": nid,
                "label": label,
                "kind": kind,
                "x": _num(item.get("x")),
                "y": _num(item.get("y")),
            }
            # also index by id for edge resolution
            nodes_by_label.setdefault(nid.lower(), nodes_by_label[label.lower()])
        for item in parsed.get("edges") or []:
            if not isinstance(item, dict):
                continue
            frm = _clean_label(str(item.get("from") or ""))
            to = _clean_label(str(item.get("to") or ""))
            if not frm or not to:
                continue
            frm_id = _resolve(frm, nodes_by_label, used_ids)
            to_id = _resolve(to, nodes_by_label, used_ids)
            edges.append({"from": frm_id, "to": to_id, "kind": str(item.get("kind") or "link")})

    # Only scrape A --> B lines outside GRAPH_JSON — line-oriented to avoid cross-line joins.
    prose = _strip_graph_json(raw) if parsed else raw
    if not json_complete:
        for line in prose.splitlines():
            match = _EDGE_RE.search(line.strip())
            if not match:
                continue
            left = _clean_label(match.group(1))
            right = _clean_label(match.group(2))
            if not left or not right or left.lower() == right.lower():
                continue
            if len(left) > 60 or len(right) > 60:
                continue
            if left.startswith("{") or right.startswith("{"):
                continue
            frm_id = _resolve(left, nodes_by_label, used_ids)
            to_id = _resolve(right, nodes_by_label, used_ids)
            edge = {"from": frm_id, "to": to_id, "kind": "link"}
            if edge not in edges and not any(e["from"] == frm_id and e["to"] == to_id for e in edges):
                edges.append(edge)

    # Merge classifier inventory labels — skip when GRAPH_JSON already defined the board
    if not json_complete:
        for node in typed_nodes or []:
            label = _clean_label(str(node.get("label") or node.get("id") or ""))
            if not label or len(label) > 80:
                continue
            if label.startswith("{") or label in {"nodes", "edges", "id", "label", "kind", "from", "to"}:
                continue
            key = label.lower()
            if key in nodes_by_label:
                nodes_by_label[key]["kind"] = node.get("kind") or nodes_by_label[key]["kind"]
                continue
            nid = _slug(label, used_ids)
            nodes_by_label[key] = {
                "id": nid,
                "label": label,
                "kind": str(node.get("kind") or _kind_for(label.lower())),
                "x": None,
                "y": None,
            }

    # Deduplicate: nodes_by_label may hold id+label aliases pointing at same dict
    seen: set[int] = set()
    nodes: list[dict[str, Any]] = []
    for node in nodes_by_label.values():
        ident = id(node)
        if ident in seen:
            continue
        seen.add(ident)
        nodes.append(node)

    _layout(nodes)
    mermaid = _to_mermaid(nodes, edges)
    return {
        "nodes": nodes,
        "edges": edges,
        "mermaid": mermaid,
        "board": {"nodes": nodes, "edges": edges},
    }


def _resolve(token: str, nodes_by_label: dict[str, dict[str, Any]], used_ids: set[str]) -> str:
    key = token.lower()
    # match existing id
    for node in nodes_by_label.values():
        if node["id"] == token or node["label"].lower() == key:
            return str(node["id"])
    nid = _slug(token, used_ids)
    nodes_by_label[key] = {
        "id": nid,
        "label": token,
        "kind": _kind_for(key),
        "x": None,
        "y": None,
    }
    return nid


def _layout(nodes: list[dict[str, Any]]) -> None:
    """Layer nodes by kind left→right if x/y missing."""
    columns = {
        "ui": 0,
        "hitl": 1,
        "agent": 2,
        "mcp": 3,
        "tool": 3,
        "llm": 4,
        "data": 4,
        "unknown": 2,
    }
    buckets: dict[int, list[dict[str, Any]]] = {}
    for node in nodes:
        if node.get("x") is not None and node.get("y") is not None:
            continue
        col = columns.get(str(node.get("kind") or "unknown"), 2)
        buckets.setdefault(col, []).append(node)
    for col, items in buckets.items():
        for row, node in enumerate(items):
            node["x"] = 36 + col * 180
            node["y"] = 36 + row * 96


def _to_mermaid(nodes: list[dict[str, Any]], edges: list[dict[str, str]]) -> str:
    id_to_label = {str(n["id"]): str(n["label"]) for n in nodes}
    lines = ["flowchart LR"]
    for node in nodes:
        safe = re.sub(r"[^\w]", "_", str(node["id"]))
        label = str(node["label"]).replace('"', "'")
        lines.append(f'  {safe}["{label}"]')
    for edge in edges:
        a = re.sub(r"[^\w]", "_", str(edge["from"]))
        b = re.sub(r"[^\w]", "_", str(edge["to"]))
        if edge["from"] in id_to_label and edge["to"] in id_to_label:
            lines.append(f"  {a} --> {b}")
    return "\n".join(lines)


def board_to_analysis_text(board: dict[str, Any]) -> str:
    """Serialize an edited board back into analyzer text."""
    nodes = board.get("nodes") or []
    edges = board.get("edges") or []
    lines = ["DIAGRAM:"]
    id_label = {str(n.get("id")): str(n.get("label") or n.get("id")) for n in nodes}
    for edge in edges:
        frm = id_label.get(str(edge.get("from")), str(edge.get("from")))
        to = id_label.get(str(edge.get("to")), str(edge.get("to")))
        lines.append(f"{frm} --> {to}")
    lines.append("NODES:")
    for node in nodes:
        lines.append(f"- {node.get('label') or node.get('id')} ({node.get('kind') or 'unknown'})")
    payload = {
        "nodes": [
            {
                "id": n.get("id"),
                "label": n.get("label"),
                "kind": n.get("kind"),
                "x": n.get("x"),
                "y": n.get("y"),
            }
            for n in nodes
        ],
        "edges": [{"from": e.get("from"), "to": e.get("to"), "kind": e.get("kind") or "link"} for e in edges],
    }
    lines.append("GRAPH_JSON:")
    lines.append(json.dumps(payload))
    return "\n".join(lines)
