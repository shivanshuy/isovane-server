"""Derive a privacy posture summary from a Structurizr / board graph."""

from __future__ import annotations

from typing import Any

from isovane_serve.architecture_graph import board_edges, board_nodes, normalize_graph

_CROSS_BORDER = (
    "openai",
    "anthropic",
    "bedrock",
    "gemini",
    "us)",
    "(us",
    "america",
)
_SINK = ("langsmith", "trace", "log", "observability", "datadog", "sentry")
_DLP = ("dlp", "redact", "zdr", "zero data", "no-train", "no train")


def privacy_posture_from_graph(graph: dict[str, Any] | None) -> dict[str, Any]:
    """Emit inventory.privacy_posture without changing board render shape."""
    g = normalize_graph(graph or {})
    nodes = board_nodes(g)
    edges = board_edges(g)
    kinds = {str(n.get("kind") or "unknown") for n in nodes}
    labels = [str(n.get("label") or "") for n in nodes]
    lower_blob = " ".join(labels).lower()

    llm_vendors = [
        n["label"]
        for n in nodes
        if str(n.get("kind")) == "llm"
        or any(
            t in str(n.get("label") or "").lower()
            for t in ("openai", "anthropic", "bedrock", "azure", "gemini")
        )
    ]
    data_stores = [n["label"] for n in nodes if str(n.get("kind")) == "data"]
    sinks = [
        n["label"]
        for n in nodes
        if any(t in str(n.get("label") or "").lower() for t in _SINK)
    ]
    has_hitl = "hitl" in kinds
    has_cross_border = any(t in lower_blob for t in _CROSS_BORDER)
    has_dlp_marker = any(t in lower_blob for t in _DLP)

    edge_count = len(edges)
    risky_egress = 0
    for edge in edges:
        frm = next((n for n in nodes if n["id"] == edge.get("from")), None)
        to = next((n for n in nodes if n["id"] == edge.get("to")), None)
        if not frm or not to:
            continue
        if str(to.get("kind")) in {"llm", "unknown"} and str(frm.get("kind")) in {
            "agent",
            "data",
            "ui",
        }:
            risky_egress += 1

    controls = {
        "hitl_present": has_hitl,
        "dlp_or_zdr_labeled": has_dlp_marker,
        "cross_border_llm": has_cross_border,
        "observability_sink": bool(sinks),
    }
    gaps: list[str] = []
    if has_cross_border and not has_dlp_marker:
        gaps.append("cross_border_llm_without_dlp_zdr_label")
    if not has_hitl and edge_count > 0:
        gaps.append("no_hitl_node")
    if sinks and not has_dlp_marker:
        gaps.append("logging_sink_without_redaction_label")
    if len(llm_vendors) >= 2:
        gaps.append("multi_vendor_llm_fanout")

    return {
        "schema": "isovane.privacy_posture.v1",
        "llm_vendors": llm_vendors,
        "data_stores": data_stores,
        "observability_sinks": sinks,
        "edge_count": edge_count,
        "risky_egress_edges": risky_egress,
        "controls": controls,
        "gaps": gaps,
        "kinds_present": sorted(kinds),
    }
