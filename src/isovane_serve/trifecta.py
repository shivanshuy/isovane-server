"""Lethal trifecta scorecard — private data × untrusted ingress × egress."""

from __future__ import annotations

from typing import Any

from isovane_serve.architecture_graph import board_edges, board_nodes, normalize_graph
from isovane_serve.capabilities import node_caps
from isovane_serve.studio_models import TrifectaAxis, TrifectaScorecard


def score_trifecta(
    workspace_id: str,
    *,
    graph: dict[str, Any] | None = None,
    toxic_flows: list[dict[str, Any]] | None = None,
    privacy_posture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from isovane_serve.persistence import get_board

    raw = graph
    if raw is None:
        saved = get_board(workspace_id) or {}
        raw = saved.get("graph") or saved.get("board") or saved
        if privacy_posture is None and isinstance(saved.get("privacy_posture"), dict):
            privacy_posture = saved["privacy_posture"]

    g = normalize_graph(raw) if raw else None
    nodes = board_nodes(g) if g else []
    edges = board_edges(g) if g else []

    private_nodes: list[str] = []
    untrusted_nodes: list[str] = []
    egress_nodes: list[str] = []

    for n in nodes:
        caps = node_caps(n)
        nid = str(n.get("id"))
        kind = str(n.get("kind") or "")
        label = str(n.get("label") or "")
        if kind == "data" or "private" in caps or "secrets" in caps or "read_fs" in caps:
            private_nodes.append(nid)
        if kind == "ui" or "untrusted" in caps or any(
            k in label.lower() for k in ("mail", "rag", "web", "chat", "public")
        ):
            untrusted_nodes.append(nid)
        if kind in {"llm", "tool", "mcp"} or "exfil" in caps or "egress" in caps or "network" in caps:
            if kind == "llm" or "exfil" in caps or any(
                k in label.lower() for k in ("email", "slack", "webhook", "send", "http")
            ):
                egress_nodes.append(nid)
            elif kind in {"tool", "mcp"} and ("network" in caps or "exfil" in caps):
                egress_nodes.append(nid)

    # Edges that look like egress
    for e in edges:
        kind = str(e.get("kind") or "").lower()
        if any(k in kind for k in ("email", "http", "exfil", "llm", "cloud")):
            to = str(e.get("to") or "")
            if to and to not in egress_nodes:
                egress_nodes.append(to)

    if privacy_posture:
        for label in privacy_posture.get("data_stores") or []:
            if label and label not in private_nodes:
                private_nodes.append(str(label))
        if (privacy_posture.get("risky_egress_edges") or 0) > 0 and not egress_nodes:
            egress_nodes.append("(risky-egress-edges)")

    private = TrifectaAxis(
        present=bool(private_nodes),
        nodes=private_nodes[:12],
        detail="Private / secret / filesystem data reachable on the board" if private_nodes else "No private-data nodes labeled",
    )
    untrusted = TrifectaAxis(
        present=bool(untrusted_nodes),
        nodes=untrusted_nodes[:12],
        detail="UI / mail / RAG / public ingress present" if untrusted_nodes else "No untrusted ingress labeled",
    )
    egress = TrifectaAxis(
        present=bool(egress_nodes),
        nodes=egress_nodes[:12],
        detail="Outbound LLM / email / HTTP / webhook path present" if egress_nodes else "No egress channel labeled",
    )

    complete = private.present and untrusted.present and egress.present
    blocking: list[str] = []
    if toxic_flows is None:
        from isovane_serve.persistence import get_studio

        studio = get_studio(workspace_id) or {}
        toxic_flows = (studio.get("toxic_flows") or {}).get("flows") or []
    for flow in toxic_flows or []:
        if isinstance(flow, dict) and flow.get("id"):
            blocking.append(str(flow["id"]))

    gaps: list[str] = []
    if not private.present:
        gaps.append("Label private data stores on the board")
    if not untrusted.present:
        gaps.append("Mark UI/mail/RAG as untrusted ingress")
    if not egress.present:
        gaps.append("Label egress channels (LLM vendor / email / webhook)")
    if complete:
        gaps.append("Lethal trifecta complete — insert HITL/DLP/quarantine before tools")
        if not blocking:
            gaps.append("Run Toxic Flow analyze to list concrete capability chains")

    severity = "critical" if complete else ("medium" if sum([private.present, untrusted.present, egress.present]) >= 2 else "low")

    scorecard = TrifectaScorecard(
        private_data=private,
        untrusted_ingress=untrusted,
        egress=egress,
        complete=complete,
        severity=severity,
        blocking_flows=blocking[:20],
        gaps=gaps,
    )
    payload = {
        "workspace_id": workspace_id,
        "scorecard": scorecard.model_dump(mode="json"),
    }
    from isovane_serve.persistence import save_studio_slice

    save_studio_slice(workspace_id, "trifecta", payload)
    return payload
