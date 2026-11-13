"""Dual-LLM / CaMeL lint — untrusted ingress + privileged tools without quarantine."""

from __future__ import annotations

from typing import Any

from isovane_serve.architecture_graph import board_edges, board_nodes, normalize_graph
from isovane_serve.insights import insight_for
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix
from isovane_serve.studio_models import DualLlmVerdict


_QUARANTINE_MARKERS = (
    "quarantine",
    "dual-llm",
    "dual llm",
    "camel",
    "privileged llm",
    "no tools",
    "privilege drop",
)


def lint_dual_llm(
    workspace_id: str,
    graph: dict[str, Any] | None,
    *,
    persist_findings: bool = True,
) -> dict[str, Any]:
    g = normalize_graph(graph) if graph else None
    if not g:
        return {"workspace_id": workspace_id, "verdicts": [], "findings": []}

    nodes = board_nodes(g)
    edges = board_edges(g)
    by_id = {str(n["id"]): n for n in nodes}

    untrusted_ids = {
        str(n["id"])
        for n in nodes
        if str(n.get("kind")) == "ui"
        or _looks_untrusted(str(n.get("label") or ""))
    }
    tool_ids = {
        str(n["id"])
        for n in nodes
        if str(n.get("kind")) in {"tool", "mcp"}
        or _looks_privileged_tool(str(n.get("label") or ""))
    }
    has_quarantine = any(
        any(m in str(n.get("label") or "").lower() for m in _QUARANTINE_MARKERS)
        or str(n.get("kind")) == "hitl"
        and "quarant" in str(n.get("label") or "").lower()
        for n in nodes
    )
    # Explicit dual-llm pattern already on board
    if any("privileged llm" in str(n.get("label") or "").lower() for n in nodes) and any(
        "quarantined" in str(n.get("label") or "").lower() for n in nodes
    ):
        has_quarantine = True

    # Agents that reach both untrusted and tools
    adj: dict[str, set[str]] = {str(n["id"]): set() for n in nodes}
    for e in edges:
        frm, to = str(e.get("from") or ""), str(e.get("to") or "")
        if frm in adj and to in adj:
            adj[frm].add(to)
            adj[to].add(frm)

    verdicts: list[DualLlmVerdict] = []
    agents = [n for n in nodes if str(n.get("kind")) in {"agent", "llm"}]
    for agent in agents:
        aid = str(agent["id"])
        reachable = _reachable(aid, adj)
        has_u = bool(reachable & untrusted_ids) or any(
            str(e.get("to")) == aid and str(e.get("from")) in untrusted_ids for e in edges
        )
        # also inbound from ui
        if not has_u:
            has_u = any(
                str(e.get("to")) == aid and by_id.get(str(e.get("from")), {}).get("kind") == "ui"
                for e in edges
            )
        has_tools = bool(reachable & tool_ids) or any(
            str(e.get("from")) == aid and str(e.get("to")) in tool_ids for e in edges
        )
        if not (has_u and has_tools):
            continue
        if has_quarantine:
            continue
        verdicts.append(
            DualLlmVerdict(
                id=f"dual-llm:{aid}",
                agent_id=aid,
                agent_label=str(agent.get("label") or aid),
                has_untrusted=True,
                has_privileged_tools=True,
                has_quarantine=False,
                severity="high",
                summary=(
                    f"Agent/LLM '{agent.get('label')}' can see untrusted ingress and call "
                    "privileged tools/MCP without a quarantined Dual-LLM / CaMeL split."
                ),
            )
        )

    findings = [_verdict_to_finding(workspace_id, v) for v in verdicts]
    if persist_findings and findings:
        from isovane_serve import store
        from isovane_serve.remediations import hydrate_finding

        for f in findings:
            store.add_finding(hydrate_finding(f))

    payload = {
        "workspace_id": workspace_id,
        "verdicts": [v.model_dump(mode="json") for v in verdicts],
        "findings": [{"id": f.id, "title": f.title, "severity": f.severity} for f in findings],
        "has_quarantine_pattern": has_quarantine,
    }
    from isovane_serve.persistence import save_studio_slice

    save_studio_slice(workspace_id, "dual_llm", payload)
    return payload


def _verdict_to_finding(workspace_id: str, v: DualLlmVerdict) -> Finding:
    title = f"Dual-LLM gap — {v.agent_label}"
    checklist = [
        "Apply Trust Pattern: Dual-LLM / quarantined model",
        "Route UI/mail/RAG only to the quarantined model",
        "Tools only via privileged path + deterministic orchestrator",
        "Re-analyze Architecture after rewrite",
    ]
    insight = insight_for(title=title, issue_text=v.summary, tool="architecture-workflow")
    return Finding(
        workspace_id=workspace_id,
        source="analyze",
        severity=v.severity if v.severity in {"critical", "high", "medium", "low"} else "high",
        title=title,
        summary=v.summary,
        tags=["dual-llm", "camel", "trust-studio"],
        owasp=list(v.owasp),
        category="architecture",
        evidence=FindingEvidence(
            path=v.agent_id,
            snippet=v.summary,
            source_channel="dual-llm",
            args={"agent_id": v.agent_id, "verdict_id": v.id},
        ),
        suggested_fix=SuggestedFix(
            kind="architecture",
            summary="Apply Dual-LLM / CaMeL: privileged LLM (tools) + quarantined LLM (no tools).",
            checklist=checklist,
            diff=(
                "# Dual-LLM / CaMeL\n"
                "- UI → Agent(+tools) → MCP/Tools\n"
                "+ UI → Quarantined LLM (no tools) → Orchestrator\n"
                "+ Privileged LLM (tools) → Orchestrator → Tools\n"
            ),
        ),
        policy_rule_id="arch-dual-llm",
        exploit=insight.exploit or None,
        technical_details=insight.technical_details or None,
        solutions=list(insight.solutions or []) or checklist,
    )


def _looks_untrusted(label: str) -> bool:
    low = label.lower()
    return any(k in low for k in ("mail", "email", "rag", "web", "chat", "untrusted", "public"))


def _looks_privileged_tool(label: str) -> bool:
    low = label.lower()
    return any(
        k in low
        for k in ("shell", "email", "send", "refund", "pay", "write", "exec", "mcp", "filesystem")
    )


def _reachable(start: str, adj: dict[str, set[str]], limit: int = 64) -> set[str]:
    seen = {start}
    stack = [start]
    while stack and len(seen) < limit:
        cur = stack.pop()
        for nxt in adj.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen
