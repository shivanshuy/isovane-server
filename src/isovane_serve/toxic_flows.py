"""Toxic Flow Studio — capability graph + named toxic pairs across MCP/code/board."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from isovane_serve.architecture_graph import board_edges, board_nodes, normalize_graph
from isovane_serve.capabilities import classify_tools, load_toxic_pairs, matching_pairs, node_caps
from isovane_serve.insights import insight_for
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix
from isovane_serve.studio_models import CapabilityNode, ToxicFlow


def analyze_toxic_flows(
    workspace_id: str,
    *,
    graph: dict[str, Any] | None = None,
    folder: str | Path | None = None,
    persist_findings: bool = True,
) -> dict[str, Any]:
    """Build capability nodes + toxic flows; optionally upsert findings."""
    nodes: list[CapabilityNode] = []
    sources_used: list[str] = []

    if graph:
        g = normalize_graph(graph)
        for n in board_nodes(g):
            caps = sorted(node_caps(n))
            nodes.append(
                CapabilityNode(
                    id=str(n.get("id")),
                    label=str(n.get("label") or n.get("id")),
                    kind=str(n.get("kind") or "unknown"),
                    caps=caps,
                    source="board",
                    path=str(n.get("path")) if n.get("path") else None,
                )
            )
        sources_used.append("board")
        edges = board_edges(g)
    else:
        edges = []

    if folder:
        root = Path(folder).expanduser()
        if root.is_dir():
            mcp_nodes = _mcp_capability_nodes(root)
            nodes.extend(mcp_nodes)
            if mcp_nodes:
                sources_used.append("mcp")
            code_nodes = _code_tool_nodes(root)
            nodes.extend(code_nodes)
            if code_nodes:
                sources_used.append("code")

    # Dedupe by id keeping richest caps
    by_id: dict[str, CapabilityNode] = {}
    for n in nodes:
        prev = by_id.get(n.id)
        if not prev:
            by_id[n.id] = n
            continue
        merged = sorted(set(prev.caps) | set(n.caps))
        by_id[n.id] = prev.model_copy(
            update={
                "caps": merged,
                "source": "+".join(sorted({prev.source, n.source})),
            }
        )
    capability_nodes = list(by_id.values())

    # Aggregate caps for pair matching: also consider connected components via edges
    flows = _flows_from_nodes(capability_nodes, edges)
    findings = [_flow_to_finding(workspace_id, flow) for flow in flows]

    if persist_findings and findings:
        from isovane_serve import store
        from isovane_serve.remediations import hydrate_finding

        for f in findings:
            store.add_finding(hydrate_finding(f))

    payload = {
        "workspace_id": workspace_id,
        "flows": [f.model_dump(mode="json") for f in flows],
        "capability_graph": {
            "nodes": [n.model_dump(mode="json") for n in capability_nodes],
            "edges": edges,
            "sources": sources_used,
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "tags": f.tags,
            }
            for f in findings
        ],
    }
    _save_studio(workspace_id, "toxic_flows", payload)
    return payload


def last_toxic_flows(workspace_id: str) -> dict[str, Any] | None:
    return _load_studio(workspace_id).get("toxic_flows")


def _flows_from_nodes(
    nodes: list[CapabilityNode],
    edges: list[dict[str, str]],
) -> list[ToxicFlow]:
    flows: list[ToxicFlow] = []
    seen: set[str] = set()

    # Per-node pairs (single MCP/tool exposing both caps)
    for n in nodes:
        caps = set(n.caps)
        for pair in matching_pairs(caps):
            fid = f"{pair['id']}:{n.id}"
            if fid in seen:
                continue
            seen.add(fid)
            flows.append(
                ToxicFlow(
                    id=fid,
                    pair_id=str(pair["id"]),
                    label=str(pair["label"]),
                    severity=str(pair.get("severity") or "high"),
                    caps=sorted(pair["caps"]),
                    nodes=[n.id],
                    edges=[],
                    sources=[n.source],
                    finding_title=f"Toxic flow — {n.label}",
                )
            )

    # Cross-node pairs along edges (read node → exfil node)
    id_map = {n.id: n for n in nodes}
    for e in edges:
        a = id_map.get(str(e.get("from") or ""))
        b = id_map.get(str(e.get("to") or ""))
        if not a or not b:
            continue
        union = set(a.caps) | set(b.caps)
        for pair in matching_pairs(union):
            need = set(pair["caps"])
            # Require each side to contribute at least one needed cap when split
            if not (need & set(a.caps)) or not (need & set(b.caps)):
                # Still allow if one node alone has the pair (already covered)
                if need <= set(a.caps) or need <= set(b.caps):
                    continue
                continue
            fid = f"{pair['id']}:{a.id}->{b.id}"
            if fid in seen:
                continue
            seen.add(fid)
            flows.append(
                ToxicFlow(
                    id=fid,
                    pair_id=str(pair["id"]),
                    label=str(pair["label"]),
                    severity=str(pair.get("severity") or "high"),
                    caps=sorted(need),
                    nodes=[a.id, b.id],
                    edges=[{"from": a.id, "to": b.id, "kind": str(e.get("kind") or "link")}],
                    sources=sorted({a.source, b.source}),
                    finding_title=f"Toxic flow — {a.label} → {b.label}",
                )
            )

    # Workspace-wide union (agent that can reach both tool types)
    all_caps: set[str] = set()
    for n in nodes:
        all_caps |= set(n.caps)
    for pair in matching_pairs(all_caps):
        holders = [n for n in nodes if set(pair["caps"]) & set(n.caps)]
        if len(holders) < 2:
            continue
        fid = f"{pair['id']}:workspace"
        if fid in seen:
            continue
        # Only emit workspace aggregate when no per-node flow already covers it
        if any(f.pair_id == pair["id"] for f in flows):
            continue
        seen.add(fid)
        flows.append(
            ToxicFlow(
                id=fid,
                pair_id=str(pair["id"]),
                label=str(pair["label"]),
                severity=str(pair.get("severity") or "high"),
                caps=sorted(pair["caps"]),
                nodes=[h.id for h in holders[:8]],
                edges=[],
                sources=sorted({h.source for h in holders}),
                finding_title=f"Toxic flow — {pair['label']}",
            )
        )

    # Severity order
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    flows.sort(key=lambda f: (rank.get(f.severity, 9), f.id))
    return flows


def _flow_to_finding(workspace_id: str, flow: ToxicFlow) -> Finding:
    title = flow.finding_title or f"Toxic flow — {flow.label}"
    summary = (
        f"Toxic capability pair ({flow.label}) across {', '.join(flow.nodes) or 'workspace'}. "
        "An agent that can invoke these capabilities in one session can chain them "
        "without extra privileges (ASI02 / ASI04)."
    )
    checklist = [
        "Split tools across servers with least privilege",
        "Require HITL before exfil/shell tools",
        "Allow-list exact tool names — never '*'",
        "Deny cross-tool chaining in the policy gate",
        "Open Trust Studio → Toxic Flows to review the capability graph",
    ]
    insight = insight_for(title=title, issue_text=summary, tool="architecture-workflow")
    return Finding(
        workspace_id=workspace_id,
        source="analyze",
        severity=flow.severity if flow.severity in {"critical", "high", "medium", "low"} else "high",
        title=title,
        summary=summary,
        tags=["toxic-flow", "trust-studio", flow.pair_id, *flow.sources],
        owasp=["ASI02", "ASI04", "LLM06"],
        category="architecture",
        evidence=FindingEvidence(
            path=flow.nodes[0] if flow.nodes else None,
            snippet=f"caps={flow.caps} sources={flow.sources}",
            source_channel="toxic-flow",
            args={"flow_id": flow.id, "pair_id": flow.pair_id, "nodes": flow.nodes},
        ),
        suggested_fix=SuggestedFix(
            kind="architecture",
            summary="Split capabilities and insert HITL / policy gate on the board.",
            checklist=checklist,
            diff=(
                f"# Toxic flow ({flow.pair_id})\n"
                f"# nodes: {flow.nodes}\n"
                f"- combined caps {flow.caps}\n"
                f"+ split servers + HITL on high-impact side\n"
            ),
        ),
        policy_rule_id="arch-toxic-flow",
        exploit=insight.exploit or None,
        technical_details=insight.technical_details or None,
        solutions=list(insight.solutions or []) or checklist,
    )


def _mcp_capability_nodes(root: Path) -> list[CapabilityNode]:
    from isovane_serve.mcp_skills import _extract_mcp_servers, _try_parse_json
    from isovane_serve.yaml_config import skip_dir_names

    out: list[CapabilityNode] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dir_names() for part in path.parts):
            continue
        name = path.name.lower()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "mcpservers" not in text.lower() and name not in {
            "mcp.json",
            "claude_desktop_config.json",
        }:
            continue
        parsed = _try_parse_json(text)
        if not isinstance(parsed, dict):
            continue
        servers = _extract_mcp_servers(parsed)
        if not servers:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        for server, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            tools = _declared_tool_names(cfg)
            caps = sorted(classify_tools(tools) | classify_tools([str(server), str(cfg.get("command") or "")]))
            out.append(
                CapabilityNode(
                    id=f"mcp:{server}",
                    label=str(server),
                    kind="mcp",
                    caps=caps,
                    source="mcp",
                    path=rel,
                )
            )
    return out


def _declared_tool_names(cfg: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("tools", "allowedTools", "allowed_tools", "includeTools"):
        raw = cfg.get(key)
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    names.append(item)
                elif isinstance(item, dict):
                    n = item.get("name") or item.get("tool") or item.get("id")
                    if n:
                        names.append(str(n))
        elif isinstance(raw, str):
            names.append(raw)
    blob = " ".join(
        [
            str(cfg.get("description") or ""),
            " ".join(str(a) for a in (cfg.get("args") or []) if a),
            str(cfg.get("command") or ""),
        ]
    )
    if blob.strip():
        names.append(blob)
    return names


def _code_tool_nodes(root: Path) -> list[CapabilityNode]:
    try:
        from isovane_serve.workflow_inventory import inventory_from_tree
    except ImportError:
        return []
    inv = inventory_from_tree(root)
    out: list[CapabilityNode] = []
    for n in inv.get("nodes") or []:
        if not isinstance(n, dict):
            continue
        kind = str(n.get("kind") or "")
        if kind not in {"tool", "mcp", "agent", "data"}:
            continue
        caps = sorted(node_caps(n))
        if not caps:
            continue
        out.append(
            CapabilityNode(
                id=str(n.get("id") or n.get("label")),
                label=str(n.get("label") or n.get("id")),
                kind=kind,
                caps=caps,
                source="code",
                path=str(n.get("path")) if n.get("path") else None,
            )
        )
    return out


def _save_studio(workspace_id: str, key: str, payload: dict[str, Any]) -> None:
    from isovane_serve.persistence import save_studio_slice

    save_studio_slice(workspace_id, key, payload)


def _load_studio(workspace_id: str) -> dict[str, Any]:
    from isovane_serve.persistence import get_studio

    return get_studio(workspace_id) or {}


# Silence unused import warning for load_toxic_pairs (used by API catalog)
__all__ = ["analyze_toxic_flows", "last_toxic_flows", "load_toxic_pairs"]
