"""Infer Agentic Radar–style workflow inventory from a source tree."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from isovane_serve.yaml_config import skip_dir_names

_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("agent", "LangGraph create_react_agent", re.compile(r"\bcreate_react_agent\s*\(")),
    ("agent", "LangGraph StateGraph", re.compile(r"\bStateGraph\s*\(")),
    ("agent", "CrewAI Agent", re.compile(r"\bfrom\s+crewai\b|\bAgent\s*\(\s*role\s*=")),
    ("agent", "CrewAI Crew", re.compile(r"\bCrew\s*\(")),
    ("agent", "AutoGen agent", re.compile(r"\bautogen\b|\bAssistantAgent\s*\(")),
    ("agent", "OpenAI Agents", re.compile(r"\bfrom\s+agents\s+import\b|\bAgent\s*\(.*instructions\s*=")),
    ("mcp", "MCP server config", re.compile(r"['\"]mcpServers['\"]|\bmcp\s*=\s*FastMCP\b|\bFastMCP\s*\(")),
    ("mcp", "MCP client session", re.compile(r"\bClientSession\b|\bstdio_client\b")),
    ("tool", "bind_tools", re.compile(r"\.bind_tools\s*\(")),
    ("tool", "LangChain tool", re.compile(r"@tool\b|\bStructuredTool\b")),
    ("tool", "Web search tool", re.compile(r"duckduckgo_search|TavilySearch|get_web_search_tools")),
    ("llm", "ChatOpenAI", re.compile(r"\bChatOpenAI\s*\(")),
    ("llm", "ChatAnthropic", re.compile(r"\bChatAnthropic\s*\(")),
    ("llm", "AzureChatOpenAI", re.compile(r"\bAzureChatOpenAI\s*\(")),
    ("ui", "Gradio / Streamlit / FastAPI chat", re.compile(r"\bgr\.ChatInterface\b|\bst\.chat_message\b|/chat\b")),
    ("hitl", "interrupt / human approval", re.compile(r"\binterrupt\s*\(|\bHumanMessage\b.*confirm|require_confirm|hitl", re.I)),
]


def inventory_from_tree(root: Path) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    if not root.exists():
        return {"nodes": [], "edges": [], "counts": {}, "by_kind": {}, "source": "code"}

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dir_names() for part in path.parts):
            continue
        if path.suffix.lower() not in {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".yml", ".yaml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for kind, label, pattern in _PATTERNS:
            if not pattern.search(text):
                continue
            key = (kind, f"{label}@{rel}")
            if key in seen:
                continue
            seen.add(key)
            node_id = f"{kind}:{len(nodes)}"
            nodes.append(
                {
                    "id": node_id,
                    "kind": kind,
                    "label": label,
                    "path": rel,
                }
            )

    # LangGraph StateGraph add_node / add_edge → real topology (preferred over synthetic).
    lg_meta: list[dict[str, Any]] = []
    fw_meta: list[dict[str, Any]] = []
    try:
        from isovane_serve.langgraph_inventory import langgraph_graphs_from_tree

        lg = langgraph_graphs_from_tree(root)
        lg_meta = list(lg.get("graphs") or [])
        if lg.get("nodes"):
            # Drop coarse "LangGraph StateGraph" keyword node when we have real nodes
            nodes = [
                n
                for n in nodes
                if n.get("label") != "LangGraph StateGraph"
            ]
            nodes.extend(lg["nodes"])
            edges.extend(lg.get("edges") or [])
    except Exception:  # noqa: BLE001
        pass

    # CrewAI / AutoGen / OpenAI Agents → Radar-class board nodes/edges
    try:
        from isovane_serve.framework_inventory import framework_graphs_from_tree

        fw = framework_graphs_from_tree(root)
        fw_meta = list(fw.get("graphs") or [])
        if fw.get("nodes"):
            # Prefer framework-extracted agents over coarse keyword duplicates
            coarse = {
                "CrewAI Agent",
                "CrewAI Crew",
                "AutoGen agent",
                "OpenAI Agents",
            }
            nodes = [n for n in nodes if n.get("label") not in coarse]
            nodes.extend(fw["nodes"])
            edges.extend(fw.get("edges") or [])
    except Exception:  # noqa: BLE001
        pass

    # Synthetic edges for report when no framework edges: UI → agents → MCP/tools → LLM
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        by_kind.setdefault(node["kind"], []).append(node)
    structured = {
        "langgraph",
        "conditional",
        "crew→agent",
        "crew→task",
        "a2a",
        "agent→tool",
    }
    if not any(e.get("kind") in structured for e in edges):
        for ui in by_kind.get("ui", [])[:3]:
            for agent in by_kind.get("agent", [])[:5]:
                edges.append({"from": ui["id"], "to": agent["id"], "kind": "ui→agent"})
        for agent in by_kind.get("agent", [])[:5]:
            for mcp in by_kind.get("mcp", [])[:5]:
                edges.append({"from": agent["id"], "to": mcp["id"], "kind": "agent→mcp"})
            for tool in by_kind.get("tool", [])[:5]:
                edges.append({"from": agent["id"], "to": tool["id"], "kind": "agent→tool"})
            for llm in by_kind.get("llm", [])[:3]:
                edges.append({"from": agent["id"], "to": llm["id"], "kind": "agent→llm"})

    from isovane_serve.architecture_graph import graph_from_parts

    # Layout for board when opened from code inventory
    for index, node in enumerate(nodes):
        col = {"ui": 0, "hitl": 1, "agent": 2, "mcp": 3, "tool": 3, "llm": 4, "data": 4}.get(
            str(node.get("kind")), 2
        )
        row = sum(1 for n in nodes[:index] if n.get("kind") == node.get("kind"))
        node.setdefault("x", 36 + col * 180)
        node.setdefault("y", 36 + row * 96)

    # Refresh by_kind after framework merge
    by_kind = {}
    for node in nodes:
        by_kind.setdefault(str(node.get("kind")), []).append(node)

    workspace = graph_from_parts(nodes, edges, source="code_inventory", filename=str(root.name))
    return {
        "nodes": nodes,
        "edges": edges,
        "counts": {k: len(v) for k, v in by_kind.items()},
        "by_kind": {k: [n["label"] for n in v] for k, v in by_kind.items()},
        "source": "code",
        "langgraph_graphs": lg_meta,
        "framework_graphs": fw_meta,
        "graph": workspace,
        "board": {"nodes": nodes, "edges": edges},
    }


def inventory_as_diagram_text(inv: dict[str, Any]) -> str:
    """Flatten code inventory into text the workflow analyzer understands."""
    lines = ["workflow inventory from source", "agentic radar style"]
    for node in inv.get("nodes") or []:
        lines.append(f"{node.get('kind')} {node.get('label')} path={node.get('path')}")
    for edge in inv.get("edges") or []:
        lines.append(f"{edge.get('from')} --> {edge.get('to')} {edge.get('kind')}")
    if inv.get("counts"):
        lines.append(f"counts {inv['counts']}")
    return "\n".join(lines)
