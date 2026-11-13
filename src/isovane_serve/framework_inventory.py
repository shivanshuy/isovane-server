"""Extra agent-framework inventory (CrewAI / AutoGen / OpenAI Agents) for Radar-class boards.

Complements ``langgraph_inventory`` AST extraction. Heuristic + light AST only —
no execution of project code.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from isovane_serve.yaml_config import skip_dir_names

_CREW_IMPORT = re.compile(r"(?m)^\s*(from\s+crewai\b|import\s+crewai\b)")
_AUTOGEN_IMPORT = re.compile(r"(?m)^\s*(from\s+autogen\b|import\s+autogen\b|from\s+autogen_agentchat\b)")
_OPENAI_AGENTS = re.compile(r"(?m)^\s*from\s+agents\s+import\b")


def framework_graphs_from_tree(root: Path) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    graphs: list[dict[str, Any]] = []
    if not root.exists():
        return {"nodes": nodes, "edges": edges, "graphs": graphs}

    for path in root.rglob("*.py"):
        if any(part in skip_dir_names() for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        if _CREW_IMPORT.search(text):
            g = _crew_from_text(text, rel)
            if g["nodes"]:
                graphs.append({"framework": "crewai", "path": rel, **g})
                nodes.extend(g["nodes"])
                edges.extend(g["edges"])
        if _AUTOGEN_IMPORT.search(text):
            g = _autogen_from_text(text, rel)
            if g["nodes"]:
                graphs.append({"framework": "autogen", "path": rel, **g})
                nodes.extend(g["nodes"])
                edges.extend(g["edges"])
        if _OPENAI_AGENTS.search(text):
            g = _openai_agents_from_ast(text, rel)
            if g["nodes"]:
                graphs.append({"framework": "openai-agents", "path": rel, **g})
                nodes.extend(g["nodes"])
                edges.extend(g["edges"])

    return {"nodes": nodes, "edges": edges, "graphs": graphs}


def _crew_from_text(text: str, rel: str) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    agents = re.findall(
        r"(?m)^(\w+)\s*=\s*Agent\s*\(",
        text,
    )
    tasks = re.findall(r"(?m)^(\w+)\s*=\s*Task\s*\(", text)
    crews = re.findall(r"(?m)^(\w+)\s*=\s*Crew\s*\(", text)
    for name in agents:
        nid = f"crew-agent:{rel}:{name}"
        nodes.append({"id": nid, "kind": "agent", "label": f"CrewAI Agent {name}", "path": rel})
    for name in tasks:
        nid = f"crew-task:{rel}:{name}"
        nodes.append({"id": nid, "kind": "tool", "label": f"CrewAI Task {name}", "path": rel})
    for name in crews:
        nid = f"crew:{rel}:{name}"
        nodes.append({"id": nid, "kind": "agent", "label": f"CrewAI Crew {name}", "path": rel})
        for agent in agents:
            edges.append(
                {
                    "from": nid,
                    "to": f"crew-agent:{rel}:{agent}",
                    "kind": "crew→agent",
                }
            )
        for task in tasks:
            edges.append(
                {
                    "from": nid,
                    "to": f"crew-task:{rel}:{task}",
                    "kind": "crew→task",
                }
            )
    if "Process.hierarchical" in text or "hierarchical" in text.lower():
        nodes.append(
            {
                "id": f"crew-hitl:{rel}",
                "kind": "hitl",
                "label": "CrewAI hierarchical process",
                "path": rel,
            }
        )
    return {"nodes": nodes, "edges": edges}


def _autogen_from_text(text: str, rel: str) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    agents = re.findall(
        r"(?m)^(\w+)\s*=\s*(?:AssistantAgent|UserProxyAgent|ConversableAgent)\s*\(",
        text,
    )
    for name in agents:
        kind = "hitl" if "UserProxy" in text and name.lower().startswith("user") else "agent"
        # Better: inspect the constructor used on that line
        kind = "agent"
        for m in re.finditer(
            rf"(?m)^{re.escape(name)}\s*=\s*(AssistantAgent|UserProxyAgent|ConversableAgent)\s*\(",
            text,
        ):
            kind = "hitl" if m.group(1) == "UserProxyAgent" else "agent"
        nid = f"autogen:{rel}:{name}"
        nodes.append(
            {
                "id": nid,
                "kind": kind,
                "label": f"AutoGen {name}",
                "path": rel,
            }
        )
    # Pairwise chat edges when initiate_chat present
    if "initiate_chat" in text and len(agents) >= 2:
        a0 = f"autogen:{rel}:{agents[0]}"
        a1 = f"autogen:{rel}:{agents[1]}"
        edges.append({"from": a0, "to": a1, "kind": "a2a"})
    return {"nodes": nodes, "edges": edges}


def _openai_agents_from_ast(text: str, rel: str) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {"nodes": nodes, "edges": edges}

    class V(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            if not isinstance(node.value, ast.Call):
                return
            func = node.value.func
            name = ""
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name != "Agent":
                return
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            label = targets[0] if targets else "Agent"
            nid = f"oai-agent:{rel}:{label}"
            nodes.append(
                {
                    "id": nid,
                    "kind": "agent",
                    "label": f"OpenAI Agent {label}",
                    "path": rel,
                }
            )
            for kw in node.value.keywords:
                if kw.arg == "tools":
                    nodes.append(
                        {
                            "id": f"oai-tools:{rel}:{label}",
                            "kind": "tool",
                            "label": f"tools@{label}",
                            "path": rel,
                        }
                    )
                    edges.append(
                        {
                            "from": nid,
                            "to": f"oai-tools:{rel}:{label}",
                            "kind": "agent→tool",
                        }
                    )

    V().visit(tree)
    return {"nodes": nodes, "edges": edges}
