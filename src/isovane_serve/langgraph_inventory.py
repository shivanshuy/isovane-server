"""Parse LangGraph StateGraph wiring into board nodes/edges (Radar-class)."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from isovane_serve.yaml_config import skip_dir_names

_GRAPH_METHODS = {
    "add_node",
    "add_edge",
    "add_conditional_edges",
    "add_sequence",
    "set_entry_point",
    "set_finish_point",
    "set_conditional_entry_point",
}


def langgraph_graphs_from_tree(root: Path) -> dict[str, Any]:
    """Return nodes/edges extracted from StateGraph / create_react_agent wiring."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str, str]] = set()
    graphs_meta: list[dict[str, Any]] = []

    if not root.exists():
        return {"nodes": [], "edges": [], "graphs": [], "source": "langgraph"}

    for path in root.rglob("*.py"):
        if any(part in skip_dir_names() for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        file_nodes, file_edges, meta = _extract_file(rel, source, tree)
        graphs_meta.extend(meta)
        for node in file_nodes:
            key = str(node["id"])
            if key in seen_nodes:
                continue
            seen_nodes.add(key)
            nodes.append(node)
        for edge in file_edges:
            key = (edge["from"], edge["to"], str(edge.get("kind") or ""))
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(edge)

    return {
        "nodes": nodes,
        "edges": edges,
        "graphs": graphs_meta,
        "source": "langgraph",
    }


def _extract_file(
    rel: str, source: str, tree: ast.AST
) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[dict[str, Any]]]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    meta: list[dict[str, Any]] = []
    graph_vars: set[str] = set()
    uses_langgraph = "langgraph" in source or "StateGraph" in source or "create_react_agent" in source

    def ensure_node(label: str, *, kind: str | None = None) -> str:
        nid = f"lg:{rel}:{label}"
        if not any(n["id"] == nid for n in nodes):
            nodes.append(
                {
                    "id": nid,
                    "label": label,
                    "kind": kind or _kind_for_node(label),
                    "path": rel,
                }
            )
        return nid

    def add_edge(frm: str, to: str, kind: str) -> None:
        a = ensure_node(frm)
        b = ensure_node(to)
        edges.append({"from": a, "to": b, "kind": kind})

    class Visitor(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            val = node.value
            # builder = StateGraph(...)
            if isinstance(val, ast.Call) and _call_name(val.func) == "StateGraph":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        graph_vars.add(target.id)
                        meta.append({"var": target.id, "path": rel, "kind": "StateGraph"})
            # agent = create_react_agent(...)
            if isinstance(val, ast.Call) and _call_name(val.func) == "create_react_agent":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        ensure_node(target.id, kind="agent")
                        meta.append({"var": target.id, "path": rel, "kind": "create_react_agent"})
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            # Bare create_react_agent(...) without assign
            if _call_name(node.func) == "create_react_agent":
                ensure_node("react_agent", kind="agent")
                meta.append({"var": "react_agent", "path": rel, "kind": "create_react_agent"})

            if isinstance(node.func, ast.Attribute):
                method = node.func.attr
                owner = _owner_name(node.func.value)
                is_graph = False
                if owner and owner in graph_vars:
                    is_graph = True
                elif uses_langgraph and method in _GRAPH_METHODS and owner:
                    # Heuristic: *graph* / *builder* / *workflow* / *app* vars
                    low = owner.lower()
                    if any(t in low for t in ("graph", "builder", "workflow", "app", "sg")):
                        is_graph = True
                        graph_vars.add(owner)

                if is_graph and method in _GRAPH_METHODS:
                    if method == "add_node" and node.args:
                        name = _const_str(node.args[0])
                        if name:
                            ensure_node(name)
                    elif method == "add_edge" and len(node.args) >= 2:
                        a, b = _const_str(node.args[0]), _const_str(node.args[1])
                        if a and b:
                            add_edge(a, b, "langgraph")
                    elif method == "add_sequence" and node.args:
                        seq = _sequence_labels(node.args[0])
                        for left, right in zip(seq, seq[1:]):
                            add_edge(left, right, "langgraph")
                    elif method == "set_entry_point" and node.args:
                        dest = _const_str(node.args[0])
                        if dest:
                            add_edge("START", dest, "langgraph")
                    elif method == "set_finish_point" and node.args:
                        src = _const_str(node.args[0])
                        if src:
                            add_edge(src, "END", "langgraph")
                    elif method == "set_conditional_entry_point":
                        for dest in _path_map_destinations(node):
                            add_edge("START", dest, "conditional")
                    elif method == "add_conditional_edges" and node.args:
                        src = _const_str(node.args[0])
                        if src:
                            dests = _path_map_destinations(node)
                            # Also accept list/tuple of destinations as 3rd arg
                            if len(node.args) >= 3 and not dests:
                                dests = _sequence_labels(node.args[2])
                            for dest in dests:
                                add_edge(src, dest, "conditional")

                # graph.compile(interrupt_before=[...]) → HITL markers
                if is_graph and method == "compile":
                    for kw in node.keywords:
                        if kw.arg in {"interrupt_before", "interrupt_after"}:
                            for label in _sequence_labels(kw.value):
                                ensure_node(label, kind="hitl")
                                meta.append(
                                    {
                                        "var": owner,
                                        "path": rel,
                                        "kind": kw.arg,
                                        "nodes": [label],
                                    }
                                )

            self.generic_visit(node)

    Visitor().visit(tree)
    return nodes, edges, meta


def _path_map_destinations(call: ast.Call) -> list[str]:
    """Collect destination node names from add_conditional_edges path maps."""
    dests: list[str] = []

    def from_dict(d: ast.Dict) -> None:
        # path_map values are node names; keys are route labels
        for val in d.values:
            name = _const_str(val)
            if name:
                dests.append(name)
            elif isinstance(val, (ast.List, ast.Tuple)):
                dests.extend(_sequence_labels(val))

    # Positional path map (3rd arg)
    if len(call.args) >= 3 and isinstance(call.args[2], ast.Dict):
        from_dict(call.args[2])

    for kw in call.keywords:
        if kw.arg in {"path_map", "then", "path"} and isinstance(kw.value, ast.Dict):
            from_dict(kw.value)
        if kw.arg in {"path_map", "then"} and isinstance(kw.value, (ast.List, ast.Tuple)):
            dests.extend(_sequence_labels(kw.value))

    # Dedupe preserve order
    out: list[str] = []
    seen: set[str] = set()
    for d in dests:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _sequence_labels(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        out: list[str] = []
        for elt in node.elts:
            name = _const_str(elt)
            if name:
                out.append(name)
        return out
    name = _const_str(node)
    return [name] if name else []


def _owner_name(value: ast.AST) -> str | None:
    if isinstance(value, ast.Name):
        return value.id
    return None


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _const_str(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in {"START", "END"}:
        return node.id
    if isinstance(node, ast.Attribute) and node.attr in {"START", "END"}:
        return node.attr
    return None


def _kind_for_node(name: str) -> str:
    lower = name.lower()
    if any(t in lower for t in ("hitl", "human", "approve", "interrupt", "review")):
        return "hitl"
    if any(t in lower for t in ("tool", "search", "shell", "email", "refund", "browser")):
        return "tool"
    if "mcp" in lower:
        return "mcp"
    if any(t in lower for t in ("llm", "model", "chat", "openai", "anthropic")):
        return "llm"
    if any(t in lower for t in ("ui", "input", "intake", "frontend")):
        return "ui"
    if any(t in lower for t in ("data", "db", "store", "memory", "retriev", "rag")):
        return "data"
    if lower in {"start", "end"}:
        return "unknown"
    return "agent"
