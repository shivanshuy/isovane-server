from pathlib import Path

from isovane_serve.langgraph_inventory import langgraph_graphs_from_tree
from isovane_serve.workflow_inventory import inventory_from_tree


def test_langgraph_add_node_edge_and_conditional(tmp_path: Path):
    (tmp_path / "graph.py").write_text(
        """
from langgraph.graph import StateGraph, START, END

def route(state):
    return "tools" if state.get("x") else "end"

builder = StateGraph(dict)
builder.add_node("intake", ingest)
builder.add_node("agent", agent)
builder.add_node("tools", tools)
builder.add_node("hitl_approve", approve)
builder.add_edge(START, "intake")
builder.add_edge("intake", "agent")
builder.add_conditional_edges(
    "agent",
    route,
    {"tools": "tools", "end": END},
)
builder.add_edge("tools", "hitl_approve")
builder.add_edge("hitl_approve", END)
app = builder.compile(interrupt_before=["tools"])
""",
        encoding="utf-8",
    )
    lg = langgraph_graphs_from_tree(tmp_path)
    labels = {n["label"] for n in lg["nodes"]}
    assert {"intake", "agent", "tools", "hitl_approve", "START", "END"} <= labels
    assert any(n["label"] == "tools" and n["kind"] == "hitl" for n in lg["nodes"]) or any(
        n["label"] == "hitl_approve" and n["kind"] == "hitl" for n in lg["nodes"]
    )
    assert any(e["kind"] == "conditional" for e in lg["edges"])
    assert any(
        e["from"].endswith(":agent") and e["to"].endswith(":tools") and e["kind"] == "conditional"
        for e in lg["edges"]
    )
    assert any(
        e["from"].endswith(":START") and e["to"].endswith(":intake") for e in lg["edges"]
    )

    inv = inventory_from_tree(tmp_path)
    assert inv.get("graph", {}).get("model", {}).get("softwareSystems")
    board_labels = {n["label"] for n in inv["board"]["nodes"]}
    assert "agent" in board_labels
    assert any(e.get("kind") in {"langgraph", "conditional"} for e in inv["edges"])


def test_langgraph_entry_finish_and_react_agent(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        """
from langgraph.graph import StateGraph
from langgraph.prebuilt import create_react_agent

graph = StateGraph(dict)
graph.add_node("research", research)
graph.set_entry_point("research")
graph.set_finish_point("research")
agent = create_react_agent(model, tools)
""",
        encoding="utf-8",
    )
    lg = langgraph_graphs_from_tree(tmp_path)
    labels = {n["label"] for n in lg["nodes"]}
    assert "research" in labels
    assert "agent" in labels or "react_agent" in labels
    assert any(e["from"].endswith(":START") for e in lg["edges"])
    assert any(e["to"].endswith(":END") for e in lg["edges"])


def test_langgraph_add_sequence(tmp_path: Path):
    (tmp_path / "seq.py").write_text(
        """
from langgraph.graph import StateGraph
g = StateGraph(dict)
g.add_sequence(["a", "b", "c"])
""",
        encoding="utf-8",
    )
    lg = langgraph_graphs_from_tree(tmp_path)
    labels = {n["label"] for n in lg["nodes"]}
    assert {"a", "b", "c"} <= labels
    assert any(e["from"].endswith(":a") and e["to"].endswith(":b") for e in lg["edges"])
