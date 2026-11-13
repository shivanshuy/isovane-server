"""Radar-class CrewAI / AutoGen inventory → board nodes."""

from __future__ import annotations

from pathlib import Path

from isovane_serve.framework_inventory import framework_graphs_from_tree
from isovane_serve.workflow_inventory import inventory_from_tree


def test_crewai_inventory_edges(tmp_path: Path):
    (tmp_path / "crew_app.py").write_text(
        """
from crewai import Agent, Task, Crew

researcher = Agent(role="researcher", goal="find", backstory="x")
writer = Agent(role="writer", goal="write", backstory="y")
task1 = Task(description="research", agent=researcher)
crew = Crew(agents=[researcher, writer], tasks=[task1])
""",
        encoding="utf-8",
    )
    fw = framework_graphs_from_tree(tmp_path)
    assert any(n["kind"] == "agent" for n in fw["nodes"])
    assert any(e["kind"].startswith("crew") for e in fw["edges"])

    inv = inventory_from_tree(tmp_path)
    assert inv.get("board")
    assert inv["board"]["nodes"]
    assert inv.get("framework_graphs")


def test_analyze_code_workflow_persists_board(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path / "data"))
    from isovane_serve import workspaces as ws
    from isovane_serve.diagram import analyze_code_workflow
    from isovane_serve.persistence import get_board

    ws.store = ws.WorkspaceStore()
    (tmp_path / "agent.py").write_text(
        "from langgraph.graph import StateGraph\n"
        "g = StateGraph(dict)\n"
        "g.add_node('a', lambda x: x)\n"
        "g.add_node('b', lambda x: x)\n"
        "g.add_edge('a', 'b')\n",
        encoding="utf-8",
    )
    result = analyze_code_workflow("checkout-agent", tmp_path, mode="workflow")
    assert result["inventory"]["board"]["nodes"]
    saved = get_board("checkout-agent")
    assert saved is not None
    assert saved.get("board")
