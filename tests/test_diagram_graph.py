from isovane_serve.diagram import analyze_diagram
from isovane_serve.diagram_graph import graph_from_text, parse_graph_json


def _force_rules(monkeypatch):
    import isovane_serve.risk_diagram as rd

    monkeypatch.setattr(
        rd,
        "analyze_risks_with_llm",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("force rules")),
    )


def test_parse_graph_json_block():
    text = """
DIAGRAM:
Chat UI --> Agent
GRAPH_JSON:
{"nodes":[{"id":"ui","label":"Chat UI","kind":"ui"},{"id":"ag","label":"Agent","kind":"agent"}],"edges":[{"from":"ui","to":"ag"}]}
"""
    data = parse_graph_json(text)
    assert data is not None
    assert len(data["nodes"]) == 2


def test_graph_from_arrows_and_layout():
    graph = graph_from_text(
        """
        Chat UI --> Orchestrator agent
        Orchestrator agent --> MCP filesystem
        Orchestrator agent --> OpenAI
        """
    )
    assert len(graph["nodes"]) >= 3
    assert len(graph["edges"]) >= 2
    assert all("x" in n and "y" in n for n in graph["nodes"])
    assert "flowchart" in graph["mermaid"]


def test_analyze_diagram_includes_board(monkeypatch):
    _force_rules(monkeypatch)
    result = analyze_diagram(
        "ws",
        description="""
        flowchart LR
          UI[Chat UI] --> Orch[Orchestrator agent]
          Orch --> MCP[MCP server]
          Orch --> Shell[shell tool]
        """,
        format_hint="mermaid",
        mode="workflow",
        filename="wf.mmd",
    )
    inv = result["inventory"]
    assert inv.get("board")
    assert inv["board"]["nodes"]
    assert inv.get("edges") is not None
