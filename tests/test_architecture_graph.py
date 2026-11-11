from isovane_serve.architecture_graph import (
    SCHEMA_ID,
    board_nodes,
    graph_to_mermaid,
    llm_payload,
    normalize_graph,
)
from isovane_serve.diagram import analyze_diagram


def test_normalize_graph_roundtrip():
    graph = normalize_graph(
        {
            "nodes": [
                {"id": "ui", "label": "Chat UI", "kind": "ui", "x": 10, "y": 20},
                {"id": "agent", "label": "Agent API", "kind": "agent"},
            ],
            "edges": [{"from": "ui", "to": "agent"}],
        },
        source="test",
    )
    assert graph.get("model")
    assert "softwareSystems" in graph["model"]
    assert graph["properties"]["isovane.source"] == "test"
    names = {s["name"] for s in graph["model"]["softwareSystems"]}
    assert "Chat UI" in names
    assert "Agent API" in names
    assert len(graph["model"]["relationships"]) == 1
    assert "Chat UI" in graph_to_mermaid(graph)
    # Board view still exposes kinds
    nodes = board_nodes(graph)
    assert {n["kind"] for n in nodes} == {"ui", "agent"}


def test_llm_payload_is_structurizr_workspace():
    graph = normalize_graph(
        {
            "nodes": [{"id": "ui", "label": "Chat UI", "kind": "ui"}],
            "edges": [],
        }
    )
    payload = llm_payload(graph, mode="privacy")
    assert payload["format"] == SCHEMA_ID
    assert payload["workspace"]["model"]["softwareSystems"][0]["name"] == "Chat UI"
    assert "ui" in payload["workspace"]["model"]["softwareSystems"][0]["tags"]
    assert "mermaid" in payload


def test_legacy_and_structurizr_normalize_to_same_shape():
    legacy = normalize_graph(
        {
            "nodes": [{"id": "a", "label": "Agent", "kind": "agent"}],
            "edges": [],
        }
    )
    again = normalize_graph(legacy)
    assert again["model"]["softwareSystems"][0]["name"] == "Agent"
    assert board_nodes(again)[0]["kind"] == "agent"


def test_analyze_prefers_provided_graph(monkeypatch):
    import isovane_serve.risk_diagram as rd
    from isovane_serve.models import Finding, FindingEvidence, SuggestedFix

    fake = Finding(
        workspace_id="ws",
        source="analyze",
        severity="high",
        title="From board graph",
        summary="Used edited graph",
        category="architecture",
        evidence=FindingEvidence(tool="architecture-llm"),
        suggested_fix=SuggestedFix(kind="architecture", summary="x", checklist=[]),
    )

    def capture(workspace_id, **kwargs):
        assert workspace_id == "ws"
        assert kwargs.get("graph")
        systems = kwargs["graph"]["model"]["softwareSystems"]
        assert systems[0]["name"] == "Edited UI"
        return {
            "findings": [fake],
            "provider": "ollama",
            "model": "llama3.1:8b",
            "graph": kwargs["graph"],
        }

    monkeypatch.setattr(rd, "analyze_risks_with_llm", capture)
    result = analyze_diagram(
        "ws",
        description="ignored when graph provided",
        mode="workflow",
        graph={
            "nodes": [{"id": "ui", "label": "Edited UI", "kind": "ui"}],
            "edges": [],
        },
    )
    assert result["inventory"]["nodes"][0]["label"] == "Edited UI"
    assert result["inventory"]["graph"]["model"]["softwareSystems"][0]["name"] == "Edited UI"
    assert result["findings"][0].title == "From board graph"
