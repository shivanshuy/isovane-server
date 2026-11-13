from isovane_serve.architecture_graph import graph_from_parts
from isovane_serve.toxic_flows import analyze_toxic_flows


def test_toxic_flow_on_board_exfil_pair():
    graph = graph_from_parts(
        [
            {"id": "ui", "label": "Chat UI", "kind": "ui"},
            {"id": "agent", "label": "Agent", "kind": "agent"},
            {"id": "read", "label": "read_file", "kind": "tool"},
            {"id": "mail", "label": "send_email", "kind": "tool"},
        ],
        [
            {"from": "ui", "to": "agent", "kind": "prompt"},
            {"from": "agent", "to": "read", "kind": "tool"},
            {"from": "agent", "to": "mail", "kind": "tool"},
        ],
        source="test",
    )
    result = analyze_toxic_flows("ws-tf", graph=graph, persist_findings=False)
    assert result["flows"]
    labels = " ".join(f["label"] for f in result["flows"])
    assert "exfil" in labels.lower() or "email" in labels.lower() or "read" in labels.lower()
    assert result["capability_graph"]["nodes"]
