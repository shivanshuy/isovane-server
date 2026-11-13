from isovane_serve.architecture_graph import graph_from_parts
from isovane_serve.trifecta import score_trifecta


def test_trifecta_complete(tmp_path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    graph = graph_from_parts(
        [
            {"id": "ui", "label": "Chat UI", "kind": "ui"},
            {"id": "crm", "label": "Customer CRM", "kind": "data"},
            {"id": "llm", "label": "OpenAI", "kind": "llm"},
            {"id": "mail", "label": "send_email", "kind": "tool"},
        ],
        [
            {"from": "ui", "to": "llm", "kind": "prompt"},
            {"from": "crm", "to": "llm", "kind": "context"},
            {"from": "llm", "to": "mail", "kind": "tool"},
        ],
        source="test",
    )
    result = score_trifecta("ws-tri", graph=graph)
    sc = result["scorecard"]
    assert sc["private_data"]["present"]
    assert sc["untrusted_ingress"]["present"]
    assert sc["egress"]["present"]
    assert sc["complete"] is True
    assert sc["severity"] == "critical"
