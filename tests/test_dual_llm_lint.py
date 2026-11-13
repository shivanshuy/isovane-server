from isovane_serve.architecture_graph import board_nodes, graph_from_parts
from isovane_serve.dual_llm_lint import lint_dual_llm
from isovane_serve.dual_llm_rewrite import apply_dual_llm


def test_dual_llm_lint_detects_gap(tmp_path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    graph = graph_from_parts(
        [
            {"id": "ui", "label": "Chat UI", "kind": "ui"},
            {"id": "agent", "label": "Support Agent", "kind": "agent"},
            {"id": "mail", "label": "send_email", "kind": "tool"},
        ],
        [
            {"from": "ui", "to": "agent", "kind": "prompt"},
            {"from": "agent", "to": "mail", "kind": "tool"},
        ],
        source="test",
    )
    result = lint_dual_llm("ws-dual", graph, persist_findings=False)
    assert result["verdicts"]
    assert result["verdicts"][0]["has_privileged_tools"]


def test_dual_llm_apply_rewrites_board(tmp_path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    from isovane_serve.persistence import save_board

    graph = graph_from_parts(
        [
            {"id": "ui", "label": "Chat UI", "kind": "ui"},
            {"id": "agent", "label": "Agent", "kind": "agent"},
            {"id": "mail", "label": "send_email", "kind": "tool"},
        ],
        [
            {"from": "ui", "to": "agent", "kind": "prompt"},
            {"from": "agent", "to": "mail", "kind": "tool"},
        ],
        source="test",
    )
    save_board("ws-dual2", {"graph": graph, "board": {"nodes": board_nodes(graph)}})
    result = apply_dual_llm("ws-dual2")
    assert result["ok"]
    labels = " ".join(n["label"].lower() for n in board_nodes(result["graph"]))
    assert "quarantined" in labels
    assert "privileged" in labels
