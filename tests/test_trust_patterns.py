from isovane_serve.architecture_graph import board_nodes, graph_from_parts
from isovane_serve.trust_patterns import apply_pattern, list_patterns


def test_list_patterns_nonempty():
    patterns = list_patterns()
    ids = {p.id for p in patterns}
    assert "hitl-gate" in ids
    assert "dual-llm" in ids


def test_apply_hitl_pattern(tmp_path, monkeypatch):
    monkeypatch.setenv("ISOVANE_DATA_DIR", str(tmp_path))
    from isovane_serve.persistence import save_board

    graph = graph_from_parts(
        [
            {"id": "agent", "label": "Agent", "kind": "agent"},
            {"id": "tool", "label": "shell", "kind": "tool"},
        ],
        [{"from": "agent", "to": "tool", "kind": "invoke"}],
        source="test",
    )
    save_board("ws-pat", {"graph": graph})
    result = apply_pattern("ws-pat", "hitl-gate")
    assert result["ok"]
    kinds = {n["kind"] for n in board_nodes(result["graph"])}
    assert "hitl" in kinds
