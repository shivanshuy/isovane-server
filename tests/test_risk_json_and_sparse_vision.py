"""Risk JSON parsing + sparse vision → fixture seed."""

from __future__ import annotations

from isovane_serve.diagram import analyze_upload_bytes, _count_nodes
from isovane_serve.risk_diagram import _extract_json


def test_extract_json_nested_fenced():
    raw = (
        "Here you go:\n```json\n"
        '{"findings":[{"title":"Missing HITL","summary":"Agent reaches shell without approval.",'
        '"severity":"high","region":"agent→tool","tags":["Workflow"],"owasp":["LLM06"],'
        '"checklist":["Add HITL"],"fix_summary":"Add HITL","meta":{"nested":true}}]}\n'
        "```\nThanks"
    )
    data = _extract_json(raw)
    assert data is not None
    assert data["findings"][0]["title"] == "Missing HITL"
    assert data["findings"][0]["meta"]["nested"] is True


def test_extract_json_list_wrapped():
    raw = '[{"title":"A","summary":"B"}]'
    data = _extract_json(raw)
    assert data == {"findings": [{"title": "A", "summary": "B"}]}


def test_extract_json_single_quotes_repaired():
    raw = "{'findings':[{'title':'A','summary':'B'}]}"
    data = _extract_json(raw)
    assert data is not None
    assert data["findings"][0]["title"] == "A"


def test_count_nodes_from_graph_json():
    text = (
        'GRAPH_JSON:\n{"nodes":[{"id":"a","label":"A"},{"id":"b","label":"B"}],'
        '"edges":[{"from":"a","to":"b"}]}'
    )
    assert _count_nodes(text) == 2


def test_sparse_vision_uses_richer_fixture_seed(monkeypatch):
    """llava often returns UI+agent only; fixture seed should restore full board."""

    def fake_extract(data, filename):
        return {
            "text": (
                "DIAGRAM:\nChat UI --> Orchestrator agent\n"
                "NODES:\n- Chat UI\n- Orchestrator agent\n"
                "GRAPH_JSON:\n"
                '{"nodes":['
                '{"id":"ui","label":"Chat UI","kind":"ui","x":40,"y":40},'
                '{"id":"orch","label":"Orchestrator agent","kind":"agent","x":220,"y":40}'
                '],"edges":[{"from":"ui","to":"orch","kind":"link"}]}'
            ),
            "provider": "ollama",
            "model": "llava",
            "filename": filename,
        }

    import isovane_serve.vision_diagram as vd
    import isovane_serve.risk_diagram as rd

    monkeypatch.setattr(vd, "extract_diagram_text_from_image", fake_extract)
    monkeypatch.setattr(
        rd,
        "analyze_risks_with_llm",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("force rules")),
    )

    result = analyze_upload_bytes(
        "ws",
        b"\x89PNG\r\n\x1a\n" + b"0" * 32,
        "02-workflow-agentic-no-hitl.png",
        format_hint="image",
        mode="workflow",
    )
    inv = result["inventory"]
    assert inv["vision"]["status"] == "seeded"
    assert inv["vision"]["source"] == "vision+seed"
    board = inv.get("board") or {}
    nodes = board.get("nodes") or inv.get("nodes") or []
    edges = board.get("edges") or inv.get("edges") or []
    labels = {str(n.get("label")) for n in nodes}
    assert len(nodes) >= 5
    assert len(edges) >= 5
    assert "Chat UI" in labels
    assert any("MCP" in lbl or "Research" in lbl or "Writer" in lbl for lbl in labels)
