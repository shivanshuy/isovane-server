from isovane_serve.diagram import analyze_upload_bytes


def _force_rules(monkeypatch):
    import isovane_serve.risk_diagram as rd

    monkeypatch.setattr(
        rd,
        "analyze_risks_with_llm",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("force rules")),
    )


def test_vision_fail_tries_ocr_then_seed(monkeypatch):
    import isovane_serve.vision_diagram as vd
    import isovane_serve.ocr_diagram as od

    _force_rules(monkeypatch)
    monkeypatch.setattr(
        vd,
        "extract_diagram_text_from_image",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("mllama crash")),
    )

    def fake_ocr(data, filename):
        return {
            "text": (
                "DIAGRAM:\nChat UI --> Agent API\nAgent API --> OpenAI\n"
                "GRAPH_JSON:\n"
                '{"nodes":[{"id":"ui","label":"Chat UI","kind":"ui"},'
                '{"id":"agent","label":"Agent API","kind":"agent"},'
                '{"id":"openai","label":"OpenAI","kind":"llm"}],'
                '"edges":[{"from":"ui","to":"agent"},{"from":"agent","to":"openai"}]}'
            ),
            "provider": "ocr",
            "model": "tesseract",
            "label_count": 3,
            "edge_count": 2,
        }

    monkeypatch.setattr(od, "extract_diagram_text_via_ocr", fake_ocr)

    result = analyze_upload_bytes(
        "ws",
        b"\x89PNG\r\n\x1a\n" + b"0" * 32,
        "custom-arch.png",
        format_hint="image",
        mode="privacy",
    )
    vision = result["inventory"]["vision"]
    assert vision["status"] == "ocr_fallback"
    assert "Vision LLM failed" in vision["message"] or "OCR" in vision["message"]
    edges = (result["inventory"].get("board") or {}).get("edges") or []
    assert len(edges) >= 2


def test_vision_and_ocr_fail_uses_fixture_seed(monkeypatch):
    import isovane_serve.vision_diagram as vd
    import isovane_serve.ocr_diagram as od

    _force_rules(monkeypatch)
    monkeypatch.setattr(
        vd,
        "extract_diagram_text_from_image",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("mllama")),
    )
    monkeypatch.setattr(
        od,
        "extract_diagram_text_via_ocr",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("tesseract missing")),
    )

    result = analyze_upload_bytes(
        "ws",
        b"\x89PNG\r\n\x1a\n" + b"0" * 32,
        "01-privacy-multi-cloud-egress.png",
        format_hint="image",
        mode="privacy",
    )
    vision = result["inventory"]["vision"]
    assert vision["status"] == "fallback"
    assert "OCR" in vision["message"]
    assert vision.get("ocr_error")
    edges = (result["inventory"].get("board") or {}).get("edges") or []
    assert len(edges) >= 5
