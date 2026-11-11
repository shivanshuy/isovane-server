from isovane_serve.diagram import analyze_upload_bytes
from isovane_serve.model_config import clear_model_config_cache, load_model_config
from isovane_serve.vision_diagram import extract_diagram_text_from_image


def test_model_config_defaults_ollama(tmp_path, monkeypatch):
    clear_model_config_cache()
    cfg_path = tmp_path / "models.yaml"
    cfg_path.write_text(
        """
MODEL_PROVIDER: ollama
ollama:
  base_url: http://127.0.0.1:11434
  arc_image_extract: llama3.2-vision
  arc_image_analyze: llama3.1:8b
openai:
  arc_image_extract: gpt-4o
  arc_image_analyze: gpt-4o-mini
  api_key_env: OPENAI_API_KEY
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("ISOVANE_MODEL_PROVIDER", raising=False)
    monkeypatch.setenv("ISOVANE_MODELS_CONFIG", str(cfg_path))
    clear_model_config_cache()
    cfg = load_model_config()
    assert cfg["MODEL_PROVIDER"] == "ollama"
    assert cfg["ollama"]["arc_image_extract"] == "llama3.2-vision"
    assert cfg["ollama"]["arc_image_analyze"] == "llama3.1:8b"


def test_model_config_env_override(tmp_path, monkeypatch):
    clear_model_config_cache()
    cfg_path = tmp_path / "models.yaml"
    cfg_path.write_text(
        "MODEL_PROVIDER: ollama\nollama:\n  arc_image_extract: llama3.2-vision\n  arc_image_analyze: llama3.1:8b\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ISOVANE_MODELS_CONFIG", str(cfg_path))
    monkeypatch.setenv("ISOVANE_MODEL_PROVIDER", "openai")
    monkeypatch.setenv("ISOVANE_OPENAI_ARC_IMAGE_EXTRACT", "gpt-4o-mini")
    monkeypatch.setenv("ISOVANE_OPENAI_ARC_IMAGE_ANALYZE", "gpt-4o-mini")
    clear_model_config_cache()
    cfg = load_model_config()
    assert cfg["MODEL_PROVIDER"] == "openai"
    assert cfg["openai"]["arc_image_extract"] == "gpt-4o-mini"
    assert cfg["openai"]["arc_image_analyze"] == "gpt-4o-mini"


def test_model_config_legacy_arc_diagram_alias(tmp_path, monkeypatch):
    clear_model_config_cache()
    cfg_path = tmp_path / "models.yaml"
    cfg_path.write_text(
        "MODEL_PROVIDER: ollama\nollama:\n  arc_diagram_model: llama3.2-vision\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ISOVANE_MODELS_CONFIG", str(cfg_path))
    monkeypatch.delenv("ISOVANE_OLLAMA_ARC_IMAGE_EXTRACT", raising=False)
    monkeypatch.delenv("ISOVANE_OLLAMA_ARC_DIAGRAM_MODEL", raising=False)
    clear_model_config_cache()
    cfg = load_model_config()
    assert cfg["ollama"]["arc_image_extract"] == "llama3.2-vision"


def test_vision_extract_ollama_mocked(monkeypatch):
    clear_model_config_cache()

    def fake_post(url, payload, *, headers, timeout):
        assert "/api/chat" in url
        assert payload["model"] == "llama3.2-vision"
        assert payload["messages"][0]["images"]
        return {
            "message": {
                "content": (
                    "DIAGRAM:\nChat UI --> Agent API\nAgent API --> OpenAI\n"
                    "NODES:\n- Chat UI\n- Agent API\n- OpenAI\n"
                    "TRUST / NOTES:\n- no HITL\n- customer PII\n"
                )
            }
        }

    monkeypatch.setattr("isovane_serve.vision_diagram._post_json", fake_post)
    monkeypatch.setattr("isovane_serve.vision_diagram.active_provider", lambda: "ollama")
    monkeypatch.setattr(
        "isovane_serve.vision_diagram.arc_image_extract_model", lambda: "llama3.2-vision"
    )
    out = extract_diagram_text_from_image(b"fakepng", "arch.png")
    assert out["provider"] == "ollama"
    assert "OpenAI" in out["text"]
    assert out["model"] == "llama3.2-vision"


def test_analyze_upload_uses_vision_text(monkeypatch):
    def fake_extract(data, filename):
        return {
            "text": (
                "Chat UI --> Orchestrator agent\n"
                "Orchestrator agent --> MCP filesystem\n"
                "Orchestrator agent --> shell tool\n"
                "permissions: *\n"
                "no HITL approval\n"
            ),
            "provider": "ollama",
            "model": "llama3.2-vision",
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
        "workflow-agentic.png",
        format_hint="image",
        mode="workflow",
    )
    assert result["inventory"]["vision"]["status"] == "ok"
    assert result["inventory"]["risk"]["status"] == "rules_fallback"
    titles = [f.title for f in result["findings"]]
    assert any("HITL" in t or "MCP" in t or "Wildcard" in t or "Shell" in t for t in titles)


def test_analyze_upload_falls_back_when_vision_fails(monkeypatch):
    def boom(data, filename):
        raise RuntimeError("ollama not running")

    import isovane_serve.vision_diagram as vd
    import isovane_serve.risk_diagram as rd

    monkeypatch.setattr(vd, "extract_diagram_text_from_image", boom)
    monkeypatch.setattr(
        rd,
        "analyze_risks_with_llm",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("force rules")),
    )
    result = analyze_upload_bytes(
        "ws",
        b"\x89PNG\r\n\x1a\n" + b"0" * 32,
        "privacy-multi-cloud.png",
        format_hint="image",
        mode="privacy",
    )
    assert result["inventory"]["vision"]["status"] == "fallback"
    assert result["findings"]  # filename seed still produces something
    edges = (result["inventory"].get("board") or {}).get("edges") or result["inventory"].get("edges")
    assert edges, "fallback board must include joining arrows"
    labels = [n.get("label") for n in result["inventory"].get("nodes") or []]
    assert not any(lbl and "terminated" in str(lbl).lower() for lbl in labels)


def test_fixture_png_seed_has_arrows_when_vision_down(monkeypatch):
    def boom(data, filename):
        raise RuntimeError("llama-server process has terminated: unknown model architecture: mllama")

    import isovane_serve.vision_diagram as vd
    import isovane_serve.risk_diagram as rd

    monkeypatch.setattr(vd, "extract_diagram_text_from_image", boom)
    monkeypatch.setattr(
        rd,
        "analyze_risks_with_llm",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("force rules")),
    )
    from pathlib import Path

    png = Path(
        r"D:\projects\ai-projects\isovane\fixtures\architecture\01-privacy-multi-cloud-egress.png"
    ).read_bytes()
    result = analyze_upload_bytes(
        "ws",
        png,
        "01-privacy-multi-cloud-egress.png",
        format_hint="image",
        mode="privacy",
    )
    inv = result["inventory"]
    board = inv.get("board") or {}
    nodes = board.get("nodes") or inv.get("nodes") or []
    edges = board.get("edges") or inv.get("edges") or []
    labels = {str(n.get("label")) for n in nodes}
    assert len(edges) >= 5
    assert "Chat UI" in labels
    assert "Agent API" in labels
    assert any("OpenAI" in lbl for lbl in labels)
    assert not any("mllama" in lbl.lower() or lbl.lower() == "error" for lbl in labels)


def test_llm_risk_analyze_preferred(monkeypatch):
    from isovane_serve.diagram import analyze_diagram
    from isovane_serve.models import Finding, FindingEvidence, SuggestedFix
    import isovane_serve.risk_diagram as rd

    fake = Finding(
        workspace_id="ws",
        source="analyze",
        severity="high",
        title="LLM found missing HITL",
        summary="Agent path has no approval.",
        category="architecture",
        evidence=FindingEvidence(tool="architecture-llm"),
        suggested_fix=SuggestedFix(kind="architecture", summary="Add HITL", checklist=[]),
    )

    monkeypatch.setattr(
        rd,
        "analyze_risks_with_llm",
        lambda *a, **k: {"findings": [fake], "provider": "ollama", "model": "llama3.1:8b"},
    )
    result = analyze_diagram(
        "ws",
        description="Chat UI --> Agent --> shell tool\npermissions: *\nno HITL",
        format_hint="mermaid",
        mode="workflow",
        filename="wf.mmd",
    )
    assert result["inventory"]["risk"]["status"] == "llm"
    assert result["findings"][0].title == "LLM found missing HITL"
