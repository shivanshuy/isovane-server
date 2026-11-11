from isovane_serve.diagram import analyze_diagram
from isovane_serve.hunt import run_hunt
from isovane_serve.promptlint import lint_text
from isovane_serve.scan import analyze_workspace


def test_prompt_lint_flags_missing_pii():
    findings = lint_text("ws", "You are a helpful assistant that can send email.")
    titles = [f.title for f in findings]
    assert any("PII" in t for t in titles)


def test_diagram_demo_script_findings():
    text = "public chat --> LLM --> Gmail --> customer DB openai"
    result = analyze_diagram("checkout-agent", description=text, filename="arch.png", mode="both")
    findings = result["findings"]
    assert len(findings) >= 2
    assert all(f.owasp for f in findings)


def test_analyze_inline_secret():
    findings = analyze_workspace(
        "checkout-agent",
        text_blobs=[
            {
                "path": "agent.py",
                "text": 'subprocess.run(cmd, shell=True)\napi_key = "sk-abcdefghijklmnopqrstuvwxyz012345"',
            }
        ],
    )
    assert any(f.category == "static" for f in findings)


def test_hunt_pack_ok():
    result = run_hunt("checkout-agent")
    assert result["ok"] is True
    assert len(result["results"]) >= 3
