from isovane_serve.diagram import analyze_diagram, normalize_diagram_text
from isovane_serve.repo import looks_like_git_url


def test_plantuml_normalizes_edges():
    text = """
    @startuml
    Public --> LLM
    LLM --> Gmail
    @enduml
    """
    out = normalize_diagram_text(text, format_hint="plantuml")
    assert "Public --> LLM" in out
    assert "LLM --> Gmail" in out


def test_plantuml_analyze_finds_risks():
    result = analyze_diagram(
        "checkout-agent",
        description="""
        @startuml
        actor Public
        rectangle LLM
        rectangle Gmail
        database CustomerDB
        Public --> LLM
        LLM --> Gmail
        LLM --> CustomerDB
        @enduml
        """,
        format_hint="plantuml",
        filename="arch.puml",
        mode="both",
    )
    findings = result["findings"]
    assert len(findings) >= 2
    assert "inventory" in result


def test_privacy_mode_flags_openai_anthropic_egress():
    result = analyze_diagram(
        "ws",
        description="""
        organization VPC customer PII DB
        --> API gateway --> OpenAI
        --> Anthropic Claude
        LangSmith logging
        """,
        mode="privacy",
        filename="privacy.mmd",
    )
    titles = [f.title for f in result["findings"]]
    assert any("egress" in t.lower() or "multi-cloud" in t.lower() for t in titles)
    assert any("Privacy & cloud" in (f.tags or []) for f in result["findings"])


def test_workflow_mode_flags_mcp_and_hitl():
    result = analyze_diagram(
        "ws",
        description="""
        flowchart LR
          UI[Chat UI] --> Orchestrator[Orchestrator agent]
          Orchestrator --> Worker[Worker agent]
          Worker --> MCP[MCP filesystem]
          Worker --> Shell[shell tool]
        """,
        mode="workflow",
        format_hint="mermaid",
        filename="wf.mmd",
    )
    titles = [f.title for f in result["findings"]]
    assert any("MCP" in t for t in titles)
    assert result["inventory"]["counts"]


def test_git_url_detection():
    assert looks_like_git_url("https://github.com/org/agent.git")
    assert looks_like_git_url("https://github.com/org/agent")
    assert not looks_like_git_url(r"D:\projects\agent")
