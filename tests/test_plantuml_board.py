from isovane_serve.arch_workflow import classify_nodes
from isovane_serve.diagram import _extract_nodes, normalize_diagram_text
from isovane_serve.diagram_graph import graph_from_text

PRIVACY_DEMO = """@startuml
cloud "Org VPC" {
  database "Customer PII DB"
  rectangle "Agent API"
}
cloud "OpenAI (US)" as OpenAI
cloud "Anthropic (US)" as Anthropic
cloud "LangSmith traces" as Logs
"Customer PII DB" --> "Agent API"
"Agent API" --> OpenAI : prompts + docs
"Agent API" --> Anthropic : fallback model
"Agent API" --> Logs : full prompt spans
@enduml"""


def test_privacy_demo_plantuml_builds_full_board():
    norm = normalize_diagram_text(PRIVACY_DEMO, format_hint="plantuml")
    assert "Customer PII DB --> Agent API" in norm
    assert "Agent API --> OpenAI (US)" in norm
    assert "Agent API --> Anthropic (US)" in norm
    assert "Agent API --> LangSmith traces" in norm

    typed = classify_nodes(norm, _extract_nodes(norm))
    built = graph_from_text(norm, typed)
    labels = {n["label"] for n in built["nodes"]}
    assert "Customer PII DB" in labels
    assert "Agent API" in labels
    assert "OpenAI (US)" in labels
    assert "Anthropic (US)" in labels
    assert "LangSmith traces" in labels
    assert len(built["edges"]) >= 4
    # No truncated / hyphen-split junk from "-->"
    assert "A" not in labels
    assert not any(label.endswith(" -") for label in labels)


def test_workflow_demo_mermaid_board():
    from isovane_serve.diagram import normalize_diagram_text
    from isovane_serve.diagram_graph import graph_from_text
    from isovane_serve.arch_workflow import classify_nodes
    from isovane_serve.diagram import _extract_nodes

    demo = """flowchart LR
  UI[Chat UI] --> Orch[Orchestrator agent]
  Orch --> Research[Research agent]
  Orch --> Writer[Writer agent]
  Research --> MCP[MCP filesystem + browser]
  Writer --> Tools[email + shell tools]
  Research -.->|a2a handoff| Writer"""
    # Mermaid passes through normalize when format is mermaid
    norm = normalize_diagram_text(demo, format_hint="mermaid")
    built = graph_from_text(norm, classify_nodes(norm, _extract_nodes(norm)))
    assert len(built["nodes"]) >= 4
    assert len(built["edges"]) >= 3
