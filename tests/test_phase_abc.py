"""Phase A–C smoke: privacy posture, suppressions, hunt pack size, plantuml board."""

from pathlib import Path

from isovane_serve.architecture_graph import board_nodes, graph_from_parts
from isovane_serve.diagram import analyze_diagram, normalize_diagram_text
from isovane_serve.diagram_graph import graph_from_text
from isovane_serve.arch_workflow import classify_nodes
from isovane_serve.diagram import _extract_nodes
from isovane_serve.hunt import SCENARIOS, run_hunt
from isovane_serve.privacy_posture import privacy_posture_from_graph
from isovane_serve.suppressions import apply_suppressions, finding_suppression_key
from isovane_serve.models import Finding, FindingEvidence
from isovane_serve.workflow_inventory import inventory_from_tree


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


def test_privacy_demo_full_board_golden():
    norm = normalize_diagram_text(PRIVACY_DEMO, format_hint="plantuml")
    built = graph_from_text(norm, classify_nodes(norm, _extract_nodes(norm)))
    labels = {n["label"] for n in built["nodes"]}
    assert {"Customer PII DB", "Agent API", "OpenAI (US)", "Anthropic (US)", "LangSmith traces"} <= labels
    assert len(built["edges"]) >= 4


def test_privacy_posture_from_structurizr():
    graph = graph_from_parts(
        [
            {"id": "db", "label": "Customer PII DB", "kind": "data"},
            {"id": "agent", "label": "Agent API", "kind": "agent"},
            {"id": "oai", "label": "OpenAI (US)", "kind": "llm"},
            {"id": "logs", "label": "LangSmith traces", "kind": "data"},
        ],
        [
            {"from": "db", "to": "agent"},
            {"from": "agent", "to": "oai"},
            {"from": "agent", "to": "logs"},
        ],
        source="test",
    )
    posture = privacy_posture_from_graph(graph)
    assert posture["schema"] == "isovane.privacy_posture.v1"
    assert any("OpenAI" in v for v in posture["llm_vendors"])
    assert "multi_vendor_llm_fanout" not in posture["gaps"] or len(posture["llm_vendors"]) >= 1
    assert "cross_border_llm_without_dlp_zdr_label" in posture["gaps"]
    assert "no_hitl_node" in posture["gaps"]


def test_analyze_emits_privacy_posture(monkeypatch):
    import isovane_serve.risk_diagram as rd

    monkeypatch.setattr(
        rd,
        "analyze_risks_with_llm",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("skip llm")),
    )
    result = analyze_diagram(
        "ws",
        description=PRIVACY_DEMO,
        format_hint="plantuml",
        mode="privacy",
    )
    assert "privacy_posture" in result["inventory"]
    assert result["inventory"]["privacy_posture"]["edge_count"] >= 1
    assert "remediation_hints" in result["inventory"]
    assert len(board_nodes(result["graph"])) >= 4


def test_suppressions_ignore_and_baseline(tmp_path: Path):
    (tmp_path / ".isovaneignore").write_text("vendor/**\n*.generated.py\n", encoding="utf-8")
    (tmp_path / ".isovane-baseline.json").write_text(
        '[{"title": "Known noise", "path": "a.py", "rule_id": "x"}]',
        encoding="utf-8",
    )
    kept = Finding(
        workspace_id="ws",
        source="analyze",
        severity="medium",
        title="Real issue",
        summary="x",
        category="agency",
        evidence=FindingEvidence(path="src/agent.py", args={"check_id": "r1"}),
    )
    ignored = Finding(
        workspace_id="ws",
        source="analyze",
        severity="low",
        title="Noise",
        summary="x",
        category="agency",
        evidence=FindingEvidence(path="vendor/lib.py"),
    )
    baselined = Finding(
        workspace_id="ws",
        source="analyze",
        severity="low",
        title="Known noise",
        summary="x",
        category="agency",
        evidence=FindingEvidence(path="a.py", args={"check_id": "x"}),
    )
    out = apply_suppressions([kept, ignored, baselined], root=tmp_path)
    assert [f.title for f in out] == ["Real issue"]
    assert "known noise" in finding_suppression_key(baselined)


def test_hunt_pack_at_least_20():
    assert len(SCENARIOS) >= 20
    result = run_hunt("ws-hunt")
    assert result["ok"] is True, result.get("regressions")
    assert len(result["results"]) >= 20
    for row in result["results"]:
        if row.get("expect_rule"):
            assert row["policy_rule_id"] == row["expect_rule"], row


def test_code_inventory_emits_structurizr(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "from langgraph.prebuilt import create_react_agent\n"
        "from langchain_openai import ChatOpenAI\n"
        "create_react_agent(ChatOpenAI(), tools=[])\n",
        encoding="utf-8",
    )
    inv = inventory_from_tree(tmp_path)
    assert inv.get("graph", {}).get("model", {}).get("softwareSystems")
    assert inv.get("board", {}).get("nodes")


def test_semgrep_rule_files_count():
    root = Path(__file__).resolve().parents[1] / "rules" / "agent"
    ids = []
    for path in root.glob("*.yml"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("- id: isovane."):
                ids.append(line.split(":", 1)[1].strip())
    # Precision over vanity count — noisy INFO rules were removed in Phase E6.
    assert len(ids) >= 30, f"expected ≥30 high-signal rules, got {len(ids)}: {ids}"
