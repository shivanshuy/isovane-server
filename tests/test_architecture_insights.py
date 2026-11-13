"""Architecture findings should carry real case files + title-matched remediations."""

from isovane_serve.arch_workflow import analyze_workflow
from isovane_serve.insights import insight_for
from isovane_serve.incidents_catalog import incidents_for_architecture
from isovane_serve.remediations import hydrate_finding, load_remediations, resolve_remediation


def test_architecture_incidents_not_empty():
    cases = incidents_for_architecture("architecture workflow hitl agency tool")
    assert len(cases) >= 2
    assert any("Replit" in c["headline"] or "agent" in c["headline"].lower() for c in cases)
    # Never classic open-bind for architecture
    assert not any("MongoDB" in c["headline"] for c in cases)


def test_architecture_hitl_insight_has_exploit_and_cases():
    insight = insight_for(
        title="UI → agent → tools without HITL gate",
        issue_text="Missing approval on consequential path",
        tool="architecture-workflow",
    )
    fields = insight.as_finding_fields(["LLM06", "ASI09"])
    assert fields["exploit"]
    assert "HITL" in fields["exploit"] or "tool" in fields["exploit"].lower()
    assert len(fields["incidents"] or []) >= 2
    assert fields["incident_headline"]
    assert fields["solutions"]


def test_architecture_privacy_insight_uses_pii_cases():
    insight = insight_for(
        title="Privacy architecture needs cloud labels",
        issue_text="Could not map org → LLM cloud hops",
        tool="architecture-privacy",
    )
    fields = insight.as_finding_fields(["ASI10"])
    assert fields["incidents"]
    blob = " ".join(c["headline"] for c in fields["incidents"]).lower()
    assert "samsung" in blob or "chatgpt" in blob or "openai" in blob or "garante" in blob


def test_architecture_hitl_remediation_recipe():
    load_remediations.cache_clear()
    recipe = resolve_remediation(
        title="UI → agent → tools without HITL gate",
        owasp=["LLM06"],
        category="architecture",
    )
    assert recipe and recipe["id"] == "arch-hitl-gate"
    assert recipe["kind"] == "architecture"
    assert "HITL" in (recipe.get("diff") or "")


def test_architecture_catalog_covers_known_titles():
    """Every stable architecture title should hit an arch-* recipe, not code/default."""
    load_remediations.cache_clear()
    titles = [
        "UI → agent → tools without HITL gate",
        "Agent-to-agent edge without auth / identity",
        "MCP servers on the agent path — verify allow-list",
        "MCP edge lacks auth / trust boundary marker",
        "Wildcard / unrestricted tools on agent",
        "Shell / code-execution tool in workflow graph",
        "Missing trust-boundary label on UI ingress",
        "Multi-agent swarm without supervisor HITL",
        "Workflow graph needs agent / MCP / UI labels",
        "Privacy architecture needs cloud labels",
        "Organizational data egress to LLM vendor clouds",
        "Multi-cloud LLM fan-out increases privacy surface",
        "Customer/PII path to cloud LLM without redact/DLP",
        "No zero-data-retention / no-training marker on LLM edge",
        "Observability sink may duplicate prompt data outside org",
        "SaaS data store → LLM cloud crosses two processors",
        "Self-hosted model path reduces egress — verify isolation",
        "Untrusted mail path to agent tools",
        "Agent memory / long-term context without validation",
        "Missing external policy / intent gate before tools",
        "Multi-agent path without circuit breaker / rate limits",
        "Agent tools without per-agent identity / scoped credentials",
    ]
    for title in titles:
        recipe = resolve_remediation(title=title, category="architecture")
        assert recipe is not None, title
        assert str(recipe.get("id", "")).startswith("arch-"), (title, recipe.get("id"))
        assert recipe.get("kind") == "architecture", title
        insight = insight_for(title=title, issue_text=title, tool="architecture-workflow")
        fields = insight.as_finding_fields()
        assert fields.get("exploit"), title
        assert fields.get("incidents"), title


def test_analyze_workflow_finding_hydrates_like_code():
    load_remediations.cache_clear()
    findings, _inv = analyze_workflow(
        "ws",
        "User interface chat → agent planner → MCP tools and shell and refund email",
        filename="board.md",
    )
    hitl = [f for f in findings if "without HITL" in f.title or "HITL gate" in f.title]
    assert hitl, [f.title for f in findings]
    f = hitl[0]
    assert f.exploit
    assert f.incidents
    rich = hydrate_finding(f)
    assert rich.solutions
    assert rich.suggested_fix and rich.suggested_fix.diff
    assert "shell=False" not in " ".join(rich.solutions)
    sol = " ".join(rich.solutions).lower()
    assert "hitl" in sol or "approval" in sol
