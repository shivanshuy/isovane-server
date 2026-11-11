from isovane_serve.issue_type import classify_issue_type
from isovane_serve.models import Finding, FindingEvidence


def test_bandit_static_is_general():
    assert (
        classify_issue_type(
            category="static",
            tags=["General security", "LLM-amplified"],
            owasp=["ASI05"],
            tool="bandit",
            title="shell=True in subprocess",
        )
        == "GENERAL"
    )


def test_bandit_urlopen_ssrf_is_general_despite_llm06():
    """SSRF urlopen is classic AppSec — LLM06 on the insight must not flip the group."""
    assert (
        classify_issue_type(
            category="static",
            tags=["General security", "LLM-amplified"],
            owasp=["ASI05", "LLM06"],
            tool="bandit",
            title="Unvalidated URL fetch (urllib)",
        )
        == "GENERAL"
    )
    finding = Finding(
        workspace_id="ws",
        source="analyze",
        severity="medium",
        title="Unvalidated URL fetch (urllib)",
        summary="SSRF via urlopen.",
        category="static",
        owasp=["ASI05", "LLM06"],
        tags=["General security", "LLM-amplified"],
        evidence=FindingEvidence(tool="bandit"),
    )
    assert finding.issue_type == "GENERAL"


def test_prompt_is_ai_llm():
    assert (
        classify_issue_type(
            category="prompt",
            tags=["LLM / agent"],
            owasp=["LLM01"],
            tool="promptlint",
            title="RAG concat without trust boundary",
        )
        == "AI_LLM"
    )


def test_finding_serializes_type_description_severity_label():
    finding = Finding(
        workspace_id="ws",
        source="analyze",
        severity="high",
        title="Secret: API Key",
        summary="Hardcoded key in source.",
        category="pii",
        evidence=FindingEvidence(tool="detect-secrets"),
        tags=["General security"],
    )
    data = finding.model_dump()
    assert data["issue_type"] == "GENERAL"
    assert data["description"] == "Hardcoded key in source."
    assert data["severity_label"] == "HIGH"

    agent = Finding(
        workspace_id="ws",
        source="analyze",
        severity="medium",
        title="Tools mentioned without HITL",
        summary="Agent can call tools without confirm.",
        category="agency",
        evidence=FindingEvidence(tool="promptlint"),
    )
    assert agent.issue_type == "AI_LLM"
    assert agent.severity_label == "MEDIUM"
