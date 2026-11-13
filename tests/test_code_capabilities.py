from isovane_serve.code_capabilities import probe_python_source
from isovane_serve.promptlint import lint_text
from isovane_serve.scan import _filter_promptlint_by_structure
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix


def test_probe_detects_tools_not_briefing():
    briefing = '''
INGEST_SYSTEM = """Write a concise briefing with bullet points."""
'''
    caps = probe_python_source(briefing)
    assert caps.has_tool_agency is False
    assert caps.has_retriever is False

    agency = '''
from langgraph.prebuilt import create_react_agent
agent = create_react_agent(model, tools=[send_email, pay_refund])
'''
    caps2 = probe_python_source(agency)
    assert caps2.has_tool_agency is True


def test_probe_detects_retriever():
    src = '''
retriever = db.as_retriever()
docs = retriever.similarity_search(query)
'''
    caps = probe_python_source(src)
    assert caps.has_retriever is True


def test_filter_drops_ungated_python_hitl():
    hitl = Finding(
        workspace_id="ws",
        source="analyze",
        severity="high",
        title="Tools mentioned without HITL",
        summary="noise",
        category="agency",
        evidence=FindingEvidence(
            path="ingest.py",
            tool="promptlint",
            snippet="Write a concise briefing with bullet points",
        ),
        suggested_fix=SuggestedFix(kind="prompt", summary="x"),
    )
    keep = Finding(
        workspace_id="ws",
        source="analyze",
        severity="high",
        title="Other",
        summary="ok",
        category="static",
        evidence=FindingEvidence(path="ingest.py", tool="bandit"),
        suggested_fix=SuggestedFix(kind="code", summary="x"),
    )
    out = _filter_promptlint_by_structure([hitl, keep], caps_by_path={})
    assert keep in out
    assert hitl not in out
