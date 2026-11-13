"""Verify FP suppression without sacrificing recall on real agency/RAG issues.

Policy: when unsure, prefer a finding (FP OK) over missing a real issue (FN never OK).
"""

from __future__ import annotations

from isovane_serve.promptlint import lint_text
from isovane_serve.scan import analyze_workspace, _filter_promptlint_by_structure
from isovane_serve.code_capabilities import probe_python_source
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix


def _titles(text: str, path: str) -> list[str]:
    return [f.title for f in lint_text("ws", text, path=path)]


# --- Must NOT fire (clear false positives) ---


def test_fp_briefing_write_not_hitl():
    text = '''
from neurosentia_serve.utils.llm import get_chat_model

INGEST_SYSTEM = """You summarize ingested content for Neurosentia operators.
Write a concise briefing:
- Title line
- 4–8 bullet points of key facts, claims, and structure
- End with "Open questions:" if anything is unclear.
"""
'''
    titles = _titles(text, "ingest.py")
    assert not any("HITL" in t for t in titles)
    assert not any("RAG concat" in t for t in titles)


def test_fp_context_placeholder_is_not_rag():
    text = '''
SYSTEM = "Answer using the data below."
def node(state):
    context = state.get("context")
    return f"Context:\\n{context}"
'''
    titles = _titles(text, "graph.py")
    assert "RAG concat without trust boundary" not in titles
    assert any("App/state data in prompt" in t for t in titles)


def test_fp_retrieval_model_finetune_prose_is_not_rag():
    """'embedding / retrieval model' dataset prompts are not RAG concat."""
    text = '''
system = (
    "You create fine-tuning dataset rows for an embedding / retrieval model. "
    "Return ONLY a valid JSON array, no markdown."
)
'''
    titles = _titles(text, "dataset_builder.py")
    assert "RAG concat without trust boundary" not in titles


# --- Must fire (real issues — recall) ---


def test_tp_bind_tools_without_hitl():
    text = '''
SYSTEM = "You are an agent."
agent = create_react_agent(model, tools=[send_email, pay_refund])
'''
    assert any("HITL" in t for t in _titles(text, "agent.py"))


def test_tp_shell_true_without_hitl():
    text = '''
import subprocess
SYSTEM = "You run commands for the user."
subprocess.run(cmd, shell=True)
'''
    assert any("HITL" in t for t in _titles(text, "runner.py"))


def test_tp_capability_phrase_without_ast_tools_list():
    """Prompt admits side-effect tools even if wiring is imported elsewhere — still flag."""
    text = '''
SYSTEM = """You are a support agent.
You can send email and call the refund tool when the user asks.
"""
'''
    assert any("HITL" in t for t in _titles(text, "prompt_only.py"))


def test_tp_send_emails_prose_without_hitl():
    text = 'SYSTEM = """Send emails to customers when they ask for updates."""\n'
    assert any("HITL" in t for t in _titles(text, "mailer.py"))


def test_tp_issue_refund_prose_without_hitl():
    text = 'SYSTEM = """Issue a refund when the customer requests it."""\n'
    assert any("HITL" in t for t in _titles(text, "refunds.py"))


def test_tp_run_shell_prose_without_hitl():
    text = 'SYSTEM = """Run shell commands the user requests."""\n'
    assert any("HITL" in t for t in _titles(text, "shell_agent.py"))


def test_tp_write_email_prose_without_hitl():
    """'Write an email' is consequential; 'Write a briefing' is not."""
    text = 'SYSTEM = """Write an email to the customer with the refund status."""\n'
    assert any("HITL" in t for t in _titles(text, "writer.py"))


def test_tp_transfer_money_prose_without_hitl():
    text = 'SYSTEM = """You may transfer money between accounts."""\n'
    assert any("HITL" in t for t in _titles(text, "payments.py"))


def test_tp_retriever_without_trust_marker():
    text = '''
SYSTEM = "Answer from docs."
docs = retriever.similarity_search(query)
prompt = f"Use these retrieved documents:\\n{docs}"
'''
    assert any("RAG concat" in t for t in _titles(text, "rag.py"))


def test_tp_rag_keyword_in_prompt_string():
    text = '''
SYSTEM = "Merge {rag_docs} into the answer. These are retrieved document excerpts."
'''
    assert any("RAG concat" in t for t in _titles(text, "rag_prompt.py"))


def test_tp_decorator_tool_without_hitl():
    text = '''
from langchain_core.tools import tool

@tool
def send_email(to: str, body: str) -> str:
    return "sent"

SYSTEM = "Use tools when needed."
'''
    assert any("HITL" in t for t in _titles(text, "tools_agent.py"))


def test_workspace_analyze_briefing_no_hitl(tmp_path):
    (tmp_path / "ingest.py").write_text(
        '''
INGEST_SYSTEM = """Write a concise briefing with bullet points of key facts."""
''',
        encoding="utf-8",
    )
    findings = analyze_workspace("ws", folder=str(tmp_path))
    assert not any(
        f.evidence and f.evidence.tool == "promptlint" and "HITL" in f.title for f in findings
    )


def test_workspace_analyze_react_agent_keeps_hitl(tmp_path):
    (tmp_path / "agent.py").write_text(
        '''
SYSTEM = "You are helpful."
agent = create_react_agent(model, tools=[send_email])
''',
        encoding="utf-8",
    )
    findings = analyze_workspace("ws", folder=str(tmp_path))
    assert any("HITL" in f.title for f in findings)


def test_filter_keeps_strong_hitl_even_without_caps():
    hitl = Finding(
        workspace_id="ws",
        source="analyze",
        severity="high",
        title="Tools mentioned without HITL",
        summary="agency",
        category="agency",
        evidence=FindingEvidence(
            path="agent.py",
            tool="promptlint",
            snippet="agent = create_react_agent(model, tools=[send_email])",
        ),
        suggested_fix=SuggestedFix(kind="prompt", summary="x"),
    )
    out = _filter_promptlint_by_structure([hitl], caps_by_path={})
    assert hitl in out


def test_filter_drops_briefing_fp():
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
            snippet='INGEST_SYSTEM = """Write a concise briefing"""',
        ),
        suggested_fix=SuggestedFix(kind="prompt", summary="x"),
    )
    out = _filter_promptlint_by_structure([hitl], caps_by_path={})
    assert hitl not in out


def test_probe_doubt_prefers_detecting_tools_list():
    caps = probe_python_source("graph = create_react_agent(llm, tools=[a, b])\n")
    assert caps.has_tool_agency is True
