from isovane_serve.diagram import analyze_diagram
from isovane_serve.hunt import run_hunt
from isovane_serve.insights import insight_for
from isovane_serve.promptlint import lint_text
from isovane_serve.scan import analyze_workspace


def test_prompt_lint_flags_missing_pii():
    findings = lint_text("ws", "You are a helpful assistant that can send email.")
    titles = [f.title for f in findings]
    assert any("PII" in t for t in titles)


def test_prompt_lint_context_is_not_rag():
    """LangGraph-style {context} / state context is prompt-context, not RAG."""
    langgraphish = '''
You are a support agent.
def build_prompt(state):
    context = state.get("context")
    return ChatPromptTemplate.from_messages([
        ("system", "Answer using: {context}"),
        ("human", "{question}"),
    ]).format(context=context, question=state["question"])
'''
    findings = lint_text("ws", langgraphish, path="graph.py")
    titles = [f.title for f in findings]
    assert "RAG concat without trust boundary" not in titles
    assert any("App/state data in prompt" in t for t in titles)
    insight = insight_for(
        title="App/state data in prompt without trust labels",
        issue_text="prompt-context injection, not RAG",
        tool="promptlint",
    )
    assert "RAG" not in insight.tags
    assert "Prompt context" in insight.tags


def test_prompt_lint_retriever_is_rag():
    text = '''
SYSTEM = "You are a helpful assistant."
docs = retriever.similarity_search(query)
prompt = f"Use these retrieved documents:\\n{docs}\\nQuestion: {q}"
'''
    findings = lint_text("ws", text, path="rag_chain.py")
    titles = [f.title for f in findings]
    assert any("RAG concat without trust boundary" in t for t in titles)


def test_rag_finding_shows_multi_line_code_window():
    """Technical details must show surrounding code — not a single orphan line."""
    text = '''
# helper notes
# requires login to the vector store admin console
def answer(query: str, q: str) -> str:
    docs = retriever.similarity_search(query)
    prompt = f"Use these retrieved documents:\\n{docs}\\nQuestion: {q}"
    return prompt
'''
    findings = lint_text("ws", text, path="rag_chain.py")
    hit = next(f for f in findings if "RAG concat" in f.title)
    snip = hit.evidence.snippet or ""
    assert "\n" in snip, snip
    assert "similarity_search" in snip
    assert "retrieved documents" in snip or "docs" in snip
    # Must not be ONLY the comment/login line
    assert snip.strip() != "# requires login to the vector store admin console"


def test_prompt_lint_python_needs_ast_for_hitl():
    """Prose 'tool' / 'write' in a .py string must not imply agency without AST sinks."""
    text = '''
SYSTEM = """You are helpful. Write a summary. You may search your memory for facts."""
'''
    findings = lint_text("ws", text, path="summarizer.py")
    assert not any("HITL" in f.title for f in findings)


def test_prompt_lint_includes_code_snippet():
    text = '''
def node(state):
    context = state.get("context")
    return ChatPromptTemplate.from_template("Use: {context}").format(context=context)
'''
    findings = lint_text("ws", text, path="graphs/agent.py")
    hit = next(f for f in findings if "App/state data in prompt" in f.title)
    assert hit.evidence.path == "graphs/agent.py"
    assert hit.evidence.line is not None
    assert hit.evidence.snippet
    assert "ChatPromptTemplate" in hit.evidence.snippet or "{context}" in hit.evidence.snippet
    assert "Retrieved context is concatenated" not in (hit.evidence.snippet or "")


def test_prompt_lint_briefing_prompt_not_hitl():
    """'Write a briefing' is prose, not a side-effect tool."""
    text = '''
from neurosentia_serve.utils.llm import get_chat_model

INGEST_SYSTEM = """You summarize ingested content for Neurosentia operators.
Write a concise briefing:
- Title line
- 4–8 bullet points of key facts, claims, and structure
- End with "Open questions:" if anything is unclear.
"""
'''
    findings = lint_text("ws", text, path="ingest.py")
    assert not any("HITL" in f.title for f in findings)


def test_prompt_lint_bind_tools_without_hitl():
    text = '''
SYSTEM = "You are an agent that can send email."
agent = create_react_agent(model, tools=[send_email, pay_refund])
'''
    findings = lint_text("ws", text, path="agent.py")
    assert any("HITL" in f.title for f in findings)


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
