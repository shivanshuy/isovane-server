"""Known finding titles must keep matching business/technical gravity copy."""

from isovane_serve.insights import insight_for


def test_hitl_title_not_stolen_by_token_in_snippet():
    insight = insight_for(
        title="Tools mentioned without HITL",
        issue_text="Agent wiring without confirm.",
        tool="promptlint",
        snippet='return any(token in lowered for token in ("news", "headline"))\n@tool("duckduckgo_search")\n',
    )
    assert "credential" not in insight.summary.lower()
    assert "hitl" in insight.summary.lower() or "confirm" in insight.summary.lower()
    assert insight.exploit
    assert insight.incident_story or insight.real_world
    assert insight.technical_details or insight.incident_technical


def test_system_prompt_title_not_stolen_by_pii_in_message():
    insight = insight_for(
        title="System prompt built in Python",
        issue_text="SystemMessage constructed — review for jailbreak, PII, and HITL bounds.",
        tool="semgrep",
        snippet='SystemMessage(content=f"{base_system}")\n',
    )
    assert "appears in source or prompts" not in insight.summary.lower()
    assert "system" in insight.summary.lower()
    assert insight.exploit


def test_web_search_title_not_wildcard_story():
    insight = insight_for(
        title="Web search tool attached to agent",
        issue_text="Web search tool wiring detected.",
        tool="semgrep",
        snippet='permissions: "*"\nget_web_search_tools()\n',
    )
    assert "wildcard" not in insight.summary.lower()
    assert "tool" in insight.summary.lower() or "hitl" in insight.summary.lower()


def test_missing_pii_bounds_is_policy_gap_not_detection():
    insight = insight_for(
        title="Missing PII / disclosure bounds",
        issue_text="System/prompt text lacks PII handling.",
        tool="semgrep",
        snippet='SYSTEM = """You are helpful."""\n',
    )
    assert "does not mean pii was found" in insight.summary.lower() or "lacks explicit pii" in insight.summary.lower()
