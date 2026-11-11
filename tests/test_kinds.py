"""kinds.yaml drives shared node classification."""

from __future__ import annotations

from isovane_serve.kinds import kind_for_label


def test_kind_for_label_common_tokens():
    assert kind_for_label("Chat UI") == "ui"
    assert kind_for_label("MCP filesystem") == "mcp"
    assert kind_for_label("HITL approval") == "hitl"
    assert kind_for_label("OpenAI GPT-4o") == "llm"
    assert kind_for_label("Postgres store") == "data"
    assert kind_for_label("refund tool") == "tool"
    assert kind_for_label("orchestrator agent") == "agent"


def test_kind_for_label_default():
    assert kind_for_label("xyzzy") == "unknown"
    assert kind_for_label("planner", default="agent") == "agent"
