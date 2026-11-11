"""Classify findings as AI_LLM vs GENERAL for UI grouping."""

from __future__ import annotations

from typing import Literal

IssueType = Literal["AI_LLM", "GENERAL"]

_AI_CATEGORIES = frozenset({"prompt", "agency", "injection", "architecture", "runtime"})
_AI_TOOLS = frozenset(
    {
        "promptlint",
        "architecture-privacy",
        "architecture-workflow",
    }
)


def classify_issue_type(
    *,
    category: str,
    tags: list[str] | None = None,
    owasp: list[str] | None = None,
    tool: str | None = None,
    title: str = "",
) -> IssueType:
    """AI_LLM = agent/prompt/LLM-cloud risks. GENERAL = classic AppSec/secrets/host.

    Classic scanners (Bandit SSRF/urlopen, secrets, static sinks) stay GENERAL even when
    insights also attach LLM06 / LLM-amplified tags.
    """
    cat = (category or "").lower()
    tool_l = (tool or "").lower()
    tags_l = [t.lower() for t in (tags or [])]
    title_l = (title or "").lower()

    # GENERAL wins first for classic AppSec engines / categories.
    if tool_l in {"bandit", "detect-secrets", "presidio"}:
        return "GENERAL"
    if cat in {"static", "pii"}:
        return "GENERAL"
    if any(
        key in title_l
        for key in (
            "url fetch",
            "urlopen",
            "urllib",
            "ssrf",
            "shell=true",
            "os.system",
            "hardcoded",
            "secret:",
            "assert used",
        )
    ):
        return "GENERAL"

    if cat in _AI_CATEGORIES:
        return "AI_LLM"
    if tool_l in _AI_TOOLS or tool_l.startswith("architecture-"):
        return "AI_LLM"
    if any(t == "llm / agent" or t.startswith("llm /") for t in tags_l):
        return "AI_LLM"
    if any(
        key in " ".join(tags_l)
        for key in ("privacy & cloud", "workflow graph", "mcp", "rag", "hitl")
    ):
        return "AI_LLM"
    if any(str(o).upper().startswith("LLM") for o in (owasp or [])):
        return "AI_LLM"
    if any(
        key in title_l
        for key in (
            "prompt",
            "bind_tools",
            "react agent",
            "system message",
            "rag ",
            "hitl",
            "mcp",
            "langchain",
            "crewai",
            "max_tokens",
            "jailbreak",
        )
    ):
        return "AI_LLM"

    return "GENERAL"


def severity_label(severity: str) -> str:
    return (severity or "medium").strip().upper()
