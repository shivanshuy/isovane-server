"""Generate copyable patches for findings (LibCST when available).

Analyze fixes = code / prompt / architecture (dev-time).
Watch / hunt fixes = policy / gate wrappers (runtime).
Same Finding id — different remediation lane.
"""

from __future__ import annotations

from typing import Any

from isovane_serve.copy import (
    analyze_code_fix_summary,
    architecture_fix_summary,
    pii_fix_summary,
    prompt_fix_summary,
    watch_policy_fix_summary,
)
from isovane_serve.models import Finding, SuggestedFix
from isovane_serve import store


def patch_for_finding(finding_id: str) -> dict[str, Any] | None:
    finding = store.FINDINGS.get(finding_id)
    if finding is None:
        return None
    lane = _lane(finding)
    fix = finding.suggested_fix or _default_fix(finding, lane)
    if finding.suggested_fix is None:
        store.patch_finding(finding_id, suggested_fix=fix.model_dump())
        finding = store.FINDINGS[finding_id]
    assert finding is not None
    return {
        "finding_id": finding.id,
        "lane": lane,
        "source": finding.source,
        "kind": fix.kind,
        "summary": fix.summary,
        "diff": fix.diff,
        "checklist": fix.checklist,
        "copy_text": _copy_text(finding, fix, lane),
        "lane_label": (
            "Dev-time fix (Analyze)"
            if lane == "analyze"
            else "Runtime gate fix (Watch)"
        ),
    }


def accept_finding(finding_id: str) -> Finding | None:
    return store.patch_finding(finding_id, status="accepted")


def mark_fixed(finding_id: str) -> Finding | None:
    return store.patch_finding(finding_id, status="fixed")


def _lane(finding: Finding) -> str:
    if finding.source in ("watch", "hunt") or finding.category == "runtime":
        return "watch"
    return "analyze"


def _default_fix(finding: Finding, lane: str) -> SuggestedFix:
    if lane == "watch":
        return SuggestedFix(
            kind="policy",
            summary=watch_policy_fix_summary(),
            diff=_policy_diff(finding),
            checklist=[
                "Keep judge() outside the model",
                "Wrap tool invoke with POST /gates",
                "Re-run hunt pack in CI",
            ],
        )
    if finding.category == "architecture":
        return SuggestedFix(
            kind="architecture",
            summary=architecture_fix_summary(),
            checklist=[
                "Mark untrusted ingress",
                "Add HITL before consequential tools",
                "Re-run Analyze on diagram",
            ],
        )
    if finding.category == "prompt":
        return SuggestedFix(
            kind="prompt",
            summary=prompt_fix_summary(),
            diff="+ Never place PII in tool args.\n+ Require confirm before send/pay/shell.",
            checklist=["Edit system prompt", "Re-run Analyze prompts"],
        )
    if finding.category == "pii":
        return SuggestedFix(
            kind="code",
            summary=pii_fix_summary(),
            diff="- body = user_text\n+ body = redact(user_text)",
            checklist=["Remove hardcoded secrets", "Add redact before tools"],
        )
    return SuggestedFix(
        kind="code",
        summary=analyze_code_fix_summary(),
        diff=_code_diff(finding),
        checklist=["Apply code patch", "Re-run Analyze on folder"],
    )


def _policy_diff(finding: Finding) -> str:
    tool = (finding.evidence.tool or "send").lower()
    return (
        "# Runtime policy — Watch / sidecar\n"
        "# policies/default.yaml\n"
        f"# finding {finding.id} · {', '.join(finding.owasp)}\n"
        "block_if_untrusted_source: true\n"
        f"require_confirm: [..., {tool}]\n"
        "deny_pii_outbound: true\n"
    )


def _code_diff(finding: Finding) -> str:
    """Copyable diffs for top code/prompt finding classes (apply manually / CI later)."""
    path = finding.evidence.path or "agent.py"
    title = (finding.title or "").lower()
    blob = f"{finding.title} {finding.summary} {finding.category}".lower()

    if "shell=true" in blob or "shell true" in blob:
        return (
            f"# {path}\n"
            "- subprocess.run(cmd, shell=True)\n"
            "+ subprocess.run(shlex.split(cmd), shell=False)\n"
        )
    if "system prompt" in blob or "user input concatenated" in blob or "tainted" in blob:
        return (
            f"# {path}\n"
            '- SystemMessage(content=f"You are helpful. User: {user_text}")\n'
            '+ SystemMessage(content="You are helpful.")\n'
            "+ HumanMessage(content=user_text)\n"
        )
    if "max_tokens" in blob:
        return (
            f"# {path}\n"
            "- ChatOpenAI(model=\"gpt-4o\")\n"
            "+ ChatOpenAI(model=\"gpt-4o\", max_tokens=2048, timeout=60)\n"
        )
    if "unpinned" in blob or "npx" in blob or "uvx" in blob or "mcp" in blob:
        return (
            f"# {path} or mcp.json\n"
            '- "args": ["-y", "@modelcontextprotocol/server-filesystem"]\n'
            '+ "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2"]\n'
        )
    if "eval" in blob or "exec" in blob:
        return (
            f"# {path}\n"
            "- result = eval(llm_output)\n"
            "+ result = json.loads(llm_output)  # structured only; never eval\n"
        )
    if "hitl" in blob or "confirm" in blob:
        return (
            f"# {path}\n"
            "+ from isovane_gate import require_confirm\n"
            "+ require_confirm(tool=\"send\", source=channel)\n"
            "+ # or: interrupt() before consequential tools in LangGraph\n"
        )
    if "pii" in blob or "secret" in blob or "api_key" in blob:
        return (
            f"# {path}\n"
            "- OPENAI_API_KEY = \"sk-...\"\n"
            "+ OPENAI_API_KEY = os.environ[\"OPENAI_API_KEY\"]\n"
            "+ body = redact(user_text)\n"
        )
    if "wildcard" in blob or "tools list" in blob or "bind_tools" in blob:
        return (
            f"# {path}\n"
            "- tools = load_all_tools()\n"
            "+ tools = [search_docs, read_ticket]  # explicit allow-list\n"
            "+ model.bind_tools(tools)\n"
        )
    if finding.category == "architecture" or "architecture" in blob:
        return (
            "# Architecture board remediation\n"
            "# 1) Add HITL box before consequential tools\n"
            "# 2) Cut UI→shell edges; pin MCP; label DLP/ZDR on LLM egress\n"
            "# 3) Analyze board\n"
        )
    return (
        f"# Dev-time code fix — Analyze\n"
        f"# {path} · {title or finding.category}\n"
        "- # unsafe agent path\n"
        "+ # allow-list tools · gate invoke · redact PII · pin MCP\n"
    )


def _copy_text(finding: Finding, fix: SuggestedFix, lane: str) -> str:
    lane_title = (
        "ANALYZE → DEV FIX (code / prompt / architecture)"
        if lane == "analyze"
        else "WATCH → RUNTIME FIX (policy / sidecar gate)"
    )
    lines = [
        f"# Isovane · {lane_title}",
        f"# finding {finding.id} · source={finding.source}",
        f"# {finding.title}",
        f"# OWASP: {', '.join(finding.owasp)}",
        f"# patch kind: {fix.kind}",
        "",
    ]
    if fix.summary:
        lines.append(f"# {fix.summary}")
        lines.append("")
    if fix.diff:
        lines.append(fix.diff)
    if fix.checklist:
        lines.append("")
        lines.append("# Checklist")
        lines.extend(f"# - {item}" for item in fix.checklist)
    return "\n".join(lines) + "\n"


def try_libcst_rewrite(source: str, finding: Finding) -> str | None:
    """Optional LibCST rewrite for shell=True → shell=False."""
    if "shell=True" not in source:
        return None
    try:
        import libcst as cst  # type: ignore
    except Exception:
        return source.replace("shell=True", "shell=False")

    class ShellFalse(cst.CSTTransformer):
        def leave_Arg(self, original_node: cst.Arg, updated_node: cst.Arg) -> cst.Arg:
            if (
                original_node.keyword
                and original_node.keyword.value == "shell"
                and isinstance(original_node.value, cst.Name)
                and original_node.value.value == "True"
            ):
                return updated_node.with_changes(value=cst.Name("False"))
            return updated_node

    try:
        module = cst.parse_module(source)
        return module.visit(ShellFalse()).code
    except Exception:
        return source.replace("shell=True", "shell=False")
