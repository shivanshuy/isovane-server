"""Architecture mode 2: Agentic Radar–style workflow graph (UI → agents → MCP → tools)."""

from __future__ import annotations

from typing import Any

from isovane_serve.insights import insight_for
from isovane_serve.kinds import a2a_tokens, kind_for_label, kind_tokens
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix
from isovane_serve.remediations import apply_remediation_fields

__all__ = [
    "analyze_workflow",
    "classify_nodes",
    "inventory_summary",
    "kind_for_label",
]


def classify_nodes(text: str, raw_nodes: list[str]) -> list[dict[str, Any]]:
    """Build a typed inventory from diagram text + extracted node labels."""
    lower = text.lower()
    inventory: list[dict[str, Any]] = []
    # Prefer real diagram labels; bare tokens like "agent" only when nothing else was extracted.
    cleaned = [n.strip() for n in raw_nodes if n and str(n).strip()]
    labels = list(dict.fromkeys(cleaned)) or list(dict.fromkeys(_token_labels(lower)))
    for label in labels:
        kind = kind_for_label(label.lower())
        if kind == "unknown" and len(label) < 2:
            continue
        inventory.append({"id": label, "kind": kind, "label": label})
    # Ensure diagram-level kinds even without explicit node names
    if any(t in lower for t in kind_tokens("mcp")) and not any(
        n["kind"] == "mcp" for n in inventory
    ):
        inventory.append({"id": "MCP", "kind": "mcp", "label": "MCP servers"})
    if any(t in lower for t in kind_tokens("ui")) and not any(
        n["kind"] == "ui" for n in inventory
    ):
        inventory.append({"id": "UI", "kind": "ui", "label": "User interface"})
    return inventory


def analyze_workflow(
    workspace_id: str,
    text: str,
    *,
    filename: str | None = None,
    inventory: list[dict[str, Any]] | None = None,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    lower = text.lower()
    inv = inventory or classify_nodes(text, [])
    kinds = {n["kind"] for n in inv}
    findings: list[Finding] = []

    has_ui = "ui" in kinds or any(t in lower for t in kind_tokens("ui"))
    has_agent = "agent" in kinds or any(t in lower for t in kind_tokens("agent"))
    has_mcp = "mcp" in kinds or any(t in lower for t in kind_tokens("mcp"))
    has_tool = "tool" in kinds or any(t in lower for t in kind_tokens("tool"))
    has_hitl = "hitl" in kinds or any(t in lower for t in kind_tokens("hitl"))
    has_a2a = any(t in lower for t in a2a_tokens()) or sum(
        1 for n in inv if n["kind"] == "agent"
    ) >= 2
    has_auth = any(t in lower for t in ("auth", "oauth", "mtls", "jwt", "signed", "acl", "rbac"))
    has_shell = any(t in lower for t in ("shell", "exec", "bash", "powershell", "code interpreter"))
    wildcard = "*" in text or "all tools" in lower or "tools=*" in lower or "permissions: *" in lower
    # OWASP ASI diagram markers (keyword presence only — recall-first).
    has_memory = any(
        t in lower
        for t in (
            "long-term memory",
            "agent memory",
            "memory store",
            "vector store",
            "vector db",
            "conversation store",
            "checkpoint store",
        )
    )
    has_memory_guard = any(
        t in lower
        for t in (
            "memory validation",
            "memory guard",
            "memory provenance",
            "segmented memory",
            "memory allow",
        )
    )
    has_policy_gate = any(
        t in lower
        for t in (
            "policy gate",
            "intent gate",
            "policy engine",
            "policy enforcement",
            "tool gateway",
            "guardrail middleware",
        )
    )
    has_breaker = any(
        t in lower
        for t in (
            "circuit breaker",
            "rate limit",
            "rate-limit",
            "kill switch",
            "blast radius",
            "tool budget",
            "token budget",
        )
    )
    has_agent_identity = any(
        t in lower
        for t in (
            "per-agent identity",
            "agent identity",
            "workload identity",
            "spiffe",
            "short-lived",
            "jit credential",
            "task-scoped",
        )
    )

    if has_ui and has_agent and not has_hitl and (has_tool or has_mcp or has_shell):
        findings.append(
            _finding(
                workspace_id,
                filename,
                "UI → agent → tools without HITL gate",
                (
                    "User interface reaches an agent that can call tools/MCP with no human "
                    "confirmation node on the consequential path (Agentic Radar: missing approval). "
                    "Roles may stop anonymous callers, but they do not stop a privileged agent "
                    "session from acting as a confused deputy when RAG/chat steers a refund or shell call."
                ),
                ["LLM06", "ASI09"],
                "high",
                [
                    "Insert HITL/approval before send/pay/shell/MCP side-effects",
                    "Keep the gate outside the model (sidecar / policy)",
                    "Treat RAG/email as untrusted — require confirm when source is not the user",
                    "Keep RBAC, but do not treat roles as a substitute for per-action confirm",
                ],
                "Add an explicit confirm node between agent planner and consequential tools.",
                tags=["Workflow graph", "HITL"],
                region="ui→agent→tools",
            )
        )

    if has_a2a and not has_auth:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Agent-to-agent edge without auth / identity",
                (
                    "Multi-agent or A2A handoff is present, but the diagram has no auth, mTLS, "
                    "or signed-message marker between agents (ASI07)."
                ),
                ["ASI07"],
                "high",
                [
                    "Mutual auth between agents",
                    "Deny unsigned A2A calls",
                    "Scope tools per agent identity",
                ],
                "Add authenticated A2A channels; never trust peer agents by network alone.",
                tags=["Workflow graph", "A2A"],
                region="agent→agent",
            )
        )

    if has_mcp:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "MCP servers on the agent path — verify allow-list",
                (
                    "MCP appears in the workflow. MCP tools inherit the agent's privileges; "
                    "poisoned tool descriptions or unpinned servers expand blast radius."
                ),
                ["LLM03", "ASI04", "LLM06"],
                "high",
                [
                    "Pin MCP package versions; prefer allow-listed servers",
                    "Scan skills/configs for tool poisoning",
                    "Sandbox network egress from MCP processes",
                ],
                "Treat MCP as supply-chain + agency: pin, allow-list, and gate tool invoke.",
                tags=["Workflow graph", "MCP"],
                region="agent→mcp",
            )
        )
        if not has_auth:
            findings.append(
                _finding(
                    workspace_id,
                    filename,
                    "MCP edge lacks auth / trust boundary marker",
                    "MCP connection is drawn without auth or trust-zone labeling.",
                    ["ASI04", "ASI07"],
                    "medium",
                    ["Authenticate MCP clients", "Isolate MCP on a private network"],
                    "Label MCP trust boundary and require auth on the transport.",
                    tags=["Workflow graph", "MCP"],
                    region="mcp-auth",
                )
            )

    if has_agent and has_tool and wildcard:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Wildcard / unrestricted tools on agent",
                "Workflow suggests agents with unrestricted tool permissions (*).",
                ["LLM06", "ASI03"],
                "critical",
                ["Replace * with explicit tool allow-list", "Split read-only vs consequential agents"],
                "Enumerate tools per agent; deny by default.",
                tags=["Workflow graph", "Agency"],
                region="agent-tools",
            )
        )

    if has_shell:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Shell / code-execution tool in workflow graph",
                "Shell/exec/code interpreter on the agent graph enables OS-level agency (ASI05).",
                ["ASI05", "LLM06"],
                "high",
                ["Remove shell from prod agents or sandbox + HITL", "Never pass raw chat into shell"],
                "Drop or heavily gate shell tools in production workflows.",
                tags=["Workflow graph", "Shell"],
                region="agent→shell",
            )
        )

    if has_ui and has_agent and "untrusted" not in lower and "trust" not in lower:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Missing trust-boundary label on UI ingress",
                (
                    "Chat/UI content is untrusted input. Diagrams should mark the UI→agent edge as "
                    "untrusted (prompt-injection ingress)."
                ),
                ["LLM01", "ASI01"],
                "medium",
                ["Mark UI/chat as untrusted source", "Strip instructions before tool policy"],
                "Annotate UI as untrusted; enforce source=user|web in the gate.",
                tags=["Workflow graph", "Trust boundary"],
                region="ui→agent",
            )
        )

    agent_count = sum(1 for n in inv if n["kind"] == "agent")
    if agent_count >= 3 and not has_hitl:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Multi-agent swarm without supervisor HITL",
                f"Inventory shows {agent_count} agent nodes without a human approval node.",
                ["LLM06", "ASI09"],
                "medium",
                ["Designate a supervisor with confirm for side-effects", "Limit which agents may call MCP"],
                "Add a supervisor/HITL node before any agent may invoke consequential MCP/tools.",
                tags=["Workflow graph", "Multi-agent"],
                region="swarm",
            )
        )

    if has_agent and has_memory and not has_memory_guard:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Agent memory / long-term context without validation",
                (
                    "Durable agent memory / vector context appears without validation, segmentation, "
                    "or provenance on the board (OWASP ASI06 Memory & Context Poisoning)."
                ),
                ["ASI06", "LLM08"],
                "high",
                [
                    "Validate memory writes before commit",
                    "Segment memory by user/session/domain",
                    "Require provenance and TTL on durable context",
                ],
                "Add a memory-validation edge and segmented stores before agents read long-term context.",
                tags=["Workflow graph", "Memory"],
                region="agent⇄memory",
            )
        )

    if has_agent and (has_tool or has_mcp or has_shell) and not has_policy_gate:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Missing external policy / intent gate before tools",
                (
                    "Tools/MCP are reachable from the agent without an external policy / intent gate "
                    "(OWASP ASI02 Policy Enforcement Middleware). Prompt-only controls are not enough."
                ),
                ["ASI02", "LLM06"],
                "high",
                [
                    "Insert a policy/intent gate (PEP) between planner and tools",
                    "Validate schema + rate limits; issue short-lived credentials",
                    "Fail closed on unknown tools or missing approval",
                ],
                "Separate planning from execution with an external policy enforcement point.",
                tags=["Workflow graph", "Policy gate"],
                region="planner→tools",
            )
        )

    if (has_a2a or agent_count >= 2) and not has_breaker:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Multi-agent path without circuit breaker / rate limits",
                (
                    "Multi-agent fan-out is present without circuit breaker, rate limit, budget, or "
                    "kill-switch markers (OWASP ASI08 Cascading Failures)."
                ),
                ["ASI08"],
                "high",
                [
                    "Add circuit breakers / quotas between planner and executor",
                    "Rate-limit anomalous cross-agent fan-out",
                    "Keep tamper-evident logs of inter-agent actions",
                ],
                "Cap blast radius with breakers and budgets on every multi-agent edge.",
                tags=["Workflow graph", "Cascading failures"],
                region="multi-agent",
            )
        )

    if has_agent and (has_tool or has_mcp) and not has_agent_identity and not has_auth:
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Agent tools without per-agent identity / scoped credentials",
                (
                    "Agents reach tools/MCP without per-agent identity or task-scoped credentials on "
                    "the board (OWASP ASI03 Identity & Privilege Abuse)."
                ),
                ["ASI03"],
                "high",
                [
                    "Assign each agent its own identity",
                    "Issue short-lived, task-scoped tokens — not a shared key",
                    "Re-authorize each privileged tool call in a policy engine",
                ],
                "Label per-agent identities and JIT credentials on every tool edge.",
                tags=["Workflow graph", "Identity"],
                region="agent→tools-identity",
            )
        )

    if not findings and text.strip():
        findings.append(
            _finding(
                workspace_id,
                filename,
                "Workflow graph needs agent / MCP / UI labels",
                (
                    "Label UI, agents, MCP servers, tools, and HITL nodes (Agentic Radar–style inventory) "
                    "so trust and agency edges can be scored."
                ),
                ["ASI10"],
                "low",
                ["Name each agent", "List MCP servers and tools", "Mark HITL if any"],
                "Redraw with UI → Agent(s) → MCP/Tools → Data and annotate auth/HITL.",
                tags=["Workflow graph"],
                region="unclassified",
            )
        )

    for f in findings:
        if f.evidence.args is None:
            f.evidence.args = {}
        f.evidence.args["analysis_mode"] = "workflow"
        f.evidence.args["inventory"] = inv[:40]
    return findings, inv


def inventory_summary(
    inv: list[dict[str, Any]],
    *,
    edges: list[dict[str, Any]] | None = None,
    board: dict[str, Any] | None = None,
    mermaid: str | None = None,
) -> dict[str, Any]:
    by_kind: dict[str, list[str]] = {}
    for node in inv:
        by_kind.setdefault(str(node.get("kind") or "unknown"), []).append(
            str(node.get("label") or node.get("id"))
        )
    out: dict[str, Any] = {
        "nodes": inv,
        "counts": {k: len(v) for k, v in by_kind.items()},
        "by_kind": by_kind,
    }
    if edges is not None:
        out["edges"] = edges
    if board is not None:
        out["board"] = board
    if mermaid:
        out["mermaid"] = mermaid
    return out


def _token_labels(lower: str) -> list[str]:
    labels: list[str] = []
    for kid in ("ui", "agent", "mcp", "tool", "hitl"):
        for token in kind_tokens(kid):
            if token in lower:
                labels.append(token)
                break
    return labels


def _finding(
    workspace_id: str,
    filename: str | None,
    title: str,
    summary: str,
    owasp: list[str],
    severity: str,
    checklist: list[str],
    fix_summary: str,
    *,
    tags: list[str],
    region: str,
) -> Finding:
    insight = insight_for(title=title, issue_text=summary, tool="architecture-workflow")
    fields = insight.as_finding_fields(owasp)
    fields["tags"] = list(dict.fromkeys([*(fields.get("tags") or []), *tags]))
    suggested = apply_remediation_fields(
        title=title,
        owasp=owasp,
        category="architecture",
        path=filename,
        existing=SuggestedFix(
            kind="architecture",
            summary=fix_summary,
            checklist=insight.merge_checklist(checklist),
        ),
    )
    if suggested.checklist:
        fields["solutions"] = list(suggested.checklist)
    return Finding(
        workspace_id=workspace_id,
        source="analyze",
        severity=severity,  # type: ignore[arg-type]
        title=title,
        category="architecture",
        evidence=FindingEvidence(
            path=filename,
            diagram_region=region,
            snippet=summary[:240],
            tool="architecture-workflow",
            args={"analysis_mode": "workflow"},
        ),
        suggested_fix=suggested,
        **fields,
    )
