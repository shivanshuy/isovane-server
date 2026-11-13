"""Generate copyable patches for findings (LibCST when available).

Analyze fixes = code / prompt / architecture (dev-time).
Watch / hunt fixes = policy / gate wrappers (runtime).
Same Finding id — different remediation lane.

Remediation checklists/diffs come from config/remediations.yaml (industry standards).
Source tags stay in YAML only — never shown to developers in the UI payload.
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
from isovane_serve.remediations import enrich_finding_fix
from isovane_serve import store


def patch_for_finding(finding_id: str) -> dict[str, Any] | None:
    finding = store.FINDINGS.get(finding_id)
    if finding is None:
        return None
    lane = _lane(finding)
    fix = enrich_finding_fix(finding)
    if finding.suggested_fix is None or _should_refresh_fix(finding.suggested_fix, fix):
        store.patch_finding(finding_id, suggested_fix=fix.model_dump())
        finding = store.FINDINGS[finding_id]
    assert finding is not None
    fix = finding.suggested_fix or fix
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


def _should_refresh_fix(existing: SuggestedFix, enriched: SuggestedFix) -> bool:
    """Prefer YAML catalog when existing fix is thin."""
    if not existing.diff and enriched.diff:
        return True
    if len(existing.checklist or []) < 2 and len(enriched.checklist or []) >= 2:
        return True
    return False


def _lane(finding: Finding) -> str:
    if finding.source in ("watch", "hunt") or finding.category == "runtime":
        return "watch"
    return "analyze"


def _default_fix(finding: Finding, lane: str) -> SuggestedFix:
    # Kept for callers; prefer enrich_finding_fix.
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
    enriched = enrich_finding_fix(finding)
    if enriched.checklist or enriched.diff:
        return enriched
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
            checklist=["Edit system prompt", "Re-run Analyze prompts"],
        )
    if finding.category == "pii":
        return SuggestedFix(
            kind="code",
            summary=pii_fix_summary(),
            checklist=["Remove hardcoded secrets", "Add redact before tools"],
        )
    return SuggestedFix(
        kind="code",
        summary=analyze_code_fix_summary(),
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
        lines.append(f"# {fix.summary.strip()}")
        lines.append("")
    if fix.diff:
        lines.append(fix.diff)
    if fix.checklist:
        lines.append("")
        lines.append("# Checklist")
        lines.extend(f"# - {item}" for item in fix.checklist)
    return "\n".join(lines) + "\n"
