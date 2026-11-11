"""Shared Finding / Trace / Policy / ScanJob models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field, model_validator

from isovane_serve.catalog import CATEGORIES, SEVERITIES, SOURCES, STATUSES
from isovane_serve.issue_type import IssueType, classify_issue_type, severity_label


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


Severity = Literal["critical", "high", "medium", "low"]
FindingSource = Literal["analyze", "watch", "hunt"]
FindingCategory = Literal[
    "static", "prompt", "pii", "injection", "architecture", "runtime", "agency"
]
FindingStatus = Literal["open", "accepted", "fixed", "wontfix", "false_positive"]
FixKind = Literal["prompt", "policy", "schema", "code", "architecture"]
# Re-export for API consumers
IssueTypeLabel = IssueType


class SuggestedFix(BaseModel):
    kind: FixKind
    diff: str | None = None
    checklist: list[str] = Field(default_factory=list)
    summary: str | None = None


class FindingEvidence(BaseModel):
    path: str | None = None
    line: int | None = None
    snippet: str | None = None
    diagram_region: str | None = None
    tool: str | None = None
    args: dict[str, Any] | None = None
    source_channel: str | None = None


class IncidentCase(BaseModel):
    """One documented real-world incident used to motivate a fix."""

    headline: str
    when: str = ""
    story: str = ""
    technical: str = ""
    source: str = ""


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: new_id("fnd"))
    workspace_id: str
    agent_id: str | None = None
    source: FindingSource
    severity: Severity
    title: str
    summary: str
    # AI_LLM | GENERAL — set automatically from category/tool/tags if omitted
    issue_type: IssueType = "GENERAL"
    exploit: str | None = None
    real_world: str | None = None
    # Engineer-facing root-cause / sink / verify write-up (not the plain Description)
    technical_details: str | None = None
    # Legacy single-incident fields (first of `incidents` mirrored for older clients)
    incident_headline: str | None = None
    incident_when: str | None = None
    incident_story: str | None = None
    incident_technical: str | None = None
    incidents: list[IncidentCase] = Field(default_factory=list)
    solutions: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    category: FindingCategory
    evidence: FindingEvidence = Field(default_factory=FindingEvidence)
    pii_classes: list[str] = Field(default_factory=list)
    policy_rule_id: str | None = None
    status: FindingStatus = "open"
    suggested_fix: SuggestedFix | None = None
    created_at: str = Field(default_factory=utc_now)
    closed_at: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def description(self) -> str:
        """Alias for summary — stable field name for UI/API consumers."""
        return self.summary

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_label(self) -> str:
        """CRITICAL | HIGH | MEDIUM | LOW."""
        return severity_label(self.severity)

    @model_validator(mode="after")
    def _normalize_issue_type(self) -> Finding:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity: {self.severity}")
        if self.source not in SOURCES:
            raise ValueError(f"bad source: {self.source}")
        if self.category not in CATEGORIES:
            raise ValueError(f"bad category: {self.category}")
        if self.status not in STATUSES:
            raise ValueError(f"bad status: {self.status}")
        tool = self.evidence.tool if self.evidence else None
        self.issue_type = classify_issue_type(
            category=self.category,
            tags=self.tags,
            owasp=self.owasp,
            tool=tool,
            title=self.title,
        )
        return self


class TraceEvent(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    source: str = "user"
    confirmed: bool = False
    verdict: str
    reason: str
    finding_id: str | None = None
    owasp: list[str] = Field(default_factory=list)
    pii_classes: list[str] = Field(default_factory=list)
    at: str = Field(default_factory=utc_now)


class Trace(BaseModel):
    id: str = Field(default_factory=lambda: new_id("trc"))
    workspace_id: str
    agent_id: str | None = None
    run_id: str | None = None
    kind: Literal["watch", "hunt"] = "watch"
    events: list[TraceEvent] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now)


class ScanJob(BaseModel):
    id: str = Field(default_factory=lambda: new_id("job"))
    workspace_id: str
    status: Literal["queued", "running", "done", "failed"] = "queued"
    inputs: dict[str, Any] = Field(default_factory=dict)
    finding_ids: list[str] = Field(default_factory=list)
    error: str | None = None
    created_at: str = Field(default_factory=utc_now)
    finished_at: str | None = None


class PolicyConfig(BaseModel):
    version: int = 1
    allow_tools: list[str] = Field(
        default_factory=lambda: ["read", "list", "search", "get", "log"]
    )
    consequential: list[str] = Field(
        default_factory=lambda: [
            "send",
            "email",
            "mail",
            "pay",
            "transfer",
            "refund",
            "write",
            "delete",
            "shell",
            "exec",
            "fetch",
            "urlopen",
            "browse",
        ]
    )
    require_confirm: list[str] = Field(
        default_factory=lambda: [
            "send",
            "pay",
            "refund",
            "write",
            "delete",
            "shell",
            "exec",
            "fetch",
            "urlopen",
        ]
    )
    money_tools: list[str] = Field(default_factory=lambda: ["pay", "transfer", "refund"])
    untrusted_sources: list[str] = Field(
        default_factory=lambda: [
            "email",
            "web",
            "page",
            "doc",
            "document",
            "tool_return",
            "rag",
        ]
    )
    block_if_untrusted_source: bool = True
    amount_cap: float = 500
    deny_pii_outbound: bool = True
    pii_classes: list[str] = Field(
        default_factory=lambda: [
            "email",
            "phone",
            "pan",
            "aadhaar",
            "ssn",
            "api_key",
            "password",
            "credit_card",
        ]
    )
    max_tool_calls_per_run: int = 40
    timeout_seconds: int = 120
