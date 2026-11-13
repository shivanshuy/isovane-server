"""Pydantic payloads for Trust Studio APIs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class CapabilityNode(BaseModel):
    id: str
    label: str
    kind: str = "tool"
    caps: list[str] = Field(default_factory=list)
    source: str = "board"  # board | code | mcp
    path: str | None = None


class ToxicFlow(BaseModel):
    id: str
    pair_id: str
    label: str
    severity: str = "high"
    caps: list[str] = Field(default_factory=list)
    nodes: list[str] = Field(default_factory=list)
    edges: list[dict[str, str]] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    finding_title: str | None = None


class DualLlmVerdict(BaseModel):
    id: str
    agent_id: str
    agent_label: str
    has_untrusted: bool
    has_privileged_tools: bool
    has_quarantine: bool
    severity: str = "high"
    summary: str
    owasp: list[str] = Field(default_factory=lambda: ["LLM01", "ASI01"])


class ModelSeesTool(BaseModel):
    name: str
    description: str = ""
    poison_signals: list[str] = Field(default_factory=list)


class ModelSeesView(BaseModel):
    server: str
    path: str
    raw_text: str
    tools: list[ModelSeesTool] = Field(default_factory=list)
    poison_signals: list[str] = Field(default_factory=list)
    split_risk: bool = False


class TrustPattern(BaseModel):
    id: str
    title: str
    summary: str
    remediation_id: str | None = None
    owasp: list[str] = Field(default_factory=list)
    policy_snippet: str | None = None


class TrifectaAxis(BaseModel):
    present: bool
    nodes: list[str] = Field(default_factory=list)
    detail: str = ""


class TrifectaScorecard(BaseModel):
    schema_id: Literal["isovane.trifecta.v1"] = "isovane.trifecta.v1"
    private_data: TrifectaAxis
    untrusted_ingress: TrifectaAxis
    egress: TrifectaAxis
    complete: bool
    severity: str = "low"
    blocking_flows: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


class StudioState(BaseModel):
    workspace_id: str
    toxic_flows: list[ToxicFlow] = Field(default_factory=list)
    capability_nodes: list[CapabilityNode] = Field(default_factory=list)
    dual_llm: list[DualLlmVerdict] = Field(default_factory=list)
    model_views: list[ModelSeesView] = Field(default_factory=list)
    trifecta: TrifectaScorecard | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
