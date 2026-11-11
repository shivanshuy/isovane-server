"""LLM-first architecture risk findings from a reconstructed diagram graph."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from isovane_serve.http_client import post_json
from isovane_serve.insights import insight_for
from isovane_serve.model_config import (
    active_provider,
    arc_image_analyze_model,
    load_model_config,
    openai_api_key,
)
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix
from isovane_serve.yaml_config import load_prompts

log = logging.getLogger("isovane.risk_diagram")


class RiskDiagramError(RuntimeError):
    """LLM risk analyze failed."""


def _risk_prompt() -> str:
    text = load_prompts().get("architecture_risk") or ""
    if not text:
        raise RiskDiagramError(
            "Missing architecture_risk prompt in config/prompts.yaml"
        )
    return text



def analyze_risks_with_llm(
    workspace_id: str,
    *,
    graph: dict[str, Any] | None = None,
    text: str | None = None,
    nodes: list[dict[str, Any]] | None = None,
    edges: list[dict[str, Any]] | None = None,
    filename: str | None = None,
    mode: str = "both",
) -> dict[str, Any]:
    """Call arc_image_analyze on the Structurizr/C4 workspace; return findings + meta."""
    from isovane_serve.architecture_graph import graph_from_parts, llm_payload, normalize_graph

    if graph:
        arch = normalize_graph(graph, source="llm", filename=filename)
    else:
        arch = graph_from_parts(nodes, edges, source="llm", filename=filename)
    payload = llm_payload(arch, mode=mode)
    if filename:
        ws = payload.setdefault("workspace", arch)
        props = ws.setdefault("properties", {})
        if isinstance(props, dict):
            props["isovane.filename"] = filename
    # Keep a short text hint only as optional context for older models
    if text:
        payload["diagram_text_hint"] = str(text)[:2000]

    provider = active_provider()
    model = arc_image_analyze_model()
    raw = _chat(provider, model, json.dumps(payload, ensure_ascii=False))
    findings = _parse_findings(workspace_id, raw, filename=filename)
    if not findings:
        raise RiskDiagramError("LLM returned no usable findings JSON.")
    return {
        "findings": findings,
        "provider": provider,
        "model": model,
        "raw_chars": len(raw),
        "graph": arch,
    }


def _chat(provider: str, model: str, diagram_json: str) -> str:
    content = f"{_risk_prompt()}\n\nSTRUCTURIZR_WORKSPACE:\n{diagram_json}"
    try:
        if provider == "openai":
            key = openai_api_key()
            if not key:
                raise RiskDiagramError(
                    "OpenAI selected but no API key for arc_image_analyze."
                )
            cfg = load_model_config()["openai"]
            url = f"{cfg['base_url']}/chat/completions"
            data = post_json(
                url,
                {
                    "model": model,
                    "temperature": 0.1,
                    "messages": [{"role": "user", "content": content}],
                },
                headers={"Authorization": f"Bearer {key}"},
                timeout=int(cfg["timeout_seconds"]),
            )
            choices = data.get("choices") or []
            if not choices:
                raise RiskDiagramError("OpenAI returned no choices for risk analyze.")
            message = (choices[0] or {}).get("message") or {}
            return str(message.get("content") or "")

        cfg = load_model_config()["ollama"]
        url = f"{cfg['base_url']}/api/chat"
        data = post_json(
            url,
            {
                "model": model,
                "stream": False,
                "messages": [{"role": "user", "content": content}],
                "options": {"temperature": 0.1},
            },
            headers={},
            timeout=int(cfg["timeout_seconds"]),
        )
    except RuntimeError as exc:
        raise RiskDiagramError(str(exc)) from exc
    message = data.get("message") if isinstance(data.get("message"), dict) else {}
    return str(message.get("content") or data.get("response") or "")


def _parse_findings(
    workspace_id: str,
    raw: str,
    *,
    filename: str | None,
) -> list[Finding]:
    data = _extract_json(raw)
    if not data:
        return []
    items = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return []
    out: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        summary = str(item.get("summary") or "").strip()
        if not title or not summary:
            continue
        severity = str(item.get("severity") or "medium").lower().strip()
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "medium"
        owasp = [str(x) for x in (item.get("owasp") or []) if x][:6]
        tags = [str(x) for x in (item.get("tags") or ["Architecture", "LLM"]) if x][:8]
        checklist = [str(x) for x in (item.get("checklist") or []) if x][:8]
        fix_summary = str(item.get("fix_summary") or "Remediate on the architecture board, then re-analyze.")
        region = str(item.get("region") or "diagram")[:80]
        insight = insight_for(title=title, issue_text=summary, tool="architecture-llm")
        fields = insight.as_finding_fields(owasp or ["LLM01"])
        fields["tags"] = list(dict.fromkeys([*(fields.get("tags") or []), *tags, "LLM analyze"]))
        out.append(
            Finding(
                workspace_id=workspace_id,
                source="analyze",
                severity=severity,  # type: ignore[arg-type]
                title=title[:160],
                category="architecture",
                evidence=FindingEvidence(
                    path=filename,
                    diagram_region=region,
                    snippet=summary[:240],
                    tool="architecture-llm",
                    args={"analysis_mode": "llm", "engine": "arc_image_analyze"},
                ),
                suggested_fix=SuggestedFix(
                    kind="architecture",
                    summary=fix_summary[:240],
                    checklist=insight.merge_checklist(checklist),
                ),
                **fields,
            )
        )
    return out


def _extract_json(raw: str) -> dict[str, Any] | None:
    text = (raw or "").strip()
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S | re.I)
    if fence:
        text = fence.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    blob = text[start : end + 1]
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None
