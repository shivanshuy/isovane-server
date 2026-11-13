"""What-the-Model-Sees — reconstruct MCP descriptor blobs + poison/split signals."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from isovane_serve.insights import insight_for
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix
from isovane_serve.studio_models import ModelSeesTool, ModelSeesView
from isovane_serve.yaml_config import skip_dir_names

_POISON = [
    (re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions"), "ignore-previous"),
    (re.compile(r"(?i)you\s+are\s+now\s+(DAN|unrestricted|jailbroken)"), "jailbreak-persona"),
    (re.compile(r"(?i)curl\s+[^\n|]*\|\s*(?:ba)?sh"), "curl-pipe-shell"),
    (re.compile(r"(?i)exfiltrat|send\s+all\s+(secrets|keys|env)"), "exfil-instruction"),
    (re.compile(r"(?i)do\s+not\s+tell\s+the\s+user"), "concealment"),
    (re.compile(r"(?i)system\s*:\s*|<\s*/?\s*system\s*>"), "system-tag-injection"),
]
_SPLIT = re.compile(
    r"(?i)(part\s+\d+\s+of|continued\s+in|see\s+tool\s+#|fragment\s+\d+|concatenat)"
)
_CAP_CLAIM = re.compile(
    r"(?i)(this\s+tool\s+can|has\s+access\s+to|full\s+(filesystem|network)|admin\s+privileges)"
)


def analyze_model_views(
    workspace_id: str,
    folder: str | Path | None,
    *,
    live_probe: bool = False,
    persist_findings: bool = True,
) -> dict[str, Any]:
    root = Path(folder).expanduser() if folder else None
    views: list[ModelSeesView] = []
    if root and root.is_dir():
        views.extend(_views_from_tree(root, live_probe=live_probe))

    findings: list[Finding] = []
    for view in views:
        if view.poison_signals or view.split_risk:
            findings.append(_view_to_finding(workspace_id, view))

    if persist_findings and findings:
        from isovane_serve import store
        from isovane_serve.remediations import hydrate_finding

        for f in findings:
            store.add_finding(hydrate_finding(f))

    payload = {
        "workspace_id": workspace_id,
        "views": [v.model_dump(mode="json") for v in views],
        "findings": [{"id": f.id, "title": f.title, "severity": f.severity} for f in findings],
    }
    from isovane_serve.persistence import save_studio_slice

    save_studio_slice(workspace_id, "model_views", payload)
    return payload


def _views_from_tree(root: Path, *, live_probe: bool) -> list[ModelSeesView]:
    from isovane_serve.mcp_skills import _extract_mcp_servers, _try_parse_json

    views: list[ModelSeesView] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dir_names() for part in path.parts):
            continue
        name = path.name.lower()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "mcpservers" not in text.lower() and name not in {
            "mcp.json",
            "claude_desktop_config.json",
        }:
            if not (path.suffix.lower() in {".json", ".yml", ".yaml"} and "mcp" in name):
                continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        parsed = _try_parse_json(text)
        servers: dict[str, Any] = {}
        if isinstance(parsed, dict):
            extracted = _extract_mcp_servers(parsed)
            if extracted:
                servers = extracted
        if not servers:
            # Skill / free-text descriptor
            signals = _scan_poison(text)
            split = bool(_SPLIT.search(text))
            views.append(
                ModelSeesView(
                    server=path.stem,
                    path=rel,
                    raw_text=text[:8000],
                    tools=[],
                    poison_signals=signals,
                    split_risk=split,
                )
            )
            continue
        for server, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            tools = _tools_from_cfg(cfg)
            if live_probe:
                tools = _maybe_live_tools(cfg, tools)
            blob = _model_visible_blob(server, cfg, tools)
            signals = _scan_poison(blob)
            for t in tools:
                signals.extend(t.poison_signals)
            signals = sorted(set(signals))
            split = bool(_SPLIT.search(blob)) or any(_SPLIT.search(t.description) for t in tools)
            views.append(
                ModelSeesView(
                    server=str(server),
                    path=rel,
                    raw_text=blob,
                    tools=tools,
                    poison_signals=signals,
                    split_risk=split,
                )
            )
    return views


def _tools_from_cfg(cfg: dict[str, Any]) -> list[ModelSeesTool]:
    out: list[ModelSeesTool] = []
    for key in ("tools", "allowedTools", "allowed_tools", "includeTools"):
        raw = cfg.get(key)
        if not isinstance(raw, list):
            continue
        for item in raw:
            if isinstance(item, str):
                out.append(ModelSeesTool(name=item, description="", poison_signals=_scan_poison(item)))
            elif isinstance(item, dict):
                name = str(item.get("name") or item.get("tool") or item.get("id") or "tool")
                desc = str(
                    item.get("description") or item.get("desc") or json.dumps(item.get("inputSchema") or {})
                )
                out.append(
                    ModelSeesTool(name=name, description=desc, poison_signals=_scan_poison(f"{name}\n{desc}"))
                )
    return out


def _maybe_live_tools(cfg: dict[str, Any], existing: list[ModelSeesTool]) -> list[ModelSeesTool]:
    try:
        from isovane_serve.mcp_probe import _probe_tools_list, live_probe_enabled

        if not live_probe_enabled():
            return existing
        url = str(cfg.get("url") or cfg.get("serverUrl") or "").strip()
        if not url.startswith(("http://", "https://")):
            return existing
        names, err = _probe_tools_list(url, cfg)
        if err or not names:
            return existing
        by_name = {t.name: t for t in existing}
        for name in names:
            if name not in by_name:
                by_name[name] = ModelSeesTool(name=name, description="(from live tools/list)")
        return list(by_name.values())
    except Exception:  # noqa: BLE001
        return existing


def _model_visible_blob(server: str, cfg: dict[str, Any], tools: list[ModelSeesTool]) -> str:
    lines = [
        f"# MCP server visible to the model: {server}",
        f"description: {cfg.get('description') or ''}",
        f"command: {cfg.get('command') or ''}",
        f"args: {cfg.get('args') or []}",
        "tools:",
    ]
    for t in tools:
        lines.append(f"- name: {t.name}")
        if t.description:
            lines.append(f"  description: {t.description}")
    # Include skill-like prose fields often inlined into prompts
    for key in ("instructions", "systemPrompt", "prompt", "notes"):
        if cfg.get(key):
            lines.append(f"{key}: {cfg.get(key)}")
    return "\n".join(lines)[:12000]


def _scan_poison(text: str) -> list[str]:
    hits: list[str] = []
    for rx, label in _POISON:
        if rx.search(text or ""):
            hits.append(label)
    if _CAP_CLAIM.search(text or ""):
        hits.append("capability-claim")
    return hits


def _view_to_finding(workspace_id: str, view: ModelSeesView) -> Finding:
    signals = ", ".join(view.poison_signals) or ("split-instruction" if view.split_risk else "risk")
    title = f"What-the-model-sees risk — {view.server}"
    summary = (
        f"MCP '{view.server}' exposes model-visible text with signals: {signals}. "
        "Tool descriptions and skill prose are prompt-injection surface (ASI04 / LLM01)."
    )
    checklist = [
        "Review What-the-Model-Sees tab for highlighted poison spans",
        "Strip ignore-previous / curl|sh / concealment phrases from descriptions",
        "Do not split instructions across tool fragments",
        "Pin + attest MCP packages",
    ]
    insight = insight_for(title=title, issue_text=summary, tool="mcp-probe")
    return Finding(
        workspace_id=workspace_id,
        source="analyze",
        severity="high" if view.poison_signals else "medium",
        title=title,
        summary=summary,
        tags=["model-sees", "mcp", "trust-studio", *view.poison_signals],
        owasp=["ASI04", "LLM01", "LLM03"],
        category="architecture",
        evidence=FindingEvidence(
            path=view.path,
            snippet=view.raw_text[:1200],
            source_channel="model-sees",
            args={"server": view.server, "poison_signals": view.poison_signals, "split_risk": view.split_risk},
        ),
        suggested_fix=SuggestedFix(
            kind="architecture",
            summary="Sanitize tool descriptions; remove jailbreak/exfil instructions; avoid split payloads.",
            checklist=checklist,
            diff=(
                f"# Model-visible MCP: {view.server}\n"
                f"# signals: {signals}\n"
                f"- poisoned / split descriptor text\n"
                f"+ sanitized descriptions + single coherent tool contracts\n"
            ),
        ),
        policy_rule_id="mcp-model-view",
        exploit=insight.exploit or None,
        technical_details=insight.technical_details or None,
        solutions=list(insight.solutions or []) or checklist,
    )
