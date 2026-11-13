"""Dev-time MCP depth: toxic-flow heuristics + optional remote tools/list probe.

Does **not** spawn stdio MCP servers by default (unsafe). Live probe is opt-in for
HTTP(S) endpoints only via ``mcp.live_probe`` / ``ISOVANE_MCP_LIVE_PROBE=1``.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from isovane_serve.insights import insight_for
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix
from isovane_serve.yaml_config import load_scan_settings

# Capability classes for toxic-flow pairing (Snyk Agent Scan–style narrative).
_READ_FS = re.compile(
    r"(?i)\b(read_?file|read_?dir|list_?dir|filesystem|fs\.|cat\b|get_file|download)\b"
)
_WRITE_FS = re.compile(
    r"(?i)\b(write_?file|delete_?file|rm\b|unlink|put_file|upload|mkdir)\b"
)
_SHELL = re.compile(
    r"(?i)\b(shell|bash|powershell|cmd\.exe|exec|run_command|terminal|code.?interpreter)\b"
)
_NETWORK = re.compile(
    r"(?i)\b(http|fetch|request|curl|wget|browser|browse|web_search|urlopen)\b"
)
_EXFIL = re.compile(
    r"(?i)(send_?email|send_?mail|send_?message|post_message|"
    r"\bemail\b|\bmail\b|\bslack\b|\bwebhook\b|\btelegram\b|\bdiscord\b|\bnotify\b)"
)
_SECRETS = re.compile(
    r"(?i)(api_?key|access_?token|\benv\b|\bsecret\b|\bcredential\b|"
    r"\bpassword\b|\bkeychain\b|\bvault\b)"
)
_INTEGRITY_KEYS = ("integrity", "sha256", "sha512", "digest", "packageIntegrity", "attest")


def _mcp_cfg() -> dict[str, Any]:
    return load_scan_settings().get("mcp") or {}


def live_probe_enabled() -> bool:
    env = os.environ.get("ISOVANE_MCP_LIVE_PROBE", "").strip().lower()
    if env in {"1", "true", "yes", "on"}:
        return True
    if env in {"0", "false", "no", "off"}:
        return False
    return bool(_mcp_cfg().get("live_probe"))


def deepen_mcp_server(
    workspace_id: str,
    rel: str,
    server: str,
    cfg: dict[str, Any],
) -> list[Finding]:
    """Extra findings beyond static pin/auth/wildcard walk."""
    out: list[Finding] = []
    out.extend(_check_missing_attest(workspace_id, rel, server, cfg))
    tools = _declared_tools(cfg)
    out.extend(_check_toxic_flows(workspace_id, rel, server, tools, source="config"))
    if live_probe_enabled():
        url = str(cfg.get("url") or cfg.get("serverUrl") or "").strip()
        if url.startswith(("http://", "https://")):
            probed, err = _probe_tools_list(url, cfg)
            if err:
                out.append(
                    _finding(
                        workspace_id,
                        rel,
                        title=f"MCP live probe failed — {server}",
                        summary=(
                            f"Opt-in live probe could not list tools from {url}: {err}. "
                            "Confirm the endpoint speaks MCP JSON-RPC tools/list."
                        ),
                        severity="low",
                        owasp=["ASI04"],
                        checklist=[
                            "Verify URL and auth headers",
                            "Re-run Analyze with ISOVANE_MCP_LIVE_PROBE=1 after fixing reachability",
                        ],
                        rule_id="mcp-live-probe-error",
                        server=server,
                    )
                )
            elif probed:
                out.extend(
                    _check_toxic_flows(
                        workspace_id, rel, server, probed, source="live-tools/list"
                    )
                )
                out.extend(_check_dangerous_tool_names(workspace_id, rel, server, probed))
    return out


def _declared_tools(cfg: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("tools", "allowedTools", "allowed_tools", "includeTools"):
        raw = cfg.get(key)
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    names.append(item)
                elif isinstance(item, dict):
                    n = item.get("name") or item.get("tool") or item.get("id")
                    if n:
                        names.append(str(n))
        elif isinstance(raw, str):
            names.append(raw)
    # Description / args often encode capability even without tools[]
    blob = " ".join(
        [
            str(cfg.get("description") or ""),
            " ".join(str(a) for a in (cfg.get("args") or []) if a),
            str(cfg.get("command") or ""),
        ]
    )
    if blob.strip():
        names.append(blob)
    return names


def _caps(names: list[str]) -> set[str]:
    caps: set[str] = set()
    for name in names:
        if _READ_FS.search(name):
            caps.add("read_fs")
        if _WRITE_FS.search(name):
            caps.add("write_fs")
        if _SHELL.search(name):
            caps.add("shell")
        if _NETWORK.search(name):
            caps.add("network")
        if _EXFIL.search(name):
            caps.add("exfil")
        if _SECRETS.search(name):
            caps.add("secrets")
    return caps


def _check_toxic_flows(
    workspace_id: str,
    rel: str,
    server: str,
    tools: list[str],
    *,
    source: str,
) -> list[Finding]:
    from isovane_serve.capabilities import matching_pairs

    caps = _caps(tools)
    out: list[Finding] = []
    for pair in matching_pairs(caps):
        need = set(pair["caps"])
        label = str(pair["label"])
        sev = str(pair.get("severity") or "high")
        out.append(
            _finding(
                workspace_id,
                rel,
                title=f"MCP toxic flow risk — {server}",
                summary=(
                    f"Server '{server}' exposes a toxic capability pair ({label}) "
                    f"via {source}. An agent that can call these tools in one session "
                    "can chain them without extra privileges (ASI02 / ASI04)."
                ),
                severity=sev if sev in {"critical", "high", "medium", "low"} else "high",
                owasp=["ASI02", "ASI04", "LLM06"],
                checklist=[
                    "Split tools across servers with least privilege",
                    "Require HITL before exfil/shell tools",
                    "Allow-list exact tool names — never '*'",
                    "Deny cross-tool chaining in the policy gate",
                    "Open Trust Studio → Toxic Flows for the capability graph",
                ],
                rule_id="mcp-toxic-flow",
                server=server,
                diff=(
                    f"# MCP toxic flow ({source})\n"
                    f"# server: {server}\n"
                    f"# caps: {sorted(caps)}\n"
                    f"- tools spanning {sorted(need)}\n"
                    f"+ split into separate servers + HITL on high-impact side\n"
                ),
            )
        )
    return out


def _check_dangerous_tool_names(
    workspace_id: str, rel: str, server: str, tools: list[str]
) -> list[Finding]:
    out: list[Finding] = []
    for name in tools:
        if not isinstance(name, str):
            continue
        if _SHELL.search(name) or name.strip() in {"*", "all"}:
            out.append(
                _finding(
                    workspace_id,
                    rel,
                    title=f"MCP live tool is high-agency — {server}",
                    summary=(
                        f"tools/list returned high-agency tool '{name}' on '{server}'. "
                        "Gate with HITL / sandbox before production agents can invoke it."
                    ),
                    severity="high",
                    owasp=["ASI05", "ASI02"],
                    checklist=[
                        "Remove shell/exec tools from prod MCP allow-lists",
                        "Or sandbox + HITL + egress allow-list",
                    ],
                    rule_id="mcp-live-high-agency",
                    server=server,
                )
            )
    return _dedupe_titles(out)


def _check_missing_attest(
    workspace_id: str, rel: str, server: str, cfg: dict[str, Any]
) -> list[Finding]:
    command = str(cfg.get("command") or "").strip().lower()
    runners = {str(r).lower() for r in (_mcp_cfg().get("runners") or [])}
    runner = Path(command).name.lower() if command else ""
    if runner not in runners and not any(k in cfg for k in ("url", "serverUrl")):
        return []
    # Pinned remote URL packages still benefit from integrity metadata when present.
    has_integrity = any(k in cfg for k in _INTEGRITY_KEYS) or any(
        isinstance(cfg.get(k), dict) and any(ik in (cfg.get(k) or {}) for ik in _INTEGRITY_KEYS)
        for k in ("metadata", "package", "attest")
    )
    args = cfg.get("args") or []
    args_s = " ".join(str(a) for a in args) if isinstance(args, list) else str(args)
    looks_packaged = bool(re.search(r"@[\w./-]+|mcp|server", args_s, re.I)) or runner in runners
    if not looks_packaged:
        return []
    if has_integrity:
        return []
    # Only warn when already "pinned" by version — attest is the next bar.
    if not re.search(r"@\d+\.\d+", args_s):
        return []
    return [
        _finding(
            workspace_id,
            rel,
            title=f"MCP package pinned but not attested — {server}",
            summary=(
                f"Server '{server}' pins a version but has no integrity/attest digest in config. "
                "Pinning alone does not stop a compromised registry revision (ASI04)."
            ),
            severity="medium",
            owasp=["ASI04"],
            checklist=[
                "Add an integrity/sha256 digest for the MCP package",
                "Prefer a private registry / lockfile with hashes",
                "Re-verify digests in CI before agent install",
            ],
            rule_id="mcp-missing-attest",
            server=server,
            diff=(
                f'# mcpServers.{server}\n'
                f'+ "integrity": "sha256-<digest>"\n'
            ),
        )
    ]


def _probe_tools_list(
    url: str, cfg: dict[str, Any]
) -> tuple[list[str], str | None]:
    """Best-effort JSON-RPC tools/list against an HTTP MCP endpoint."""
    timeout = float(_mcp_cfg().get("live_probe_timeout_sec") or 4)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    raw_headers = cfg.get("headers")
    if isinstance(raw_headers, dict):
        for k, v in raw_headers.items():
            if v is not None:
                headers[str(k)] = str(v)
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    ).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return [], str(exc)
    names = _parse_tools_list_payload(raw)
    if not names:
        return [], "no tools in response"
    return names, None


def _parse_tools_list_payload(raw: str) -> list[str]:
    text = raw.strip()
    # SSE: data: {...}
    if "data:" in text and not text.startswith("{"):
        chunks: list[str] = []
        for line in text.splitlines():
            if line.startswith("data:"):
                chunks.append(line[5:].strip())
        text = chunks[-1] if chunks else text
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    result = data.get("result") if isinstance(data, dict) else None
    tools = None
    if isinstance(result, dict):
        tools = result.get("tools")
    elif isinstance(result, list):
        tools = result
    if not isinstance(tools, list):
        return []
    names: list[str] = []
    for item in tools:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            n = item.get("name") or item.get("tool")
            if n:
                names.append(str(n))
            desc = item.get("description")
            if desc:
                names.append(str(desc))
    return names


def _finding(
    workspace_id: str,
    path: str,
    *,
    title: str,
    summary: str,
    severity: str,
    owasp: list[str],
    checklist: list[str],
    rule_id: str,
    server: str | None = None,
    diff: str | None = None,
) -> Finding:
    insight = insight_for(title=title, issue_text=summary, tool="mcp-probe")
    args: dict[str, Any] = {"rule_id": rule_id}
    if server:
        args["mcp_server"] = server
    return Finding(
        workspace_id=workspace_id,
        source="analyze",
        severity=severity,  # type: ignore[arg-type]
        title=title,
        summary=summary,
        category="agency",
        owasp=owasp,
        evidence=FindingEvidence(
            tool="mcp-probe",
            path=path,
            snippet=summary[:240],
            args=args,
        ),
        suggested_fix=SuggestedFix(
            kind="code",
            summary=summary,
            checklist=checklist,
            diff=diff,
        ),
        exploit=insight.exploit or None,
        technical_details=insight.technical_details or None,
        solutions=list(insight.solutions or []) or checklist,
    )


def _dedupe_titles(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for item in findings:
        key = f"{item.title}|{item.evidence.path if item.evidence else ''}"
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
