"""Scan MCP configs and IDE skill files for supply-chain / poisoning risks.

MCP path: prefer structured JSON walk of ``mcpServers`` (pin / auth / wildcards),
with a light text fallback for non-JSON configs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from isovane_serve.insights import insight_for
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix

_SKIP = {".git", "node_modules", ".venv", "dist", "build", "__pycache__", ".tox"}
_RUNNERS = {
    "npx",
    "npm",
    "pnpm",
    "pnpx",
    "bunx",
    "uvx",
    "yarn",
    "deno",
}
_AUTH_HEADER_KEYS = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "api-key",
    "proxy-authorization",
}
_AUTH_FIELD_KEYS = {
    "authorization",
    "auth",
    "token",
    "apikey",
    "api_key",
    "oauth",
    "bearer",
    "headers",
    "env",
}
_PIPE_SHELL = re.compile(r"curl\s+[^\n|]*\|\s*(?:ba)?sh", re.I)


def scan_mcp_and_skills(workspace_id: str, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not root.exists():
        return findings

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP for part in path.parts):
            continue
        name = path.name.lower()
        rel = str(path.relative_to(root)).replace("\\", "/")
        suffix = path.suffix.lower()

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        is_mcp = (
            "mcpservers" in text.lower()
            or name in {"mcp.json", "claude_desktop_config.json"}
            or (suffix in {".json", ".yml", ".yaml"} and "mcp" in name)
        )
        is_skill = (
            ".cursor/skills" in rel.lower()
            or (
                "skills/" in rel.lower()
                and name in {"skill.md", "skill.json"}
            )
            or name.endswith(".skill.md")
        )

        if is_mcp:
            findings.extend(_scan_mcp_file(workspace_id, rel, text))
        if is_skill:
            findings.extend(_scan_skill_file(workspace_id, rel, text))

    return _dedupe(findings)


def _scan_mcp_file(workspace_id: str, rel: str, text: str) -> list[Finding]:
    parsed = _try_parse_json(text)
    if isinstance(parsed, dict):
        servers = _extract_mcp_servers(parsed)
        if servers is not None:
            return _walk_mcp_servers(workspace_id, rel, servers)
    return _scan_mcp_text_fallback(workspace_id, rel, text)


def _try_parse_json(text: str) -> Any | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _extract_mcp_servers(doc: dict[str, Any]) -> dict[str, Any] | None:
    for key, value in doc.items():
        if key.lower() == "mcpservers" and isinstance(value, dict):
            return value
    # Some tools nest under mcp / mcp.servers
    mcp = doc.get("mcp")
    if isinstance(mcp, dict):
        servers = mcp.get("servers") or mcp.get("mcpServers")
        if isinstance(servers, dict):
            return servers
    return None


def _walk_mcp_servers(
    workspace_id: str, rel: str, servers: dict[str, Any]
) -> list[Finding]:
    out: list[Finding] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        server = str(name)
        out.extend(_check_pin(workspace_id, rel, server, cfg))
        out.extend(_check_remote_auth(workspace_id, rel, server, cfg))
        out.extend(_check_wildcard_tools(workspace_id, rel, server, cfg))
        out.extend(_check_dangerous_command(workspace_id, rel, server, cfg))
    return out


def _check_pin(
    workspace_id: str, rel: str, server: str, cfg: dict[str, Any]
) -> list[Finding]:
    command = str(cfg.get("command") or "").strip()
    args = cfg.get("args") or []
    if not isinstance(args, list):
        args = [args]
    args_s = [str(a) for a in args]
    runner = Path(command).name.lower() if command else ""
    # npx/uvx style, or bare package in command
    if runner in _RUNNERS or runner.endswith("npx") or runner.endswith("uvx"):
        if _runner_args_unpinned(runner, args_s):
            return [
                _finding(
                    workspace_id,
                    rel,
                    title="Unpinned MCP server runner",
                    summary=(
                        f"MCP server `{server}` uses `{runner}` without a pinned "
                        "package version — supply-chain risk."
                    ),
                    severity="high",
                    owasp=["LLM03", "ASI04"],
                    checklist=[
                        "Pin package version or commit hash",
                        "Prefer local path installs for trusted servers",
                        "Re-scan after lockfile change",
                    ],
                    diff=(
                        '- "args": ["-y", "@modelcontextprotocol/server-filesystem"]\n'
                        '+ "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2"]\n'
                    ),
                    rule_id="mcp-unpinned",
                    server=server,
                )
            ]
    return []


def _runner_args_unpinned(runner: str, args: list[str]) -> bool:
    packages = _package_specs(args)
    if not packages:
        # uvx/npx with no package-looking arg is odd; treat as unpinned if runner known
        return runner in {"npx", "uvx", "bunx", "pnpx"}
    return any(_spec_unpinned(spec) for spec in packages)


def _package_specs(args: list[str]) -> list[str]:
    specs: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in {"-y", "--yes", "--package", "-p"}:
            if arg in {"--package", "-p"}:
                skip_next = True
            continue
        if arg.startswith("-"):
            # -y@pkg rare; skip flags
            continue
        if arg in {"exec", "dlx", "create"}:
            continue
        specs.append(arg)
    return specs


def _spec_unpinned(spec: str) -> bool:
    s = spec.strip()
    if not s or s.startswith(".") or s.startswith("/") or s.startswith("file:"):
        return False
    lower = s.lower()
    if lower.endswith("@latest") or "/latest" in lower or lower.endswith(":latest"):
        return True
    if s.startswith("@"):
        # @scope/name → one @; @scope/name@1.2.3 → two @
        return s.count("@") < 2
    # unscoped: name@1.2.3 pinned; bare name unpinned
    if "@" not in s:
        return True
    _, _, ver = s.partition("@")
    return ver.lower() in {"", "latest", "*"}


def _check_remote_auth(
    workspace_id: str, rel: str, server: str, cfg: dict[str, Any]
) -> list[Finding]:
    url = str(cfg.get("url") or cfg.get("serverUrl") or cfg.get("server_url") or "")
    if not url:
        # sse / http transport fields
        for key in ("sse", "http", "streamableHttp", "streamable_http"):
            nested = cfg.get(key)
            if isinstance(nested, dict):
                url = str(nested.get("url") or "")
                if url:
                    cfg = {**cfg, **nested}
                    break
            elif isinstance(nested, str) and nested.startswith("http"):
                url = nested
                break
    if not url.startswith("http://") and not url.startswith("https://"):
        return []
    if _is_loopback(url):
        return []
    if _cfg_has_auth(cfg):
        return []
    return [
        _finding(
            workspace_id,
            rel,
            title="Remote MCP endpoint without auth hint",
            summary=(
                f"MCP server `{server}` points at `{url}` without headers/token/OAuth "
                "fields — unauthenticated remote MCP."
            ),
            severity="medium",
            owasp=["ASI04", "ASI07"],
            checklist=[
                "Require auth headers / OAuth for remote MCP",
                "Allow-list MCP hosts in policy",
            ],
            rule_id="mcp-remote-auth",
            server=server,
        )
    ]


def _is_loopback(url: str) -> bool:
    lower = url.lower()
    return any(
        h in lower
        for h in (
            "localhost",
            "127.0.0.1",
            "[::1]",
            "0.0.0.0",
        )
    )


def _cfg_has_auth(cfg: dict[str, Any]) -> bool:
    for key, value in cfg.items():
        lk = key.lower().replace("-", "_")
        if lk in _AUTH_FIELD_KEYS or lk in {"api_key", "access_token", "auth_token"}:
            if _value_suggests_auth(value):
                return True
        if lk == "headers" and isinstance(value, dict):
            for hk, hv in value.items():
                if hk.lower() in _AUTH_HEADER_KEYS and hv not in (None, "", {}):
                    return True
                if "token" in hk.lower() or "auth" in hk.lower():
                    return True
        if lk == "env" and isinstance(value, dict):
            for ek, ev in value.items():
                ekl = ek.lower()
                if any(t in ekl for t in ("token", "auth", "api_key", "apikey", "secret")):
                    if ev not in (None, ""):
                        return True
    return False


def _value_suggests_auth(value: Any) -> bool:
    if value in (None, "", {}, []):
        return False
    if isinstance(value, dict):
        return _cfg_has_auth(value) or any(
            k.lower() in _AUTH_HEADER_KEYS or "token" in k.lower() or "auth" in k.lower()
            for k in value
        )
    return True


def _check_wildcard_tools(
    workspace_id: str, rel: str, server: str, cfg: dict[str, Any]
) -> list[Finding]:
    for key in ("tools", "allowedTools", "allowed_tools", "permissions", "toolPermissions"):
        if key not in cfg:
            continue
        if _is_wildcard_tools(cfg[key]):
            return [
                _finding(
                    workspace_id,
                    rel,
                    title="Wildcard MCP / tool permissions",
                    summary=(
                        f"MCP server `{server}` grants wildcard tool permissions (`*`) — "
                        "excessive agency."
                    ),
                    severity="high",
                    owasp=["LLM06", "ASI02"],
                    checklist=["Replace * with an explicit allow-list"],
                    rule_id="mcp-wildcard-tools",
                    server=server,
                )
            ]
    # nested alwaysAllow / permissions.tools
    perms = cfg.get("permissions")
    if isinstance(perms, dict) and _is_wildcard_tools(perms.get("tools") or perms.get("allow")):
        return [
            _finding(
                workspace_id,
                rel,
                title="Wildcard MCP / tool permissions",
                summary=(
                    f"MCP server `{server}` grants wildcard tool permissions (`*`) — "
                    "excessive agency."
                ),
                severity="high",
                owasp=["LLM06", "ASI02"],
                checklist=["Replace * with an explicit allow-list"],
                rule_id="mcp-wildcard-tools",
                server=server,
            )
        ]
    return []


def _is_wildcard_tools(value: Any) -> bool:
    if value == "*" or value == ["*"]:
        return True
    if isinstance(value, str) and value.strip() == "*":
        return True
    if isinstance(value, list) and any(str(x).strip() == "*" for x in value):
        return True
    return False


def _check_dangerous_command(
    workspace_id: str, rel: str, server: str, cfg: dict[str, Any]
) -> list[Finding]:
    command = str(cfg.get("command") or "")
    args = cfg.get("args") or []
    blob = command + " " + " ".join(str(a) for a in args if a is not None)
    if _PIPE_SHELL.search(blob) or ("curl " in blob.lower() and "| sh" in blob.lower()):
        return [
            _finding(
                workspace_id,
                rel,
                title="MCP server command pipes to shell",
                summary=(
                    f"MCP server `{server}` command looks like curl|sh — treat as toxic."
                ),
                severity="critical",
                owasp=["ASI05", "ASI04"],
                checklist=["Remove the server entry; never pipe remote scripts to a shell"],
                rule_id="mcp-pipe-shell",
                server=server,
            )
        ]
    return []


def _scan_mcp_text_fallback(workspace_id: str, rel: str, text: str) -> list[Finding]:
    """Non-JSON MCP-ish files: conservative regex heuristics."""
    out: list[Finding] = []
    lower = text.lower()
    if re.search(
        r"\b(npx|uvx|bunx)\b.*(@latest|/latest)|[\"'](?:npx|uvx)[\"']",
        text,
        re.I,
    ) or ("@latest" in lower and ("npx" in lower or "uvx" in lower or "mcpserver" in lower)):
        out.append(
            _finding(
                workspace_id,
                rel,
                title="Unpinned MCP server runner",
                summary="MCP config uses npx/uvx/@latest without a pinned version — supply-chain risk.",
                severity="high",
                owasp=["LLM03", "ASI04"],
                checklist=[
                    "Pin package version or commit hash",
                    "Prefer local path installs for trusted servers",
                ],
                rule_id="mcp-unpinned",
            )
        )
    for match in re.finditer(r"https?://[^\s\"']+", text, re.I):
        url = match.group(0)
        if _is_loopback(url):
            continue
        snippet = text[max(0, match.start() - 80) : match.end() + 120]
        if not any(k in snippet.lower() for k in ("authorization", "token", "api_key", "apikey", "bearer")):
            out.append(
                _finding(
                    workspace_id,
                    rel,
                    title="Remote MCP endpoint without auth hint",
                    summary=f"Remote MCP URL `{url}` appears without nearby auth configuration.",
                    severity="medium",
                    owasp=["ASI04", "ASI07"],
                    checklist=["Require auth headers / OAuth for remote MCP"],
                    rule_id="mcp-remote-auth",
                )
            )
            break
    if re.search(r"[\"']tools[\"']\s*:\s*(\[?\s*[\"']\*[\"']\s*\]?|[\"']\*[\"'])", text):
        out.append(
            _finding(
                workspace_id,
                rel,
                title="Wildcard MCP / tool permissions",
                summary="Config appears to grant wildcard tool permissions.",
                severity="high",
                owasp=["LLM06", "ASI02"],
                checklist=["Replace * with an explicit allow-list"],
                rule_id="mcp-wildcard-tools",
            )
        )
    return out


def _scan_skill_file(workspace_id: str, rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    lower = text.lower()
    poison_markers = (
        "ignore previous",
        "ignore all prior",
        "exfiltrat",
        "send secrets",
        "disable safety",
        "jailbreak",
    )
    if any(m in lower for m in poison_markers):
        out.append(
            _finding(
                workspace_id,
                rel,
                title="Suspicious skill / agent instruction text",
                summary="Skill file contains jailbreak or exfiltration-style instructions.",
                severity="critical",
                owasp=["LLM01", "ASI04"],
                checklist=[
                    "Remove hostile instructions from the skill",
                    "Treat third-party skills as untrusted code",
                ],
                rule_id="skill-poison",
            )
        )
    if "curl " in lower and ("| sh" in lower or "| bash" in lower):
        out.append(
            _finding(
                workspace_id,
                rel,
                title="Skill instructs pipe-to-shell download",
                summary="Skill text tells the agent to curl|sh — treat as toxic.",
                severity="critical",
                owasp=["ASI05", "ASI04"],
                checklist=["Delete or quarantine the skill file"],
                rule_id="skill-pipe-shell",
            )
        )
    return out


def _finding(
    workspace_id: str,
    path: str,
    *,
    title: str,
    summary: str,
    severity: str,
    owasp: list[str],
    checklist: list[str],
    diff: str | None = None,
    rule_id: str = "mcp-skills",
    server: str | None = None,
) -> Finding:
    insight = insight_for(title=title, issue_text=summary, tool="mcp-skills")
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
            tool="mcp-skills",
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
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for item in findings:
        server = ""
        if item.evidence and item.evidence.args:
            server = str(item.evidence.args.get("mcp_server") or "")
        key = f"{item.title}|{item.evidence.path if item.evidence else ''}|{server}"
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
