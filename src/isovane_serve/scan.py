"""Analyze orchestrator: Semgrep CE (compose), Bandit, detect-secrets, Presidio, promptlint.

Strategy 2A: always run local rules/agent/, and compose Semgrep Registry
p/ai-best-practices when network/registry is available (ISOVANE_SEMGREP_UPSTREAM=0 to skip).
Bandit = general Python. promptlint always runs for embedded system strings.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from isovane_serve.copy import (
    bandit_fix_summary,
    detect_secrets_fix_summary,
    eval_exec_fix_summary,
    pii_fix_summary,
    secret_assignment_fix_summary,
    semgrep_fix_summary,
    shell_true_fix_summary,
    wildcard_perms_fix_summary,
)
from isovane_serve.insights import insight_for
from isovane_serve.models import Finding, FindingEvidence, SuggestedFix, utc_now
from isovane_serve.paths import AGENT_RULES_DIR
from isovane_serve.pii import detect_pii
from isovane_serve.promptlint import lint_paths, lint_text
from isovane_serve.semgrep_map import classify_semgrep_hit
from isovane_serve.yaml_config import load_scan_settings

_SHELL_TRUE = re.compile(r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True")
_EVAL = re.compile(r"\beval\s*\(")
_EXEC = re.compile(r"\bexec\s*\(")
_BROAD_PERMS = re.compile(r'["\']permissions["\']\s*:\s*["\']\*["\']')

_RULES_DIR = AGENT_RULES_DIR


def _code_exts() -> set[str]:
    return load_scan_settings()["code_exts"] or {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
    }


def _text_exts() -> set[str]:
    return load_scan_settings()["text_exts"] or (_code_exts()() | {".md", ".txt", ".yaml", ".yml", ".json", ".env", ".toml"})


def _upstream_configs() -> tuple[str, ...]:
    return tuple(load_scan_settings()["semgrep_upstream"] or ["p/ai-best-practices"])
_SEMGREP_SEVERITY = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def _upstream_enabled() -> bool:
    return os.environ.get("ISOVANE_SEMGREP_UPSTREAM", "1").lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def analyze_workspace(
    workspace_id: str,
    folder: str | None = None,
    prompts: list[str] | None = None,
    text_blobs: list[dict[str, str]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    temp_root: Path | None = None
    roots: list[Path] = []

    try:
        disk_root = Path(folder).expanduser() if folder else None
        if disk_root and disk_root.exists():
            roots.append(disk_root)

        need_temp = bool(text_blobs) or bool(prompts)
        if need_temp:
            temp_root = Path(tempfile.mkdtemp(prefix="isovane-analyze-"))
            _materialize_inputs(temp_root, text_blobs or [], prompts or [])
            roots.append(temp_root)

        if not roots:
            return findings

        for root in roots:
            batch: list[Finding] = []
            semgrep = _semgrep_scan(workspace_id, root)
            if semgrep is not None:
                batch.extend(semgrep)
            else:
                # Fallback static/regex only when Semgrep CE is missing / failed.
                batch.extend(_scan_tree_fallback(workspace_id, root))

            # Always lint embedded prompts (Python system strings, *prompt* files).
            # Semgrep path filters often miss prompts inside .py agent modules.
            batch.extend(lint_paths(workspace_id, root))
            batch.extend(_bandit_scan(workspace_id, root))
            batch.extend(_detect_secrets_scan(workspace_id, root))
            batch.extend(_pii_tree(workspace_id, root))

            try:
                from isovane_serve.mcp_skills import scan_mcp_and_skills

                batch.extend(scan_mcp_and_skills(workspace_id, root))
            except Exception:  # noqa: BLE001 — never break Analyze
                pass
            try:
                from isovane_serve.ast_taint import scan_ast_taint

                batch.extend(scan_ast_taint(workspace_id, root))
            except Exception:  # noqa: BLE001
                pass

            try:
                from isovane_serve.suppressions import apply_suppressions

                batch = apply_suppressions(batch, root=root)
            except Exception:  # noqa: BLE001
                pass

            findings.extend(batch)

        # Inline prompt strings always get Presidio even if Semgrep covered files.
        for prompt in prompts or []:
            findings.extend(_pii_in_text(workspace_id, prompt, "prompt:inline"))
    finally:
        if temp_root is not None:
            shutil.rmtree(temp_root, ignore_errors=True)

    return _dedupe(findings)


def _materialize_inputs(
    root: Path,
    text_blobs: list[dict[str, str]],
    prompts: list[str],
) -> None:
    for index, blob in enumerate(text_blobs):
        rel = (blob.get("path") or f"upload_{index}.txt").lstrip("/\\")
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(blob.get("text") or "", encoding="utf-8")
    for index, prompt in enumerate(prompts):
        path = root / f"prompt_inline_{index}.md"
        path.write_text(prompt, encoding="utf-8")


def _semgrep_bin() -> str | None:
    found = shutil.which("semgrep")
    if found:
        return found
    scripts = Path(sys.executable).resolve().parent
    for name in ("semgrep.exe", "semgrep"):
        candidate = scripts / name
        if candidate.exists():
            return str(candidate)
    return None


def _semgrep_configs() -> list[str]:
    configs: list[str] = []
    if _RULES_DIR.exists():
        configs.append(str(_RULES_DIR))
    if _upstream_enabled():
        configs.extend(_upstream_configs())
    return configs


def _semgrep_scan(workspace_id: str, root: Path) -> list[Finding] | None:
    """Run Semgrep CE: local rules/agent + optional upstream AI pack. None if Semgrep cannot run."""
    configs = _semgrep_configs()
    if not configs:
        return None
    binary = _semgrep_bin()
    if binary is None:
        return None

    # Local-only first (always). Upstream may fail offline — fall back without aborting.
    local_cfgs = [c for c in configs if not c.startswith("p/")]
    upstream_cfgs = [c for c in configs if c.startswith("p/")]
    findings: list[Finding] = []
    ran_any = False

    for label, cfgs, timeout in (
        ("local", local_cfgs, 180),
        ("upstream", upstream_cfgs, 240),
    ):
        if not cfgs:
            continue
        batch = _semgrep_run(binary, root, cfgs, timeout=timeout)
        if batch is None:
            if label == "local":
                return None
            continue
        ran_any = True
        findings.extend(_semgrep_results_to_findings(workspace_id, root, batch))

    return findings if ran_any else None


def _semgrep_run(
    binary: str,
    root: Path,
    configs: list[str],
    *,
    timeout: int,
) -> dict[str, Any] | None:
    cmd = [binary, "scan"]
    for cfg in configs:
        cmd.extend(["--config", cfg])
    cmd.extend(
        [
            "--json",
            "--quiet",
            "--disable-version-check",
            "--metrics=off",
            str(root),
        ]
    )
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    # Semgrep: 0 clean, 1 findings. Other codes (registry miss, etc.) → unavailable.
    if proc.returncode not in (0, 1):
        return None
    raw = (proc.stdout or "").strip()
    if not raw:
        return {"results": []} if proc.returncode == 0 else None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _semgrep_results_to_findings(
    workspace_id: str,
    root: Path,
    payload: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []
    for item in payload.get("results") or []:
        meta = item.get("extra", {}).get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        severity = _SEMGREP_SEVERITY.get(
            str(item.get("extra", {}).get("severity") or "WARNING").upper(),
            "medium",
        )
        check_id = str(item.get("check_id") or "")
        message = str(item.get("extra", {}).get("message") or check_id or "Semgrep finding")
        mapped = classify_semgrep_hit(check_id=check_id, message=message, meta=meta)
        title = str(mapped["title"])
        category = str(mapped["category"])
        owasp = list(mapped.get("owasp") or [])
        path = str(item.get("path") or "")
        try:
            path = str(Path(path).resolve().relative_to(root.resolve()))
        except Exception:
            path = Path(path).name or path
        start = (item.get("start") or {}).get("line")
        snippet = str(item.get("extra", {}).get("lines") or "")[:240]
        fix_kind = str(mapped.get("fix_kind") or "code")
        custom_fix = mapped.get("fix_summary")
        fix_summary = (
            str(custom_fix)
            if custom_fix
            else semgrep_fix_summary(message, title)
        )
        insight = insight_for(
            title=title,
            issue_text=message,
            tool="semgrep",
            snippet=snippet,
            test_id=check_id,
        )
        findings.append(
            Finding(
                workspace_id=workspace_id,
                source="analyze",
                severity=severity,  # type: ignore[arg-type]
                title=title,
                category=category,  # type: ignore[arg-type]
                evidence=FindingEvidence(
                    path=path,
                    line=start,
                    snippet=snippet,
                    tool="semgrep",
                    args={
                        "check_id": check_id,
                        "pack": mapped.get("pack"),
                        "message": message[:400] if message else None,
                        "severity_from_tool": item.get("extra", {}).get("severity"),
                    },
                ),
                suggested_fix=SuggestedFix(
                    kind=fix_kind,  # type: ignore[arg-type]
                    summary=fix_summary,
                    checklist=insight.merge_checklist(),
                ),
                **insight.as_finding_fields(owasp or None),
            )
        )
    return findings


def _scan_tree_fallback(workspace_id: str, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _text_exts():
            continue
        if any(part in {".git", "node_modules", ".venv", "dist", "build"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        findings.extend(_static_file_fallback(workspace_id, rel, text))
        if "prompt" in rel.lower() or rel.lower().startswith("system"):
            findings.extend(lint_text(workspace_id, text, rel))
    return findings


def _static_file_fallback(workspace_id: str, path: str, text: str) -> list[Finding]:
    """Thin regex fallback used only when Semgrep CE is not installed."""
    out: list[Finding] = []

    def add(
        title: str,
        summary: str,
        owasp: list[str],
        category: str,
        severity: str,
        line: int | None,
        snippet: str,
        fix: SuggestedFix,
    ) -> None:
        insight = insight_for(title=title, issue_text=summary, tool="regex-fallback", snippet=snippet)
        fix = SuggestedFix(
            kind=fix.kind,
            summary=fix.summary,
            diff=fix.diff,
            checklist=insight.merge_checklist(fix.checklist),
        )
        out.append(
            Finding(
                workspace_id=workspace_id,
                source="analyze",
                severity=severity,  # type: ignore[arg-type]
                title=title,
                category=category,  # type: ignore[arg-type]
                evidence=FindingEvidence(path=path, line=line, snippet=snippet[:240], tool="regex-fallback"),
                suggested_fix=fix,
                **insight.as_finding_fields(owasp),
            )
        )

    for i, line in enumerate(text.splitlines(), start=1):
        if _SHELL_TRUE.search(line):
            add(
                "shell=True in subprocess",
                "Shell execution enables unexpected code execution (ASI05).",
                ["ASI05", "LLM06"],
                "static",
                "high",
                i,
                line.strip(),
                SuggestedFix(
                    kind="code",
                    summary=shell_true_fix_summary(),
                    diff="- subprocess.run(cmd, shell=True)\n+ subprocess.run([prog, *args], shell=False)",
                ),
            )
        if _EVAL.search(line) or _EXEC.search(line):
            add(
                "Dynamic eval/exec",
                "eval/exec in agent code is excessive agency.",
                ["ASI05", "LLM06"],
                "static",
                "critical",
                i,
                line.strip(),
                SuggestedFix(
                    kind="code",
                    summary=eval_exec_fix_summary(),
                    checklist=["Delete eval/exec paths", "Route through gated tools"],
                ),
            )
        if _BROAD_PERMS.search(line):
            add(
                "Wildcard tool permissions",
                "Tool permissions use '*' — privilege abuse risk.",
                ["ASI03"],
                "static",
                "high",
                i,
                line.strip(),
                SuggestedFix(
                    kind="schema",
                    summary=wildcard_perms_fix_summary(),
                    diff='- "permissions": "*"\n+ "permissions": ["read", "list"]',
                ),
            )
    return out


def _pii_tree(workspace_id: str, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _text_exts():
            continue
        if any(part in {".git", "node_modules", ".venv", "dist", "build"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(_pii_in_text(workspace_id, text, str(path.relative_to(root))))
    return findings


def _pii_in_text(workspace_id: str, text: str, path: str) -> list[Finding]:
    hits = detect_pii(text)
    if not hits:
        return []
    classes = sorted({h.pii_class for h in hits})
    sample = hits[0]
    line = text[: sample.start].count("\n") + 1
    snippet = text[max(0, sample.start - 20) : sample.end + 20][:200]
    insight = insight_for(
        title=f"PII / secret material: {', '.join(classes)}",
        issue_text=f"Detected {', '.join(classes)} in {path}.",
        tool="presidio",
        snippet=snippet,
    )
    return [
        Finding(
            workspace_id=workspace_id,
            source="analyze",
            severity="high",
            title=f"PII / secret material: {', '.join(classes)}",
            category="pii",
            evidence=FindingEvidence(
                path=path,
                line=line,
                snippet=snippet,
                tool="presidio",
            ),
            pii_classes=classes,
            suggested_fix=SuggestedFix(
                kind="code",
                summary=pii_fix_summary(),
                diff=f"- {sample.text}\n+ <{sample.pii_class.upper()}>",
                checklist=insight.merge_checklist(),
            ),
            **insight.as_finding_fields(["LLM02"]),
        )
    ]


def _bandit_scan(workspace_id: str, root: Path) -> list[Finding]:
    try:
        proc = subprocess.run(
            ["bandit", "-r", str(root), "-f", "json", "-q"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if not proc.stdout.strip():
        return []
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for item in payload.get("results") or []:
        sev = str(item.get("issue_severity") or "MEDIUM").lower()
        severity = {"high": "high", "medium": "medium", "low": "low"}.get(sev, "medium")
        test_name = str(item.get("test_name") or "Bandit finding")
        issue_text = str(item.get("issue_text") or "")
        snippet = (item.get("code") or "")[:240]
        # Prefer a human title when Bandit only says "blacklist"
        title = test_name
        if test_name.lower() in {"blacklist", "blacklist_calls", "hardcoded_bind_all_interfaces"}:
            lowered = f"{issue_text} {snippet}".lower()
            if any(k in lowered for k in ("urlopen", "urllib", "request(")):
                title = "Unvalidated URL fetch (urllib)"
            elif "assert" in lowered:
                title = "Assert used as security check"
            elif issue_text:
                title = issue_text.split(".")[0][:80] or test_name
        insight = insight_for(
            title=title,
            issue_text=issue_text,
            tool="bandit",
            snippet=snippet,
            test_id=str(item.get("test_id") or ""),
        )
        findings.append(
            Finding(
                workspace_id=workspace_id,
                source="analyze",
                severity=severity,  # type: ignore[arg-type]
                title=title,
                category="static",
                evidence=FindingEvidence(
                    path=item.get("filename"),
                    line=item.get("line_number"),
                    snippet=snippet,
                    tool="bandit",
                    args={
                        "test_id": item.get("test_id"),
                        "test_name": test_name,
                        "issue_text": issue_text or None,
                        "issue_confidence": item.get("issue_confidence"),
                        "more_info": item.get("more_info"),
                    },
                ),
                suggested_fix=SuggestedFix(
                    kind="code",
                    summary=bandit_fix_summary(issue_text),
                    checklist=insight.merge_checklist(),
                ),
                **insight.as_finding_fields(),
            )
        )
    return findings


def _detect_secrets_scan(workspace_id: str, root: Path) -> list[Finding]:
    try:
        from detect_secrets.settings import default_settings  # type: ignore
        from detect_secrets.core.scan import scan_file  # type: ignore
    except Exception:
        return _heuristic_secrets(workspace_id, root)

    findings: list[Finding] = []
    try:
        with default_settings():
            for path in root.rglob("*"):
                if not path.is_file() or path.suffix.lower() not in _text_exts():
                    continue
                if any(p in {".git", "node_modules", ".venv"} for p in path.parts):
                    continue
                for secret in scan_file(str(path)):
                    title = f"Secret: {secret.type}"
                    issue_text = f"detect-secrets found {secret.type} in {path.name}."
                    insight = insight_for(
                        title=title,
                        issue_text=issue_text,
                        tool="detect-secrets",
                    )
                    findings.append(
                        Finding(
                            workspace_id=workspace_id,
                            source="analyze",
                            severity="critical",
                            title=title,
                            category="pii",
                            evidence=FindingEvidence(
                                path=str(path.relative_to(root)),
                                line=secret.line_number,
                                tool="detect-secrets",
                            ),
                            pii_classes=["api_key"],
                            suggested_fix=SuggestedFix(
                                kind="code",
                                summary=detect_secrets_fix_summary(secret.type),
                                checklist=insight.merge_checklist(
                                    ["Rotate credential", "Add to .gitignore / vault"]
                                ),
                            ),
                            **insight.as_finding_fields(["LLM02"]),
                        )
                    )
    except Exception:
        return _heuristic_secrets(workspace_id, root)
    return findings


def _heuristic_secrets(workspace_id: str, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    key_re = re.compile(
        r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"
    )
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _text_exts():
            continue
        if any(p in {".git", "node_modules", ".venv"} for p in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if key_re.search(line):
                title = "Hardcoded secret-like assignment"
                issue_text = f"Possible secret assignment in {path.name}:{i}."
                snippet = line.strip()[:200]
                insight = insight_for(
                    title=title,
                    issue_text=issue_text,
                    tool="regex-fallback",
                    snippet=snippet,
                )
                findings.append(
                    Finding(
                        workspace_id=workspace_id,
                        source="analyze",
                        severity="critical",
                        title=title,
                        category="pii",
                        evidence=FindingEvidence(
                            path=str(path.relative_to(root)),
                            line=i,
                            snippet=snippet,
                            tool="regex-fallback",
                        ),
                        pii_classes=["api_key"],
                        suggested_fix=SuggestedFix(
                            kind="code",
                            summary=secret_assignment_fix_summary(),
                            diff="- api_key = '....'\n+ api_key = os.environ['API_KEY']",
                            checklist=insight.merge_checklist(),
                        ),
                        **insight.as_finding_fields(["LLM02"]),
                    )
                )
    return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[Any, ...]] = set()
    out: list[Finding] = []
    for item in findings:
        check_id = None
        if item.evidence.args and isinstance(item.evidence.args, dict):
            check_id = item.evidence.args.get("check_id")
        key = (
            check_id or item.title,
            item.evidence.path or "",
            item.evidence.line,
            item.title,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    results = []
    for f in findings:
        level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}[
            f.severity
        ]
        loc: dict[str, Any] = {}
        if f.evidence.path:
            loc = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.evidence.path},
                    "region": {"startLine": f.evidence.line or 1},
                }
            }
        results.append(
            {
                "ruleId": f.owasp[0] if f.owasp else f.category,
                "level": level,
                "message": {"text": f"{f.title}: {f.summary}"},
                "locations": [loc] if loc else [],
                "properties": {
                    "findingId": f.id,
                    "owasp": f.owasp,
                    "status": f.status,
                    "tool": f.evidence.tool,
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "isovane", "informationUri": "https://isovane.local"}},
                "results": results,
                "invocations": [{"executionSuccessful": True, "endTimeUtc": utc_now()}],
            }
        ],
    }
