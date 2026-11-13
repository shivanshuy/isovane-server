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
from isovane_serve.remediations import apply_remediation_fields
from isovane_serve.semgrep_map import classify_semgrep_hit
from isovane_serve.yaml_config import load_scan_settings

_SHELL_TRUE = re.compile(r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True")
_EVAL = re.compile(r"\beval\s*\(")
_EXEC = re.compile(r"\bexec\s*\(")
_BROAD_PERMS = re.compile(r'["\']permissions["\']\s*:\s*["\']\*["\']')

_RULES_DIR = AGENT_RULES_DIR

# Semgrep on Windows has been observed returning garbage in extra.lines
# (literally "requires login" for every hit). Always prefer reading the file.
_BOGUS_SNIPPET = re.compile(r"(?i)^requires\s+login\.?$")


def _read_source_window(
    root: Path,
    rel_or_abs: str | None,
    line: int | None,
    end_line: int | None = None,
    *,
    radius: int = 5,
    fallback: str = "",
) -> str:
    """Multi-line code window for Technical details — never a single orphan line."""
    fb = (fallback or "").strip()
    if _BOGUS_SNIPPET.match(fb):
        fb = ""

    path: Path | None = None
    if rel_or_abs:
        raw = Path(rel_or_abs)
        if raw.is_file():
            path = raw
        else:
            for candidate in (
                root / rel_or_abs,
                root / Path(str(rel_or_abs).replace("\\", "/")),
            ):
                if candidate.is_file():
                    path = candidate
                    break

    if path is None:
        return fb[:1200]

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return fb[:1200]

    if not lines:
        return fb[:1200]
    if not line or line < 1:
        return "\n".join(lines[:16])[:1200]

    lo = max(0, line - 1 - radius)
    hi = min(len(lines), max(line, end_line or line) + radius)
    window = "\n".join(lines[lo:hi]).strip("\n")
    if window.strip():
        return window[:1200]
    return fb[:1200]


def _text_exts() -> set[str]:
    return load_scan_settings()["text_exts"] or {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".md",
        ".txt",
        ".yaml",
        ".yml",
        ".json",
        ".env",
        ".toml",
    }


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

            # Structure-first capabilities for Python — gates promptlint HITL/RAG.
            caps_by_path: dict = {}
            try:
                from isovane_serve.code_capabilities import probe_tree

                caps_by_path = probe_tree(root)
            except Exception:  # noqa: BLE001
                caps_by_path = {}

            # Always lint embedded prompts (Python system strings, *prompt* files).
            # Semgrep path filters often miss prompts inside .py agent modules.
            batch.extend(lint_paths(workspace_id, root, caps_by_path=caps_by_path or None))
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

            # Drop promptlint HITL/RAG that still lack structural confirmation.
            batch = _filter_promptlint_by_structure(batch, caps_by_path)

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
        end = (item.get("end") or {}).get("line")
        raw_lines = str(item.get("extra", {}).get("lines") or "")
        abs_path = str(item.get("path") or "")
        snippet = _read_source_window(
            root,
            abs_path or path,
            int(start) if start else None,
            int(end) if end else None,
            radius=5,
            fallback=raw_lines,
        )
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
        suggested = apply_remediation_fields(
            title=title,
            owasp=owasp,
            category=category,
            path=path,
            existing=SuggestedFix(
                kind=fix_kind,  # type: ignore[arg-type]
                summary=fix_summary,
                checklist=insight.merge_checklist(),
            ),
        )
        fields = insight.as_finding_fields(owasp or None)
        if suggested.checklist:
            fields["solutions"] = list(suggested.checklist)
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
                suggested_fix=suggested,
                **fields,
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
        filename = str(item.get("filename") or "")
        line_no = item.get("line_number")
        raw_code = str(item.get("code") or "")
        snippet = _read_source_window(
            root,
            filename,
            int(line_no) if line_no else None,
            radius=5,
            fallback=raw_code,
        )
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
        try:
            rel_path = str(Path(filename).resolve().relative_to(root.resolve()))
        except Exception:
            rel_path = Path(filename).name or filename
        insight = insight_for(
            title=title,
            issue_text=issue_text,
            tool="bandit",
            snippet=snippet,
            test_id=str(item.get("test_id") or ""),
        )
        suggested = apply_remediation_fields(
            title=title,
            owasp=list(insight.owasp or []),
            category="static",
            path=rel_path,
            existing=SuggestedFix(
                kind="code",
                summary=bandit_fix_summary(issue_text),
                checklist=insight.merge_checklist(),
            ),
        )
        fields = insight.as_finding_fields()
        if suggested.checklist:
            fields["solutions"] = list(suggested.checklist)
        findings.append(
            Finding(
                workspace_id=workspace_id,
                source="analyze",
                severity=severity,  # type: ignore[arg-type]
                title=title,
                category="static",
                evidence=FindingEvidence(
                    path=rel_path,
                    line=line_no,
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
                suggested_fix=suggested,
                **fields,
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
                rel = str(path.relative_to(root))
                snippet = _read_source_window(
                    root, rel, i, radius=4, fallback=line.strip()[:200]
                )
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
                            path=rel,
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


def _norm_path(path: str | None) -> str:
    return (path or "").replace("\\", "/").lstrip("./")


def _path_in_set(path: str, confirmed: set[str]) -> bool:
    p = _norm_path(path)
    if p in confirmed:
        return True
    base = p.split("/")[-1]
    return any(_norm_path(c).endswith("/" + base) or _norm_path(c) == base for c in confirmed)


_BRIEFING_FP = re.compile(
    r"(?is)\bwrite\b.{0,40}\b(briefing|summary|bullet|title line)\b|"
    r"\bsummarize\b.{0,40}\b(content|document|ingest)"
)
_STRONG_AGENCY_EVIDENCE = re.compile(
    r"(?is)(@tool\b|bind_tools|create_react_agent|ToolNode|tools\s*=\s*\[|"
    r"send_email|pay_refund|run_shell|shell\s*=\s*True|os\.system|subprocess\.|"
    r"(?:send|draft|compose|write)\s+(?:an?\s+)?emails?|"
    r"(?:issue|process|approve|execute|pay)\s+(?:a\s+|the\s+)?refunds?|"
    r"run\s+(?:shell|bash|commands?)|"
    r"(?:transfer|wire)\s+(?:money|funds|payments?)|"
    r"you (?:can|may|should|must|will).{0,80}(?:send|email|pay|refund|shell|exec|transfer|delete|money|funds))"
)
_STRONG_RAG_EVIDENCE = re.compile(
    r"(?is)(similarity_search|as_retriever|get_relevant_documents|vector\s*store|"
    r"chroma|pinecone|faiss|retrieved\s+(?:document|doc|chunk)|knowledge\s*base|"
    r"\brag\b|\bretriever\b)"
)


def _filter_promptlint_by_structure(
    batch: list[Finding],
    caps_by_path: dict[str, Any] | None,
) -> list[Finding]:
    """Recall-first filter: drop only clear briefing FPs, never strip strong evidence."""
    agency: set[str] = set()
    rag: set[str] = set()
    for rel, caps in (caps_by_path or {}).items():
        p = _norm_path(rel)
        if getattr(caps, "has_tool_agency", False):
            agency.add(p)
        if getattr(caps, "has_retriever", False):
            rag.add(p)
    for item in batch:
        tool = (item.evidence.tool or "") if item.evidence else ""
        path = _norm_path(item.evidence.path if item.evidence else None)
        blob = f"{item.title} {item.summary}".lower()
        if tool in {"ast-taint", "semgrep", "mcp-skills"}:
            if any(
                k in blob
                for k in ("tool", "agency", "shell", "bind_tools", "refund", "email", "hitl")
            ):
                agency.add(path)
            if any(k in blob for k in ("retriev", "rag", "vector", "chroma", "pinecone", "faiss")):
                rag.add(path)

    out: list[Finding] = []
    for item in batch:
        tool = (item.evidence.tool or "") if item.evidence else ""
        # promptlint + local Semgrep prompt rules share HITL/RAG titles — same FP gates.
        if tool not in {"promptlint", "semgrep"}:
            out.append(item)
            continue
        path = _norm_path(item.evidence.path if item.evidence else None)
        title = item.title or ""
        snip = (item.evidence.snippet if item.evidence else None) or ""
        evidence_blob = f"{snip} {item.summary or ''}"

        # Drop only obvious summarizer FPs with no structural agency.
        if "HITL" in title and _BRIEFING_FP.search(evidence_blob):
            if not _path_in_set(path, agency) and not _STRONG_AGENCY_EVIDENCE.search(evidence_blob):
                continue
        # Drop weak Semgrep HITL when the window has no strong agency signal and AST agrees.
        if "HITL" in title and tool == "semgrep" and path.endswith(".py"):
            if not _path_in_set(path, agency) and not _STRONG_AGENCY_EVIDENCE.search(evidence_blob):
                caps = None
                if caps_by_path:
                    caps = (
                        caps_by_path.get(path)
                        or caps_by_path.get(path.replace("/", "\\"))
                        or caps_by_path.get(path.replace("\\", "/"))
                    )
                if caps is not None and not getattr(caps, "has_tool_agency", False):
                    continue
        # Drop RAG only when evidence is clearly non-retrieval (should be rare).
        if "RAG concat" in title and not (
            _path_in_set(path, rag) or _STRONG_RAG_EVIDENCE.search(evidence_blob)
        ):
            # Keep when in doubt (empty snippet / weak path) — recall over precision.
            if snip and not _STRONG_RAG_EVIDENCE.search(snip) and path.endswith(".py"):
                caps = None
                if caps_by_path:
                    caps = caps_by_path.get(path) or caps_by_path.get(path.replace("/", "\\"))
                if caps is not None and not getattr(caps, "has_retriever", False):
                    continue
        out.append(item)
    return out


_COLLAPSE_PER_PATH = {
    "Tools mentioned without HITL",
    "RAG concat without trust boundary",
    "Web search tool attached to agent",
    "Missing PII / disclosure bounds",
    "System prompt built in Python",
}


def _snippet_score(item: Finding) -> int:
    snip = (item.evidence.snippet if item.evidence else None) or ""
    score = len(snip)
    if _STRONG_AGENCY_EVIDENCE.search(snip):
        score += 500
    if _STRONG_RAG_EVIDENCE.search(snip):
        score += 500
    if "\n" in snip:
        score += 50
    return score


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

    # Collapse noisy Semgrep/promptlint repeats: one HITL / RAG story per file,
    # keeping the richest code window so Technical details stays readable.
    best: dict[tuple[str, str], Finding] = {}
    rest: list[Finding] = []
    for item in out:
        path = _norm_path(item.evidence.path if item.evidence else None)
        if item.title in _COLLAPSE_PER_PATH and path:
            key2 = (item.title, path)
            prev = best.get(key2)
            if prev is None or _snippet_score(item) > _snippet_score(prev):
                best[key2] = item
        else:
            rest.append(item)
    return rest + list(best.values())


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
