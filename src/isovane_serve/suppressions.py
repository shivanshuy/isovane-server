"""`.isovaneignore` + optional baseline suppressions for Analyze noise control."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from isovane_serve.models import Finding

_IGNORE_NAMES = (".isovaneignore",)
_BASELINE_NAMES = (".isovane-baseline.json", "isovane-baseline.json")


def load_ignore_globs(root: Path) -> list[str]:
    patterns: list[str] = []
    for name in _IGNORE_NAMES:
        path = root / name
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            patterns.append(raw)
    return patterns


def load_baseline_keys(root: Path) -> set[str]:
    keys: set[str] = set()
    for name in _BASELINE_NAMES:
        path = root / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        items = data if isinstance(data, list) else data.get("findings") or data.get("keys") or []
        for item in items:
            if isinstance(item, str):
                keys.add(item)
            elif isinstance(item, dict):
                key = item.get("key") or _key_from_parts(
                    item.get("title"), item.get("path"), item.get("rule_id")
                )
                if key:
                    keys.add(key)
    return keys


def finding_suppression_key(finding: Finding) -> str:
    path = ""
    if finding.evidence and finding.evidence.path:
        path = str(finding.evidence.path)
    rule = ""
    if finding.evidence and isinstance(finding.evidence.args, dict):
        rule = str(
            finding.evidence.args.get("check_id")
            or finding.evidence.args.get("rule_id")
            or ""
        )
    return _key_from_parts(finding.title, path, rule)


def apply_suppressions(
    findings: Iterable[Finding],
    *,
    root: Path | None = None,
    ignore_globs: list[str] | None = None,
    baseline_keys: set[str] | None = None,
) -> list[Finding]:
    globs = list(ignore_globs or [])
    base = set(baseline_keys or set())
    if root is not None:
        globs.extend(load_ignore_globs(root))
        base |= load_baseline_keys(root)

    out: list[Finding] = []
    for finding in findings:
        path = (finding.evidence.path if finding.evidence else None) or ""
        if path and _path_ignored(str(path), globs):
            continue
        if finding_suppression_key(finding) in base:
            continue
        out.append(finding)
    return out


def _key_from_parts(title: Any, path: Any, rule_id: Any) -> str:
    return "|".join(
        [
            str(title or "").strip().lower(),
            str(path or "").strip().replace("\\", "/").lower(),
            str(rule_id or "").strip().lower(),
        ]
    )


def _path_ignored(path: str, globs: list[str]) -> bool:
    norm = path.replace("\\", "/")
    name = Path(norm).name
    for pattern in globs:
        pat = pattern.replace("\\", "/")
        if pat.startswith("**/"):
            suffix = pat[3:]
            if norm.endswith(suffix) or name == suffix or f"/{suffix}" in f"/{norm}":
                return True
        elif pat.endswith("/**"):
            prefix = pat[:-3].rstrip("/")
            if norm == prefix or norm.startswith(prefix + "/"):
                return True
        elif "*" in pat:
            if pat.startswith("*") and norm.endswith(pat[1:]):
                return True
            if pat.endswith("*") and norm.startswith(pat[:-1]):
                return True
        elif pat in norm or name == pat:
            return True
    return False
