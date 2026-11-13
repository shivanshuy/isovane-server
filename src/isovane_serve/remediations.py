"""Load industry-standard remediations from YAML catalogs.

- config/remediations.yaml — code / prompt recipes (+ shared `sources`)
- config/remediations-architecture.yaml — architecture / diagram recipes

Sources are tracked in YAML for maintainers. Never expose `source` fields to the UI.

Matching rule: pick suggestions that are *relevant to this finding's title*.
OWASP tags alone must never pull in an unrelated recipe (e.g. ASI05 must not
attach shell=True remediations to a 0.0.0.0 bind finding).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from isovane_serve.models import Finding, SuggestedFix
from isovane_serve.paths import REMEDIATIONS_ARCHITECTURE_YAML, REMEDIATIONS_YAML
from isovane_serve.yaml_config import load_yaml

# Title hit required before OWASP/category may act as a tie-breaker.
_TITLE_EXACT = 100
_TITLE_CONTAINS = 60
_OWASP_BONUS = 15
_CATEGORY_BONUS = 8
_DEFAULT_SCORE = 1


def _items_from(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not path.is_file():
        return {}, []
    data = load_yaml(str(path)) or {}
    items = [r for r in (data.get("remediations") or []) if isinstance(r, dict)]
    sources = data.get("sources") or {}
    return (sources if isinstance(sources, dict) else {}), items


@lru_cache(maxsize=4)
def load_remediations(path: str | None = None) -> dict[str, Any]:
    """Merge code + architecture catalogs. Optional `path` overrides the code catalog only."""
    code_path = Path(path) if path else REMEDIATIONS_YAML
    sources, items = _items_from(code_path)
    # Always merge architecture file when present (unless a one-off path override
    # is the architecture file itself).
    arch_path = REMEDIATIONS_ARCHITECTURE_YAML
    if code_path.resolve() != arch_path.resolve():
        arch_sources, arch_items = _items_from(arch_path)
        sources = {**sources, **arch_sources}
        items = [*items, *arch_items]
    return {
        "sources": sources,
        "remediations": items,
    }


def _title_hit(title_l: str, match: dict[str, Any]) -> int:
    """Return title-match score, or 0 if this recipe is not about this title."""
    if not title_l:
        return 0
    titles = [str(t).lower() for t in (match.get("titles") or [])]
    if title_l in titles:
        return _TITLE_EXACT
    # Prefer longer / more specific contains needles first.
    contains = sorted(
        (str(t).lower() for t in (match.get("title_contains") or []) if t),
        key=len,
        reverse=True,
    )
    for needle in contains:
        if needle in title_l:
            return _TITLE_CONTAINS
    return 0


def resolve_remediation(
    *,
    title: str = "",
    owasp: list[str] | None = None,
    category: str = "",
) -> dict[str, Any] | None:
    """Best matching remediation — title-relevant only.

    OWASP / category only break ties among recipes that already matched the title.
    """
    catalog = load_remediations()["remediations"]
    title_l = (title or "").strip().lower()
    owasp_set = {str(x).upper() for x in (owasp or []) if x}
    category_l = (category or "").strip().lower()

    best: dict[str, Any] | None = None
    best_score = -1
    default_item: dict[str, Any] | None = None

    for item in catalog:
        if item.get("id") == "default-analyze":
            default_item = item
            continue

        match = item.get("match") or {}
        title_score = _title_hit(title_l, match)
        if title_score <= 0:
            # No title relevance → never select this recipe for this finding.
            continue

        score = title_score
        ow = {str(x).upper() for x in (match.get("owasp") or []) if x}
        cats = {str(x).lower() for x in (match.get("categories") or []) if x}
        if owasp_set and ow and owasp_set & ow:
            score += _OWASP_BONUS
        if category_l and category_l in cats:
            score += _CATEGORY_BONUS
        # Prefer architecture recipes when resolving architecture findings
        # (avoids code mcp-supply winning on a diagram title that merely says "MCP").
        if category_l == "architecture" and str(item.get("kind") or "") == "architecture":
            score += _CATEGORY_BONUS

        if score > best_score:
            best_score = score
            best = item

    if best is not None:
        return best
    return default_item


def checklist_for(recipe: dict[str, Any]) -> list[str]:
    """Developer-facing suggestion texts only — strip source tags."""
    out: list[str] = []
    for row in recipe.get("suggestions") or []:
        if isinstance(row, dict):
            text = str(row.get("text") or "").strip()
        else:
            text = str(row).strip()
        if text and text not in out:
            out.append(text)
    return out


def suggested_fix_from_recipe(
    recipe: dict[str, Any],
    *,
    path: str | None = None,
    existing: SuggestedFix | None = None,
    merge_existing_checklist: bool = False,
) -> SuggestedFix:
    kind = str(recipe.get("kind") or (existing.kind if existing else "code"))
    summary = str(recipe.get("summary") or "").strip()
    if existing and existing.summary and not summary:
        summary = existing.summary
    diff = str(recipe.get("diff") or "").strip() or None
    if path and diff and not diff.lstrip().startswith("#"):
        diff = f"# {path}\n{diff}"
    elif path and diff and "# " not in diff.splitlines()[0][:40]:
        diff = f"# {path}\n{diff}"
    checklist = checklist_for(recipe)
    # Only merge prior tips when explicitly asked (default recipes). Title matches
    # stay recipe-only so shell tips never ride along on a bind finding.
    if merge_existing_checklist and existing and existing.checklist:
        for item in existing.checklist:
            if item not in checklist:
                checklist.append(item)
    return SuggestedFix(
        kind=kind,  # type: ignore[arg-type]
        summary=summary or (existing.summary if existing else None),
        diff=diff or (existing.diff if existing else None),
        checklist=checklist,
    )


def enrich_finding_fix(finding: Finding) -> SuggestedFix:
    """Attach YAML remediations; never include source attribution in the payload."""
    recipe = resolve_remediation(
        title=finding.title or "",
        owasp=list(finding.owasp or []),
        category=finding.category or "",
    )
    if recipe is None:
        return finding.suggested_fix or SuggestedFix(kind="code", summary=finding.summary)
    merge = _should_merge_checklist(recipe, category=finding.category or "")
    return suggested_fix_from_recipe(
        recipe,
        path=finding.evidence.path if finding.evidence else None,
        existing=finding.suggested_fix,
        merge_existing_checklist=merge,
    )


def _should_merge_checklist(recipe: dict[str, Any], *, category: str = "") -> bool:
    """Default + architecture: keep analyzer tips; code title matches stay recipe-only."""
    if recipe.get("id") == "default-analyze":
        return True
    if str(recipe.get("kind") or "") == "architecture" or category == "architecture":
        return True
    return False


def apply_remediation_fields(
    *,
    title: str,
    owasp: list[str] | None = None,
    category: str = "",
    path: str | None = None,
    existing: SuggestedFix | None = None,
) -> SuggestedFix:
    recipe = resolve_remediation(title=title, owasp=owasp, category=category)
    if recipe is None:
        return existing or SuggestedFix(kind="code", summary=None, checklist=[])
    merge = _should_merge_checklist(recipe, category=category)
    return suggested_fix_from_recipe(
        recipe,
        path=path,
        existing=existing,
        merge_existing_checklist=merge,
    )


def _merge_unique(*lists: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for group in lists:
        for item in group:
            key = (item or "").strip()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(key)
    return out


def hydrate_finding(finding: Finding) -> Finding:
    """Ensure issue-details payloads carry *relevant* YAML remediations only.

    Sources stay in YAML catalogs only — never copied onto the finding.
    """
    recipe = resolve_remediation(
        title=finding.title or "",
        owasp=list(finding.owasp or []),
        category=finding.category or "",
    )
    fix = enrich_finding_fix(finding)
    if recipe and recipe.get("id") != "default-analyze":
        # Title-matched recipe is authoritative — do not mix in unrelated tips.
        solutions = list(fix.checklist or [])
    else:
        solutions = _merge_unique(list(fix.checklist or []), list(finding.solutions or []))
    return finding.model_copy(
        update={
            "suggested_fix": fix,
            "solutions": solutions,
        }
    )


def finding_to_api_dict(finding: Finding) -> dict[str, Any]:
    """Serialize a finding for API/UI with remediations hydrated."""
    return hydrate_finding(finding).model_dump()
