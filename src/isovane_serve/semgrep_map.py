"""Map Semgrep check_ids / messages → Isovane titles, categories, OWASP."""

from __future__ import annotations

from typing import Any


def classify_semgrep_hit(
    *,
    check_id: str,
    message: str,
    meta: dict[str, Any],
) -> dict[str, Any]:
    """Prefer Isovane metadata when present; otherwise infer from upstream packs."""
    if meta.get("isovane_title"):
        owasp = meta.get("owasp") or []
        if isinstance(owasp, str):
            owasp = [owasp]
        return {
            "title": str(meta["isovane_title"]),
            "category": str(meta.get("isovane_category") or "static"),
            "owasp": list(owasp),
            "fix_kind": str(meta.get("isovane_fix_kind") or "code"),
            "fix_summary": meta.get("isovane_fix_summary"),
            "pack": "isovane",
        }

    blob = f"{check_id} {message}".lower()
    title = _pretty_title(check_id, message)
    category = "static"
    owasp: list[str] = []
    fix_kind = "code"
    fix_summary: str | None = None

    if any(k in blob for k in ("prompt", "systemmessage", "jailbreak", "injection", "rag")):
        category = "prompt"
        fix_kind = "prompt"
        owasp = ["LLM01"]
    if any(k in blob for k in ("pii", "secret", "credential", "api_key", "apikey")):
        category = "pii" if "pii" in blob else "static"
        owasp = list(dict.fromkeys([*owasp, "LLM02"]))
    if any(
        k in blob
        for k in (
            "agency",
            "agent",
            "tool",
            "bind_tools",
            "react",
            "mcp",
            "permission",
            "shell",
            "eval",
            "exec",
            "unbounded",
            "max_tokens",
            "max_iterations",
        )
    ):
        if category == "static":
            category = "agency"
        owasp = list(dict.fromkeys([*owasp, "LLM06"]))
        fix_summary = fix_summary or "Gate tools / bound loops outside the model; prefer allow-lists + HITL."
    if "mcp" in blob:
        owasp = list(dict.fromkeys([*owasp, "LLM03", "ASI04"]))
        fix_kind = "schema"
    if any(k in blob for k in ("ssrf", "urlopen", "requests.get", "httpx")):
        owasp = list(dict.fromkeys([*owasp, "ASI05"]))
    if not owasp:
        meta_owasp = meta.get("owasp") or meta.get("cwe") or []
        if isinstance(meta_owasp, str):
            meta_owasp = [meta_owasp]
        owasp = [str(x) for x in meta_owasp][:4]

    pack = "upstream"
    if "ai-best-practices" in check_id or "ai.ai" in check_id:
        pack = "semgrep-ai-best-practices"
    elif check_id.startswith("rules.agent.") or "isovane." in check_id:
        pack = "isovane"

    return {
        "title": title,
        "category": category,
        "owasp": owasp,
        "fix_kind": fix_kind,
        "fix_summary": fix_summary,
        "pack": pack,
    }


def _pretty_title(check_id: str, message: str) -> str:
    leaf = check_id.split(".")[-1].replace("-", " ").replace("_", " ").strip()
    if leaf and leaf.lower() not in {"python", "javascript", "generic", "yaml", "json"}:
        return leaf[:1].upper() + leaf[1:]
    first = (message or "").strip().split(".")[0].strip()
    return (first[:90] if first else "Semgrep finding") or "Semgrep finding"
