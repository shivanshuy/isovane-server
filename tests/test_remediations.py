"""Industry remediations YAML — sources tracked, never leaked to UI payloads."""

from isovane_serve.models import Finding, FindingEvidence, SuggestedFix
from isovane_serve.remediations import (
    apply_remediation_fields,
    checklist_for,
    enrich_finding_fix,
    load_remediations,
    resolve_remediation,
)
from isovane_serve.patches import patch_for_finding
from isovane_serve import store


def test_catalog_loads_with_sources():
    data = load_remediations()
    assert data["sources"]
    assert data["remediations"]
    assert "owasp_llm01" in data["sources"]
    assert "isovane" in data["sources"]
    ids = {r["id"] for r in data["remediations"]}
    assert "arch-hitl-gate" in ids  # from remediations-architecture.yaml
    assert "shell-true" in ids  # from remediations.yaml


def test_system_prompt_recipe_from_owasp():
    recipe = resolve_remediation(title="System prompt built in Python", owasp=["LLM01"])
    assert recipe is not None
    assert recipe["id"] == "system-prompt-built"
    texts = checklist_for(recipe)
    assert len(texts) >= 3
    # Sources must not appear in developer-facing checklist strings
    blob = " ".join(texts).lower()
    assert "owasp_llm" not in blob
    assert "source:" not in blob
    assert any("system" in t.lower() or "pii" in t.lower() or "hitl" in t.lower() for t in texts)


def test_hitl_recipe_prefers_llm06():
    recipe = resolve_remediation(title="Tools mentioned without HITL", owasp=["LLM06"])
    assert recipe is not None
    assert recipe["id"] == "tools-without-hitl"
    assert any(
        (s.get("source") if isinstance(s, dict) else None) == "owasp_llm06"
        for s in recipe["suggestions"]
    )
    fix = apply_remediation_fields(title="Tools mentioned without HITL", owasp=["LLM06"])
    assert fix.diff
    assert "allow-list" in (fix.diff or "").lower() or "create_react_agent" in (fix.diff or "")
    assert "owasp_llm06" not in (fix.summary or "").lower()
    assert all("source" not in c.lower() for c in fix.checklist)


def test_rag_and_pii_recipes_exist():
    rag = resolve_remediation(title="RAG concat without trust boundary")
    pii = resolve_remediation(title="Missing PII / disclosure bounds")
    assert rag and rag["id"] == "rag-without-trust"
    assert pii and pii["id"] == "missing-pii-bounds"
    assert "UNTRUSTED" in (rag.get("diff") or "")


def test_enrich_finding_and_patch_hide_sources(tmp_path):
    finding = Finding(
        workspace_id="ws",
        source="analyze",
        severity="medium",
        title="System prompt built in Python",
        summary="SystemMessage constructed",
        category="prompt",
        owasp=["LLM01", "LLM02"],
        evidence=FindingEvidence(path="agent.py", tool="semgrep", line=10),
        suggested_fix=SuggestedFix(kind="prompt", summary="x", checklist=[]),
    )
    store.FINDINGS[finding.id] = finding
    fix = enrich_finding_fix(finding)
    assert len(fix.checklist) >= 3
    assert fix.diff
    payload = patch_for_finding(finding.id)
    assert payload is not None
    assert "checklist" in payload
    assert "source" not in str(payload.get("checklist"))
    dumped = str(payload)
    assert "owasp_llm01" not in dumped
    assert "CC-BY-SA" not in dumped


def test_hydrate_finding_for_issue_details():
    from isovane_serve.remediations import hydrate_finding, finding_to_api_dict

    thin = Finding(
        workspace_id="ws",
        source="analyze",
        severity="high",
        title="Tools mentioned without HITL",
        summary="old finding without remediations",
        category="agency",
        owasp=["LLM06"],
        evidence=FindingEvidence(path="agent.py", tool="semgrep", line=1),
        solutions=["vague tip"],
        suggested_fix=SuggestedFix(kind="code", summary="old", checklist=[]),
    )
    rich = hydrate_finding(thin)
    assert len(rich.solutions) >= 5
    assert rich.suggested_fix and rich.suggested_fix.diff
    assert "allow-list" in (rich.suggested_fix.diff or "").lower() or "create_react_agent" in (
        rich.suggested_fix.diff or ""
    )
    api = finding_to_api_dict(thin)
    assert len(api["solutions"]) >= 5
    assert "owasp_llm06" not in str(api)
    assert "source" not in str(api.get("solutions"))


def test_bind_all_not_shell_remediations():
    """ASI05 alone must not attach shell=True tips to a 0.0.0.0 bind finding."""
    from isovane_serve.remediations import hydrate_finding, load_remediations

    load_remediations.cache_clear()
    recipe = resolve_remediation(
        title="Possible binding to all interfaces",
        owasp=["ASI05"],
        category="static",
    )
    assert recipe is not None
    assert recipe["id"] == "bind-all-interfaces"
    texts = checklist_for(recipe)
    blob = " ".join(texts).lower()
    assert "127.0.0.1" in blob or "0.0.0.0" in blob
    assert "shell=false" not in blob
    assert "cwe-78" not in blob
    assert "argv" not in blob

    # Bandit test_name form must also resolve to bind, not hardcoded-secret.
    by_name = resolve_remediation(title="hardcoded_bind_all_interfaces", owasp=["ASI05"])
    assert by_name and by_name["id"] == "bind-all-interfaces"

    finding = Finding(
        workspace_id="ws",
        source="analyze",
        severity="medium",
        title="Possible binding to all interfaces",
        summary="Possible binding to all interfaces.",
        category="static",
        owasp=["ASI05"],
        evidence=FindingEvidence(path="app.py", tool="bandit", line=12),
        solutions=[
            "Do not invoke OS commands through a shell when an API exists; pass a fixed argv list with shell=False (CWE-78).",
            "Bind to 127.0.0.1 (or another private interface) for local-only services.",
        ],
        suggested_fix=SuggestedFix(
            kind="code",
            summary="stale",
            checklist=["Avoid open-ended run-shell agent tools; use a narrow, allow-listed tool instead (OWASP LLM06)."],
        ),
    )
    rich = hydrate_finding(finding)
    sol_blob = " ".join(rich.solutions).lower()
    assert "127.0.0.1" in sol_blob
    assert "shell=false" not in sol_blob
    assert "cwe-78" not in sol_blob
    assert "argv" not in sol_blob
    assert rich.suggested_fix and "127.0.0.1" in (rich.suggested_fix.diff or "")


def test_shell_true_still_gets_shell_tips():
    load_remediations.cache_clear()
    recipe = resolve_remediation(
        title="shell=True enables unexpected code execution",
        owasp=["ASI05", "LLM06"],
    )
    assert recipe and recipe["id"] == "shell-true"
    texts = checklist_for(recipe)
    assert any("shell=False" in t or "argv" in t.lower() for t in texts)
    assert not any("127.0.0.1" in t for t in texts)


def test_owasp_alone_falls_back_to_default():
    """Shared OWASP tags must not cross-wire unrelated recipes."""
    load_remediations.cache_clear()
    recipe = resolve_remediation(title="Some unrelated scanner finding", owasp=["ASI05", "LLM06"])
    assert recipe is not None
    assert recipe["id"] == "default-analyze"
