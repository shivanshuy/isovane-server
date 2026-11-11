"""F5: AST taint precision — aliases, sources, clean literals."""

from __future__ import annotations

from pathlib import Path

from isovane_serve.ast_taint import scan_ast_taint

ROOT = Path(__file__).resolve().parents[1]


def _scan_src(tmp_path: Path, src: str) -> list[str]:
    p = tmp_path / "mod.py"
    p.write_text(src, encoding="utf-8")
    return [f.title for f in scan_ast_taint("t", tmp_path)]


def test_alias_from_request_json_reaches_system_message(tmp_path: Path):
    titles = _scan_src(
        tmp_path,
        """
def handle(request):
    raw = request.json["prompt"]
    msg = raw
    return SystemMessage(content=f"sys {msg}")
""",
    )
    assert any("system prompt" in t.lower() for t in titles)


def test_userish_param_in_fstring(tmp_path: Path):
    titles = _scan_src(
        tmp_path,
        """
def build(user_text: str):
    return SystemMessage(content=f"User said: {user_text}")
""",
    )
    assert any("system prompt" in t.lower() for t in titles)


def test_static_system_message_not_flagged(tmp_path: Path):
    titles = _scan_src(
        tmp_path,
        """
def ok():
    return SystemMessage(content="You are helpful.")
""",
    )
    assert not any("system prompt" in t.lower() for t in titles)


def test_clean_reassignment_kills_taint(tmp_path: Path):
    titles = _scan_src(
        tmp_path,
        """
def handle(user_text: str):
    msg = user_text
    msg = "static policy text"
    return SystemMessage(content=msg)
""",
    )
    assert not any("system prompt" in t.lower() for t in titles)


def test_bare_content_name_not_auto_tainted(tmp_path: Path):
    """Regression: old heuristics treated any Name called content as tainted."""
    titles = _scan_src(
        tmp_path,
        """
def ok():
    content = "You are helpful."
    return SystemMessage(content=content)
""",
    )
    assert not any("system prompt" in t.lower() for t in titles)


def test_tainted_reaches_send_tool(tmp_path: Path):
    titles = _scan_src(
        tmp_path,
        """
def act(user_text: str):
    send(to="a@b.c", body=user_text)
""",
    )
    assert any("consequential tool" in t.lower() for t in titles)


def test_bakeoff_ast_taint_alias_fixture():
    folder = ROOT / "tests" / "bakeoff" / "fixtures" / "ast_taint_alias"
    findings = scan_ast_taint("bakeoff", folder)
    titles = [f.title for f in findings]
    assert any("system prompt" in t.lower() for t in titles)
    # Precision: safe_static in same file must not create a second prompt hit on that line
    prompt_hits = [f for f in findings if "system prompt" in f.title.lower()]
    assert len(prompt_hits) >= 1
    snippets = " ".join((f.evidence.snippet or "") for f in prompt_hits)
    assert "helpful assistant" not in snippets.lower()
