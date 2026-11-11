from isovane_serve.semgrep_map import classify_semgrep_hit


def test_isovane_metadata_wins():
    hit = classify_semgrep_hit(
        check_id="rules.agent.isovane.agent.shell-true",
        message="shell=True",
        meta={
            "isovane_title": "shell=True in subprocess",
            "isovane_category": "static",
            "owasp": ["ASI05"],
            "isovane_fix_kind": "code",
        },
    )
    assert hit["title"] == "shell=True in subprocess"
    assert hit["category"] == "static"
    assert hit["pack"] == "isovane"


def test_upstream_ai_pack_inferred():
    hit = classify_semgrep_hit(
        check_id="ai.ai-best-practices.agent-unbounded-loop.agent-unbounded-loop-python",
        message="LLM API call inside a while True loop",
        meta={},
    )
    assert hit["pack"] == "semgrep-ai-best-practices"
    assert hit["category"] == "agency"
    assert "LLM06" in hit["owasp"]
