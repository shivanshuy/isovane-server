from isovane_serve.gate import judge
from isovane_serve.pii import detect_pii, pii_classes_in


def test_email_detected():
    hits = detect_pii("Contact jane@example.com please")
    assert any(h.pii_class == "email" for h in hits)


def test_outbound_pii_denied():
    decision = judge(
        {
            "tool": "send",
            "args": {"body": "ssn 123-45-6789"},
            "source": "user",
            "confirmed": True,
        }
    )
    assert decision["verdict"] == "deny"
    assert decision["policy_rule_id"] == "pii_outbound"
    assert "ssn" in decision["pii_classes"]
    assert "LLM02" in decision["owasp"]


def test_pan_class():
    assert "pan" in pii_classes_in("PAN ABCDE1234F")
