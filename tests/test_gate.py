from isovane_serve.agent.graph import graph
from isovane_serve.gate import judge


def test_refund_over_cap_is_denied():
    decision = judge({"tool": "refund", "args": {"amount": 800}, "source": "user", "confirmed": True})
    assert decision["verdict"] == "deny"
    assert "500" in decision["reason"]


def test_untrusted_send_is_denied():
    decision = judge({"tool": "send", "args": {}, "source": "email", "confirmed": True})
    assert decision["verdict"] == "deny"
    assert "untrusted" in decision["reason"]


def test_confirmed_write_is_allowed():
    decision = judge({"tool": "write", "args": {}, "source": "user", "confirmed": True})
    assert decision["verdict"] == "allow"


def test_graph_denies_a_chat_message():
    result = graph.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": '{"tool":"send","source":"email","confirmed":true}',
                }
            ]
        }
    )
    assert result["verdict"] == "deny"
    assert "DENY" in result["messages"][-1].content
