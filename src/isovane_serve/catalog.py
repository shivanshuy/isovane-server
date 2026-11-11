"""OWASP LLM + Agentic finding catalog. Every Finding carries ≥1 id from here."""

from __future__ import annotations

LLM_TOP_10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

ASI_TOP_10: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

ALL_OWASP = {**LLM_TOP_10, **ASI_TOP_10}

PII_CLASSES = (
    "email",
    "phone",
    "pan",
    "aadhaar",
    "ssn",
    "credit_card",
    "bank_account",
    "health_id",
    "api_key",
    "password",
    "private_key",
)

SEVERITIES = ("critical", "high", "medium", "low")
SOURCES = ("analyze", "watch", "hunt")
CATEGORIES = (
    "static",
    "prompt",
    "pii",
    "injection",
    "architecture",
    "runtime",
    "agency",
)
STATUSES = ("open", "accepted", "fixed", "wontfix", "false_positive")


def label(owasp_id: str) -> str:
    return ALL_OWASP.get(owasp_id, owasp_id)


def validate_owasp(ids: list[str]) -> list[str]:
    return [item for item in ids if item in ALL_OWASP]
