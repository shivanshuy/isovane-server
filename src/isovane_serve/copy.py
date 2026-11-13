"""Plain-English gloss + punchy jargon for finding / fix copy.

Keep the interesting security phrases; explain them first so anyone can follow.
"""

from __future__ import annotations


def gloss_then_punch(gloss: str, punch: str) -> str:
    """First sentence(s) explain terms; then keep the sharp jargon line."""
    gloss = " ".join(gloss.split()).strip()
    punch = " ".join(punch.split()).strip()
    if not gloss:
        return punch
    if not punch:
        return gloss
    return f"{gloss}\n{punch}"


def bandit_fix_summary(issue_text: str | None = None) -> str:
    detail = (issue_text or "").strip()
    gloss = (
        "Bandit is a Python security scanner that flags risky code patterns. "
        "Gated tools means the agent may only call allowlisted tools that pass a policy check - "
        "not raw shell, eval, or unrestricted exec."
    )
    if detail:
        gloss = f"{gloss} What Bandit reported: {detail}"
    return gloss_then_punch(
        gloss,
        "Address Bandit issue; prefer gated tools over raw exec.",
    )


def semgrep_fix_summary(message: str, title: str | None = None) -> str:
    msg = (message or title or "Semgrep finding").strip()
    return gloss_then_punch(
        "Semgrep is a static code scanner that matches security rules against your source. "
        f"It flagged: {msg}",
        "Address Semgrep finding; tighten the risky path before ship.",
    )


def detect_secrets_fix_summary(secret_type: str | None = None) -> str:
    kind = secret_type or "credential"
    return gloss_then_punch(
        f"detect-secrets is a scanner that looks for leaked credentials in files. "
        f"It found a possible {kind}. Rotate means issue a new secret and retire the old one; "
        "env/Keychain means load it from the environment or a password manager - not from source.",
        "Rotate the secret and load from env/Keychain.",
    )


def pii_fix_summary() -> str:
    return gloss_then_punch(
        "PII means personally identifiable information (names, emails, IDs, and similar). "
        "A vault is a secure secret store. Redact means replace sensitive text before it reaches a model or tool.",
        "Redact or move secrets to a vault; never embed in prompts.",
    )


def shell_true_fix_summary() -> str:
    return gloss_then_punch(
        "shell=True tells Python to run a command through the system shell, which can let unexpected text become real commands. "
        "Prefer a fixed argument list with shell=False.",
        "Use shell=False and argument lists.",
    )


def eval_exec_fix_summary() -> str:
    return gloss_then_punch(
        "eval/exec run text as code at runtime - that is excessive agency for an agent. "
        "Typed tool handlers means only call named, checked functions instead.",
        "Remove eval/exec; use typed tool handlers.",
    )


def wildcard_perms_fix_summary() -> str:
    return gloss_then_punch(
        "A wildcard (*) permission lets the agent use any tool. An allow-list is an explicit short list of tools it may call.",
        "Replace * with an explicit allow-list.",
    )


def secret_assignment_fix_summary() -> str:
    return gloss_then_punch(
        "A hardcoded secret is a password or API key written directly in source. "
        "Environment / Keychain means load it at runtime from a secure store.",
        "Move secret to environment / Keychain.",
    )


def watch_policy_fix_summary() -> str:
    return gloss_then_punch(
        "A runtime policy is the rule set that blocks or allows tool calls as they happen. "
        "A sidecar is a small gate process sitting next to the agent that enforces those rules.",
        "Tighten runtime policy / sidecar so this deny class stays blocked.",
    )


def architecture_fix_summary() -> str:
    return gloss_then_punch(
        "Trust boundaries mark where untrusted input meets sensitive systems. "
        "Confirm gates means require a human or policy check before high-impact tools fire.",
        "Update deployment diagram trust boundaries and confirm gates.",
    )


def prompt_fix_summary() -> str:
    return gloss_then_punch(
        "System prompt bounds are hard rules in the model instructions - what data it may see, which tools it may call, and what it must refuse.",
        "Harden system prompt bounds (PII, tools, trust).",
    )


def analyze_code_fix_summary() -> str:
    return gloss_then_punch(
        "This came from Analyze: fix it in the agent code or tool registration before you ship.",
        "Patch agent code / tool registration from Analyze finding.",
    )


def jailbreak_fix_summary() -> str:
    return gloss_then_punch(
        "A jailbreak invitation asks the model to ignore its system rules. "
        "Refusal boundaries are clear lines for what it must decline.",
        "Remove jailbreak invitations; add refusal boundaries.",
    )


def rag_trust_fix_summary() -> str:
    return gloss_then_punch(
        "RAG means retrieved documents pasted into the prompt. "
        "Untrusted delimiters mark that text as untrusted so the model must not treat it as instructions.",
        "Wrap RAG in untrusted delimiters; forbid tool use from RAG alone.",
    )


def prompt_context_fix_summary() -> str:
    return gloss_then_punch(
        "Prompt context is app/state/API data you put into the model yourself — not the same as RAG retrieval. "
        "Trust labels tell the model that block is data, not system instructions.",
        "Label concatenated app/state fields as data; redact before prompt; reserve 'RAG' for retrievers.",
    )


def pii_prompt_fix_summary() -> str:
    return gloss_then_punch(
        "PII is personal data such as emails, phones, or IDs. "
        "Redact-before-tool means strip that data before calling any tool.",
        "Add PII non-disclosure and redact-before-tool rules.",
    )


def hitl_fix_summary() -> str:
    return gloss_then_punch(
        "HITL means human-in-the-loop: a person must confirm before high-impact actions like send, pay, or shell.",
        "Require confirmation before send/pay/shell.",
    )


def system_disclosure_fix_summary() -> str:
    return gloss_then_punch(
        "System instructions are the private rules behind the agent. "
        "Verbatim means word-for-word - the model should never dump them to the user.",
        "Forbid repeating system instructions verbatim.",
    )
