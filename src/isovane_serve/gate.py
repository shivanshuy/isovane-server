"""Policy that sits outside the model.

A consequential tool call is denied unless a person confirmed it, the amount
is inside the cap, the request did not arrive from untrusted content, and
outbound args do not leak denied PII classes.
"""

from __future__ import annotations

import json
import re
from typing import Any

from isovane_serve.models import PolicyConfig
from isovane_serve.pii import args_to_text, pii_classes_in
from isovane_serve.policy import load_policy

_AMOUNT = re.compile(r'"amount"\s*:\s*(\d+(?:\.\d+)?)')

# OWASP ids attached to deny reasons
_RULE_OWASP = {
    "no_tool": ["ASI02"],
    "amount_cap": ["LLM06", "ASI02"],
    "untrusted": ["ASI01", "ASI02"],
    "confirm": ["ASI09", "LLM06"],
    "allow_list": ["ASI03", "ASI10"],
    "pii_outbound": ["LLM02"],
    "shell": ["ASI05"],
}


def _amount(args: dict[str, Any]) -> float | None:
    for key in ("amount", "value", "total"):
        raw = args.get(key)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            return float(raw)
    return None


def parse_action(text: str) -> dict[str, Any]:
    """Read a tool call from a JSON object, or from a `tool: name` line."""
    raw = (text or "").strip()
    if not raw:
        return {}
    if raw.startswith("{") or raw.startswith("["):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            tool = str(payload.get("tool") or payload.get("name") or "").strip()
            args = payload.get("args") if isinstance(payload.get("args"), dict) else {}
            return {
                "tool": tool,
                "args": args,
                "source": str(payload.get("source") or "user"),
                "confirmed": bool(payload.get("confirmed")),
            }
    tool = ""
    match = re.search(r"\btool\s*[:=]\s*([a-zA-Z0-9_\-]+)", raw, re.IGNORECASE)
    if match:
        tool = match.group(1)
    amount_match = _AMOUNT.search(raw)
    args: dict[str, Any] = {}
    if amount_match:
        args["amount"] = float(amount_match.group(1))
    source = "user"
    untrusted = load_policy().untrusted_sources
    for marker in untrusted:
        if marker in raw.lower():
            source = marker
            break
    return {
        "tool": tool,
        "args": args,
        "source": source,
        "confirmed": "confirmed" in raw.lower(),
    }


def judge(
    action: dict[str, Any] | None,
    policy: PolicyConfig | None = None,
) -> dict[str, Any]:
    """Return allow or deny. The model does not get a vote."""
    cfg = policy or load_policy()
    body = action or {}
    tool = str(body.get("tool") or "").strip().lower().replace("-", "_")
    source = str(body.get("source") or "user").strip().lower()
    confirmed = bool(body.get("confirmed"))
    args = body.get("args") if isinstance(body.get("args"), dict) else {}
    amount = _amount(args)

    allow = {t.lower().replace("-", "_") for t in cfg.allow_tools}
    consequential = {t.lower().replace("-", "_") for t in cfg.consequential}
    require_confirm = {t.lower().replace("-", "_") for t in cfg.require_confirm}
    money = {t.lower().replace("-", "_") for t in cfg.money_tools}
    untrusted = {s.lower() for s in cfg.untrusted_sources}

    def deny(rule: str, reason: str, pii: list[str] | None = None) -> dict[str, Any]:
        return {
            "verdict": "deny",
            "reason": reason,
            "policy_rule_id": rule,
            "owasp": list(_RULE_OWASP.get(rule, ["ASI02"])),
            "pii_classes": pii or [],
        }

    if not tool:
        return deny("no_tool", "No tool was named.")

    # PII on outbound consequential args
    pii_hits: list[str] = []
    if cfg.deny_pii_outbound and tool in consequential:
        pii_hits = pii_classes_in(args_to_text(args), cfg.pii_classes)
        if pii_hits:
            return deny(
                "pii_outbound",
                f"{tool} args contain outbound PII: {', '.join(pii_hits)}.",
                pii_hits,
            )

    if tool in allow and source not in untrusted:
        return {
            "verdict": "allow",
            "reason": f"{tool} is read-only.",
            "policy_rule_id": "allow_read",
            "owasp": [],
            "pii_classes": [],
        }

    if tool in money and amount is not None and amount > cfg.amount_cap:
        return deny(
            "amount_cap",
            f"{tool} of {amount:g} is over the {cfg.amount_cap:g} cap.",
        )

    if cfg.block_if_untrusted_source and tool in consequential and source in untrusted:
        return deny(
            "untrusted",
            f"{tool} was requested from untrusted {source}.",
        )

    if tool in require_confirm and not confirmed:
        return deny(
            "confirm",
            f"{tool} needs a person to confirm it.",
        )

    if tool in {"shell", "exec"} and not confirmed:
        return deny("shell", f"{tool} is blocked without confirmation.")

    if tool in consequential or tool in allow:
        return {
            "verdict": "allow",
            "reason": f"{tool} is inside the rules.",
            "policy_rule_id": "allow",
            "owasp": [],
            "pii_classes": [],
        }

    return deny("allow_list", f"{tool} is not on the allow list.")
