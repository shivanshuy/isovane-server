"""Shared capability classification for toxic flows / trifecta / MCP depth."""

from __future__ import annotations

import re
from typing import Any

from isovane_serve.yaml_config import load_yaml
from isovane_serve.paths import CONFIG_DIR

_READ_FS = re.compile(
    r"(?i)\b(read_?file|read_?dir|list_?dir|filesystem|fs\.|cat\b|get_file|download|pii|customer.?data|secret.?store)\b"
)
_WRITE_FS = re.compile(
    r"(?i)\b(write_?file|delete_?file|rm\b|unlink|put_file|upload|mkdir)\b"
)
_SHELL = re.compile(
    r"(?i)\b(shell|bash|powershell|cmd\.exe|exec|run_command|terminal|code.?interpreter)\b"
)
_NETWORK = re.compile(
    r"(?i)\b(http|fetch|request|curl|wget|browser|browse|web_search|urlopen)\b"
)
_EXFIL = re.compile(
    r"(?i)(send_?email|send_?mail|send_?message|post_message|"
    r"\bemail\b|\bmail\b|\bslack\b|\bwebhook\b|\btelegram\b|\bdiscord\b|\bnotify\b|\brefund\b|\bpay\b)"
)
_SECRETS = re.compile(
    r"(?i)(api_?key|access_?token|\benv\b|\bsecret\b|\bcredential\b|"
    r"\bpassword\b|\bkeychain\b|\bvault\b)"
)
_PRIVATE = re.compile(
    r"(?i)\b(pii|customer|crm|database|db|vector|memory|rag|knowledge|docstore|secret|private)\b"
)
_UNTRUSTED = re.compile(
    r"(?i)\b(ui|chat|user|mail|email|web|rag|retrieved|public|ingress|untrusted)\b"
)
_EGRESS = re.compile(
    r"(?i)\b(send|email|slack|webhook|http|fetch|exfil|cloud.?llm|openai|anthropic|egress)\b"
)

# Default pairs when toxic-flows.yaml missing
_DEFAULT_PAIRS: list[tuple[frozenset[str], str, str]] = [
    (frozenset({"read_fs", "exfil"}), "filesystem read + send/email — classic exfil path", "high"),
    (frozenset({"secrets", "exfil"}), "secret/credential access + outbound message", "critical"),
    (frozenset({"shell", "network"}), "shell/exec + network — RCE with egress", "critical"),
    (frozenset({"read_fs", "network"}), "filesystem read + HTTP fetch — data staging/exfil", "high"),
    (frozenset({"write_fs", "shell"}), "filesystem write + shell — persistence / payload drop", "high"),
    (frozenset({"private", "exfil"}), "private/PII data + outbound channel", "critical"),
]


def classify_text(text: str) -> set[str]:
    caps: set[str] = set()
    if not text:
        return caps
    if _READ_FS.search(text):
        caps.add("read_fs")
    if _WRITE_FS.search(text):
        caps.add("write_fs")
    if _SHELL.search(text):
        caps.add("shell")
    if _NETWORK.search(text):
        caps.add("network")
    if _EXFIL.search(text):
        caps.add("exfil")
    if _SECRETS.search(text):
        caps.add("secrets")
    if _PRIVATE.search(text):
        caps.add("private")
    if _UNTRUSTED.search(text):
        caps.add("untrusted")
    if _EGRESS.search(text):
        caps.add("egress")
    return caps


def classify_tools(names: list[str]) -> set[str]:
    caps: set[str] = set()
    for name in names:
        caps |= classify_text(str(name))
    return caps


def load_toxic_pairs() -> list[dict[str, Any]]:
    path = CONFIG_DIR / "toxic-flows.yaml"
    if path.is_file():
        data = load_yaml(str(path)) or {}
        rows = data.get("pairs") or []
        out: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            need = frozenset(str(x) for x in (row.get("caps") or []) if x)
            if len(need) < 2:
                continue
            out.append(
                {
                    "caps": need,
                    "label": str(row.get("label") or "toxic capability pair"),
                    "severity": str(row.get("severity") or "high"),
                    "id": str(row.get("id") or "-".join(sorted(need))),
                }
            )
        if out:
            return out
    return [
        {
            "caps": caps,
            "label": label,
            "severity": sev,
            "id": "-".join(sorted(caps)),
        }
        for caps, label, sev in _DEFAULT_PAIRS
    ]


def matching_pairs(caps: set[str]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for pair in load_toxic_pairs():
        need: frozenset[str] = pair["caps"]
        if need <= caps:
            hits.append(pair)
    return hits


def node_caps(node: dict[str, Any]) -> set[str]:
    blob = " ".join(
        [
            str(node.get("kind") or ""),
            str(node.get("label") or ""),
            str(node.get("id") or ""),
            str(node.get("path") or ""),
        ]
    )
    caps = classify_text(blob)
    kind = str(node.get("kind") or "").lower()
    if kind in {"ui"}:
        caps.add("untrusted")
    if kind in {"data"}:
        caps.add("private")
        caps.add("read_fs")
    if kind in {"mcp", "tool"}:
        caps |= classify_text(str(node.get("label") or ""))
    if kind == "llm":
        caps.add("egress")
    return caps
