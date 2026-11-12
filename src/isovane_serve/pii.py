"""PII detection: fast regex path + optional Presidio/GLiNER."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from isovane_serve.catalog import PII_CLASSES

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    (
        "phone",
        re.compile(
            r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"
        ),
    ),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("aadhaar", re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),
    ("pan", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    (
        "api_key",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
        ),
    ),
    (
        "password",
        re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{6,}"),
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
]


@dataclass
class PiiHit:
    pii_class: str
    start: int
    end: int
    text: str


def detect_pii(text: str, classes: list[str] | None = None) -> list[PiiHit]:
    if not text:
        return []
    allowed = set(classes or PII_CLASSES)
    hits: list[PiiHit] = []
    for name, pattern in _PATTERNS:
        if name not in allowed:
            continue
        for match in pattern.finditer(text):
            value = match.group(0)
            if name == "credit_card" and not _luhn(re.sub(r"\D", "", value)):
                continue
            if name == "phone" and len(re.sub(r"\D", "", value)) < 10:
                continue
            if name == "aadhaar" and len(re.sub(r"\D", "", value)) != 12:
                continue
            hits.append(PiiHit(name, match.start(), match.end(), value))
    return hits


def pii_classes_in(text: str, classes: list[str] | None = None) -> list[str]:
    found = {hit.pii_class for hit in detect_pii(text, classes)}
    try:
        found.update(_presidio_classes(text, classes))
    except Exception:
        pass
    return sorted(found)


def args_to_text(args: dict[str, Any]) -> str:
    return " ".join(f"{key}={value}" for key, value in (args or {}).items())


def _luhn(digits: str) -> bool:
    if not digits.isdigit() or len(digits) < 13:
        return False
    total = 0
    for i, ch in enumerate(digits[::-1]):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _presidio_classes(text: str, classes: list[str] | None) -> set[str]:
    from presidio_analyzer import AnalyzerEngine  # type: ignore

    analyzer = AnalyzerEngine()
    results = analyzer.analyze(text=text, language="en")
    mapping = {
        "EMAIL_ADDRESS": "email",
        "PHONE_NUMBER": "phone",
        "US_SSN": "ssn",
        "CREDIT_CARD": "credit_card",
        "IBAN_CODE": "bank_account",
    }
    allowed = set(classes or PII_CLASSES)
    out: set[str] = set()
    for item in results:
        mapped = mapping.get(item.entity_type)
        if mapped and mapped in allowed:
            out.add(mapped)
    return out
