"""Best-effort redaction of secret-shaped text in remote output (REQ-010).

Redaction is heuristic and NOT complete; nothing may claim otherwise.
Patterns avoid nested/unbounded quantifiers so large inputs stay linear.
"""

from __future__ import annotations

import re

_FLAGS = re.IGNORECASE | re.MULTILINE

_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]*?"
            r"(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|\Z)"
        ),
        "[REDACTED:private_key]",
    ),
    (
        re.compile(r"^([ \t]*Authorization[ \t]*:)[^\r\n]*", _FLAGS),
        r"\1 [REDACTED:authorization]",
    ),
    (
        re.compile(r"^([ \t]*(?:Set-)?Cookie[ \t]*:)[^\r\n]*", _FLAGS),
        r"\1 [REDACTED:cookie]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
        "[REDACTED:jwt]",
    ),
    (
        re.compile(r"\bBearer[ \t]+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
        "Bearer [REDACTED:bearer]",
    ),
    (
        re.compile(
            r"(password|passwd|secret|token|api_key)([ \t]*=[ \t]*)"
            r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s&;,\"']+)",
            re.IGNORECASE,
        ),
        r"\1\2[REDACTED:secret]",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_key]"),
    (
        re.compile(
            r"\b(?:ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}"
            r"|sk-[A-Za-z0-9_-]{20,}|xox[bp]-[A-Za-z0-9-]{10,})"
        ),
        "[REDACTED:token]",
    ),
)


def redact(text: str) -> str:
    for pattern, repl in _RULES:
        text = pattern.sub(repl, text)
    return text
