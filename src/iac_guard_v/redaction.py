"""Credential and path redaction for process output and reporting.

This module provides functions to strip credential-shaped values, tokens, and local
filesystem paths from strings before they appear in logs, reports, or error messages.

Design notes:

- Patterns are applied greedily. A false positive (redacting a non-secret that looks
  like a token) is acceptable; a false negative (leaking a real credential) is not.
- Redaction is one-way: the original value is not recoverable from the redacted output.
- This module never reads files, opens sockets, or imports subprocess.
"""
from __future__ import annotations

import re
from typing import Sequence

__all__ = [
    "redact_argv",
    "redact_detail",
    "redact_credentials",
    "redact_paths",
    "REDACTED_MARKER",
]

#: The replacement marker used when a value is redacted.
REDACTED_MARKER = "[REDACTED]"

#: Path replacement marker.
REDACTED_PATH_MARKER = "[PATH]"

# --------------------------------------------------------------------------- #
# Credential patterns
# --------------------------------------------------------------------------- #
# AWS keys: AKIA... (20 chars), temporary session tokens, generic long secrets
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # AWS Access Key IDs
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), REDACTED_MARKER),
    # AWS Secret Access Keys (40-char base64-ish)
    (re.compile(r"\b([A-Za-z0-9/+=]{40})\b"), REDACTED_MARKER),
    # Generic bearer/token patterns
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.ASCII), r"\1" + REDACTED_MARKER),
    # GitHub tokens (ghp_, gho_, ghs_, ghr_, github_pat_)
    (re.compile(r"\b(ghp_[A-Za-z0-9]{36,})\b"), REDACTED_MARKER),
    (re.compile(r"\b(gho_[A-Za-z0-9]{36,})\b"), REDACTED_MARKER),
    (re.compile(r"\b(ghs_[A-Za-z0-9]{36,})\b"), REDACTED_MARKER),
    (re.compile(r"\b(ghr_[A-Za-z0-9]{36,})\b"), REDACTED_MARKER),
    (re.compile(r"\b(github_pat_[A-Za-z0-9_]{36,})\b"), REDACTED_MARKER),
    # Generic API key patterns: key=VALUE, token=VALUE, password=VALUE, secret=VALUE
    (re.compile(
        r"(?i)((?:api[_-]?key|token|password|passwd|secret|credential)[=:]\s*)"
        r"([^\s,;'\"]{8,})"
    ), r"\1" + REDACTED_MARKER),
    # Long hex strings (32+ chars) that look like secrets
    (re.compile(r"\b([0-9a-fA-F]{32,})\b"), REDACTED_MARKER),
]

# --------------------------------------------------------------------------- #
# Path patterns
# --------------------------------------------------------------------------- #
# Absolute paths on Unix and Windows
_PATH_PATTERN = re.compile(
    r"(/(?:Users|home|root|tmp|var|etc|opt|usr)/[^\s:;,\"']+)"
    r"|"
    r"([A-Za-z]:\\[^\s:;,\"']+)"
)


def redact_credentials(text: str) -> str:
    """Remove credential-shaped values from text."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_paths(text: str) -> str:
    """Replace local filesystem paths with a generic marker."""
    return _PATH_PATTERN.sub(REDACTED_PATH_MARKER, text)


def redact_detail(text: str) -> str:
    """Redact both credentials and paths from a detail/error string."""
    text = redact_credentials(text)
    text = redact_paths(text)
    return text


def redact_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Redact credential-shaped values and paths from an argument vector.

    The executable name (argv[0]) is preserved but paths are redacted from the rest.
    """
    if not argv:
        return ()
    result = [argv[0]]
    for arg in argv[1:]:
        cleaned = redact_credentials(arg)
        cleaned = redact_paths(cleaned)
        result.append(cleaned)
    return tuple(result)
