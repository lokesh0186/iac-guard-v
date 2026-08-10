"""Credential and path redaction for process output and reporting.

This module provides functions to strip credential-shaped values, tokens, and local
filesystem paths from strings before they appear in logs, reports, or error messages.

Design notes:

- Patterns are applied greedily. A false positive (redacting a non-secret that looks
  like a token) is acceptable; a false negative (leaking a real credential) is not.
- Redaction is one-way: the original value is not recoverable from the redacted output.
- This module never reads files, opens sockets, or imports subprocess.

D2.2 additions:
- redact_option_values: redact values after known sensitive flags (--token, --password,
  --secret, --api-key, --header).
- Improved path redaction: redacts POSIX absolute paths (/Users/..., /home/..., /mnt/...,
  /private/..., /tmp/..., /var/...) and Windows (C:\...) but NOT URLs (http://... https://...).
- display_command: returns a redacted, shlex.quote'd representation.
"""
from __future__ import annotations

import re
import shlex
from typing import Sequence

__all__ = [
    "redact_argv",
    "redact_detail",
    "redact_credentials",
    "redact_paths",
    "redact_option_values",
    "display_command",
    "REDACTED_MARKER",
    "REDACTED_PATH_MARKER",
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
# Sensitive option flags whose NEXT argument should be redacted
# --------------------------------------------------------------------------- #
SENSITIVE_OPTION_NAMES: frozenset[str] = frozenset({
    "--token", "--password", "--secret", "--api-key", "--header",
    "--api_key", "--api-token", "--auth-token", "--access-token",
})

# --------------------------------------------------------------------------- #
# Path patterns - redacts POSIX and Windows absolute paths but NOT URLs
# --------------------------------------------------------------------------- #
# Match absolute paths starting with known sensitive prefixes
_POSIX_PATH_PREFIXES = (
    "/Users/", "/home/", "/mnt/", "/private/", "/tmp/", "/var/",
)

# Pattern for POSIX paths with known sensitive prefixes (not preceded by ://)
_POSIX_PATH_PATTERN = re.compile(
    r"(?<!:/)(?<!/)"  # negative lookbehind for :// (URLs)
    r"(/(?:Users|home|mnt|private|tmp|var)/[^\s:;,\"')\]}>]+)"
)

# Pattern for Windows absolute paths (C:\...)
_WINDOWS_PATH_PATTERN = re.compile(
    r"([A-Za-z]:\\[^\s:;,\"')\]}>]+)"
)


def redact_credentials(text: str) -> str:
    """Remove credential-shaped values from text."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_paths(text: str) -> str:
    """Replace local filesystem paths with a generic marker.

    Redacts POSIX paths under /Users, /home, /mnt, /private, /tmp, /var
    and Windows paths like C:\... but does NOT redact URLs.
    """
    # First protect URLs by temporarily replacing them
    url_placeholders: list[str] = []

    def _save_url(m: re.Match) -> str:
        url_placeholders.append(m.group(0))
        return f"__URL_PLACEHOLDER_{len(url_placeholders) - 1}__"

    text = re.sub(r"https?://[^\s\"'<>]+", _save_url, text)

    # Now redact POSIX paths
    text = _POSIX_PATH_PATTERN.sub(REDACTED_PATH_MARKER, text)
    # Redact Windows paths
    text = _WINDOWS_PATH_PATTERN.sub(REDACTED_PATH_MARKER, text)

    # Restore URLs
    for i, url in enumerate(url_placeholders):
        text = text.replace(f"__URL_PLACEHOLDER_{i}__", url)

    return text


def redact_option_values(argv: Sequence[str]) -> tuple[str, ...]:
    """Redact values following known sensitive option flags.

    For example: ['--token', 'secret123'] -> ['--token', '[REDACTED]']
    Also handles --token=value form.
    """
    if not argv:
        return ()
    result: list[str] = []
    skip_next = False
    for i, arg in enumerate(argv):
        if skip_next:
            result.append(REDACTED_MARKER)
            skip_next = False
            continue
        # Check --flag=value form
        if "=" in arg:
            flag_part = arg.split("=", 1)[0]
            if flag_part.lower() in {s.lower() for s in SENSITIVE_OPTION_NAMES}:
                result.append(f"{flag_part}={REDACTED_MARKER}")
                continue
        # Check if this flag means next arg is sensitive
        if arg.lower() in {s.lower() for s in SENSITIVE_OPTION_NAMES}:
            result.append(arg)
            skip_next = True
            continue
        result.append(arg)
    return tuple(result)


def redact_detail(text: str) -> str:
    """Redact both credentials and paths from a detail/error string."""
    text = redact_credentials(text)
    text = redact_paths(text)
    return text


def redact_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Redact credential-shaped values, sensitive option values, and paths from argv.

    The executable name (argv[0]) is preserved but paths are redacted from the rest.
    Sensitive option values (after --token, --password, etc.) are fully redacted.
    """
    if not argv:
        return ()
    # First apply option-value redaction
    redacted = list(redact_option_values(argv))
    # Then apply credential and path redaction to each element
    result = [redacted[0]]  # preserve executable name for credential redaction
    for arg in redacted[1:]:
        if arg == REDACTED_MARKER:
            result.append(arg)
            continue
        cleaned = redact_credentials(arg)
        cleaned = redact_paths(cleaned)
        result.append(cleaned)
    return tuple(result)


def display_command(argv: Sequence[str]) -> str:
    """Return a redacted, shlex.quote'd representation of the command.

    Safe for logs and reports - secrets and local paths are stripped.
    """
    redacted = redact_argv(argv)
    return " ".join(shlex.quote(part) for part in redacted)
