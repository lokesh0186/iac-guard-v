r"""Credential and local-path redaction for process reporting.

The functions in this module are the sole process-report redaction boundary.  They
remove credential-shaped values, adapter-declared sensitive arguments, and machine-local
absolute paths before values enter display commands, canonical reports, or logs.

Redaction is intentionally one-way and biased toward false positives.  URLs are
temporarily protected so a path-shaped URL suffix is not corrupted.  Windows examples
such as ``C:\\Users\\Alice\\secret.tf`` are written in raw docstrings so clean imports
remain valid when Python promotes invalid-escape warnings to errors.
"""
from __future__ import annotations

import ntpath
import os.path
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

REDACTED_MARKER = "[REDACTED]"
REDACTED_PATH_MARKER = "[PATH]"

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), REDACTED_MARKER),
    (re.compile(r"\b([A-Za-z0-9/+=]{40})\b"), REDACTED_MARKER),
    (
        re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.ASCII),
        r"\1" + REDACTED_MARKER,
    ),
    (re.compile(r"\b(ghp_[A-Za-z0-9]{36,})\b"), REDACTED_MARKER),
    (re.compile(r"\b(gho_[A-Za-z0-9]{36,})\b"), REDACTED_MARKER),
    (re.compile(r"\b(ghs_[A-Za-z0-9]{36,})\b"), REDACTED_MARKER),
    (re.compile(r"\b(ghr_[A-Za-z0-9]{36,})\b"), REDACTED_MARKER),
    (re.compile(r"\b(github_pat_[A-Za-z0-9_]{36,})\b"), REDACTED_MARKER),
    (
        re.compile(
            r"(?i)((?:api[_-]?key|token|password|passwd|secret|credential)[=:]\s*)"
            r"([^\s,;'\"]{8,})"
        ),
        r"\1" + REDACTED_MARKER,
    ),
    (re.compile(r"\b([0-9a-fA-F]{32,})\b"), REDACTED_MARKER),
)

SENSITIVE_OPTION_NAMES: frozenset[str] = frozenset(
    {
        "--token",
        "--password",
        "--secret",
        "--api-key",
        "--header",
        "--api_key",
        "--api-token",
        "--auth-token",
        "--access-token",
    }
)

# The closing class is conservative: whitespace, quotes, and common prose/report
# punctuation terminate a path.  Colons are retained inside POSIX path components but
# a trailing prose colon is harmlessly redacted with the path.
_POSIX_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"/(?:Users|home|mnt|private|tmp|var|opt|root|workspace)"
    r"(?:/[^\s\"'<>\[\]{}(),;]*)?"
)
_WINDOWS_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"[A-Za-z]:[\\/]"
    r"[^\s\"'<>\[\]{}(),;]*"
)
_URL_PATTERN = re.compile(r"(?:https?|file)://[^\s\"'<>]+")


def redact_credentials(text: str) -> str:
    """Remove credential-shaped values from *text*."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_paths(text: str) -> str:
    r"""Replace local absolute paths, including ``C:\\...`` and ``C:/...``.

    HTTP(S) and file URLs are restored byte-for-byte after path redaction.
    """
    url_placeholders: list[str] = []

    def save_url(match: re.Match[str]) -> str:
        url_placeholders.append(match.group(0))
        return f"__IACGV_URL_{len(url_placeholders) - 1}__"

    safe = _URL_PATTERN.sub(save_url, text)
    safe = _WINDOWS_PATH_PATTERN.sub(REDACTED_PATH_MARKER, safe)
    safe = _POSIX_PATH_PATTERN.sub(REDACTED_PATH_MARKER, safe)
    for index, url in enumerate(url_placeholders):
        safe = safe.replace(f"__IACGV_URL_{index}__", url)
    return safe


def redact_option_values(
    argv: Sequence[str],
    *,
    sensitive_option_names: Sequence[str] = (),
    sensitive_argument_indices: Sequence[int] = (),
) -> tuple[str, ...]:
    """Redact built-in and adapter-declared option values and argument indices."""
    if not argv:
        return ()
    option_names = {
        name.lower() for name in (*SENSITIVE_OPTION_NAMES, *sensitive_option_names)
    }
    sensitive_indices = frozenset(sensitive_argument_indices)
    result: list[str] = []
    redact_next = False
    for index, argument in enumerate(argv):
        if index in sensitive_indices or redact_next:
            result.append(REDACTED_MARKER)
            redact_next = False
            continue
        if "=" in argument:
            option, _ = argument.split("=", 1)
            if option.lower() in option_names:
                result.append(f"{option}={REDACTED_MARKER}")
                continue
        if argument.lower() in option_names:
            result.append(argument)
            redact_next = True
            continue
        result.append(argument)
    return tuple(result)


def _safe_tool_identity(argv0: str) -> str:
    """Return a report-safe executable identity, never an absolute machine path."""
    if os.path.isabs(argv0) or ntpath.isabs(argv0):
        return ntpath.basename(argv0.replace("/", "\\")) or "[EXECUTABLE]"
    return redact_paths(redact_credentials(argv0))


def redact_detail(text: str) -> str:
    """Redact credentials and local paths from a detail or exception string."""
    return redact_paths(redact_credentials(text))


def redact_argv(
    argv: Sequence[str],
    *,
    sensitive_option_names: Sequence[str] = (),
    sensitive_argument_indices: Sequence[int] = (),
) -> tuple[str, ...]:
    """Return report-safe argv with adapter sensitivity metadata applied."""
    if not argv:
        return ()
    option_redacted = redact_option_values(
        argv,
        sensitive_option_names=sensitive_option_names,
        sensitive_argument_indices=sensitive_argument_indices,
    )
    result = [_safe_tool_identity(option_redacted[0])]
    for argument in option_redacted[1:]:
        if argument == REDACTED_MARKER:
            result.append(argument)
        else:
            result.append(redact_detail(argument))
    return tuple(result)


def display_command(
    argv: Sequence[str],
    *,
    sensitive_option_names: Sequence[str] = (),
    sensitive_argument_indices: Sequence[int] = (),
) -> str:
    """Return a redacted, quoted representation that is never executed."""
    redacted = redact_argv(
        argv,
        sensitive_option_names=sensitive_option_names,
        sensitive_argument_indices=sensitive_argument_indices,
    )
    return " ".join(shlex.quote(part) for part in redacted)
