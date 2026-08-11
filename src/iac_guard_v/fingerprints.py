"""Versioned IaC-Guard-V finding fingerprints.

The primary fingerprint is stable across line drift, scanner prose/version changes,
severity changes, and scan-root temporary-directory changes.  It deliberately changes
when an identity component changes: scanner, rule, repository-relative path, resource,
occurrence, or artifact kind.  Native scanner fingerprints remain separate evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from .models import (
    DomainError,
    Finding,
    canonical_repo_path,
    canonical_resource_scope,
    require_exact_type,
)

FINGERPRINT_ALGORITHM = "iacgv1"
_TF_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_-]*"
_TF_INDEX = r"\[(?:[0-9]+|\"(?:[^\"\\]|\\.)*\")\]"
_TERRAFORM_ADDRESS = re.compile(
    rf"{_TF_IDENTIFIER}(?:{_TF_INDEX})?(?:\.{_TF_IDENTIFIER}(?:{_TF_INDEX})?)+\Z"
)
_KUBERNETES_API_VERSION = re.compile(
    r"(?:[A-Za-z0-9.-]+/)?[A-Za-z0-9.-]+\Z"
)


def canonicalize_scan_path(raw_path: str | Path, scan_root: Path) -> str:
    """Return a scan-root-relative path and reject lexical or symlink escapes."""
    if not isinstance(scan_root, Path):
        raise DomainError("scan_root must be a pathlib.Path")
    try:
        root = scan_root.resolve(strict=True)
    except OSError as exc:
        raise DomainError(f"scan_root cannot be resolved: {exc}") from exc
    if not root.is_dir():
        raise DomainError("scan_root must be an existing directory")
    if isinstance(raw_path, Path):
        path = raw_path
    elif type(raw_path) is str and raw_path:
        path = Path(raw_path)
    else:
        raise DomainError("scanner path must be a nonblank string or pathlib.Path")
    if path.is_absolute():
        candidate = path.resolve(strict=False)
    else:
        relative = canonical_repo_path(str(path), "scanner path")
        candidate = (root / relative).resolve(strict=False)
    try:
        relative_path = candidate.relative_to(root)
    except ValueError as exc:
        raise DomainError("scanner path resolves outside scan_root") from exc
    return canonical_repo_path(relative_path.as_posix(), "scanner path")


def canonicalize_terraform_address(raw: Any) -> str:
    """Validate the scanner's canonical Terraform address representation."""
    if type(raw) is not str or not raw or raw != raw.strip():
        raise DomainError("Terraform resource address must be an exact trimmed string")
    if not _TERRAFORM_ADDRESS.fullmatch(raw):
        raise DomainError("Terraform resource address does not use canonical address syntax")
    return canonical_resource_scope(raw, "Terraform resource address")


def canonicalize_kubernetes_identity(
    api_version: Any, kind: Any, namespace: Any, name: Any
) -> str:
    """Build ``apiVersion/kind/namespace/name`` without ambiguous missing fields."""
    values = (api_version, kind, namespace, name)
    labels = ("api_version", "kind", "namespace", "name")
    normalized: list[str] = []
    for label, value in zip(labels, values):
        if type(value) is not str or not value or value != value.strip():
            raise DomainError(f"Kubernetes {label} must be an exact nonblank string")
        if label != "api_version" and "/" in value:
            raise DomainError(f"Kubernetes {label} must not contain '/'")
        normalized.append(value)
    if not _KUBERNETES_API_VERSION.fullmatch(api_version):
        raise DomainError("Kubernetes api_version is malformed")
    return canonical_resource_scope("/".join(normalized), "Kubernetes object identity")


def _fingerprint_payload(finding: Finding) -> bytes:
    require_exact_type(finding, Finding, "finding")
    payload = {
        "algorithm": FINGERPRINT_ALGORITHM,
        "artifact_kind": finding.artifact_kind.value,
        "file_path": finding.location.file_path,
        "occurrence_index": finding.occurrence_index,
        "resource_address": finding.resource_address,
        "rule_id": finding.rule_id,
        "scanner": finding.scanner,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_iacgv_fingerprint(finding: Finding) -> str:
    """Compute the versioned primary fingerprint for one exact ``Finding``."""
    digest = hashlib.sha256(_fingerprint_payload(finding)).hexdigest()
    return f"{FINGERPRINT_ALGORITHM}:{digest}"


def attach_iacgv_fingerprint(finding: Finding) -> Finding:
    """Return a copied finding with a verified IaC-Guard-V fingerprint attached."""
    require_exact_type(finding, Finding, "finding")
    expected = compute_iacgv_fingerprint(finding)
    if finding.iacgv_fingerprint and finding.iacgv_fingerprint != expected:
        raise DomainError(
            f"existing iacgv_fingerprint does not match {FINGERPRINT_ALGORITHM} payload"
        )
    return replace(finding, iacgv_fingerprint=expected)


__all__ = [
    "FINGERPRINT_ALGORITHM",
    "attach_iacgv_fingerprint",
    "canonicalize_kubernetes_identity",
    "canonicalize_scan_path",
    "canonicalize_terraform_address",
    "compute_iacgv_fingerprint",
]
