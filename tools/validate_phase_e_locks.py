#!/usr/bin/env python3
"""Validate Phase-E locks structurally and against a protected artifact cache."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DATE = re.compile(r"^20[0-9]{2}-[01][0-9]-[0-3][0-9]$")
EXPECTED_TOOLS = {
    "kics", "trivy", "opentofu", "terraform", "kubeconform", "tflint",
}
ARCHITECTURES = ("linux/amd64", "linux/arm64")
SIGNATURE_STATUSES = {"VERIFIED", "AVAILABLE_NOT_VERIFIED", "UNAVAILABLE"}
STATIC_RESULTS = {
    "STATIC_REVIEW",
    "STATIC_REVIEW_USER_SUPPLIED_ONLY",
    "STATIC_REVIEW_OPTIONAL_NON_SECURITY",
}
OFFICIAL_REPOSITORIES = {
    "kics": "https://github.com/Checkmarx/kics",
    "trivy": "https://github.com/aquasecurity/trivy",
    "opentofu": "https://github.com/opentofu/opentofu",
    "terraform": "https://github.com/hashicorp/terraform",
    "kubeconform": "https://github.com/yannh/kubeconform",
    "tflint": "https://github.com/terraform-linters/tflint",
}
TRIVY_CHECKS_REPOSITORY = "https://github.com/aquasecurity/trivy-checks"
KUBERNETES_SCHEMA_REPOSITORY = (
    "https://github.com/yannh/kubernetes-json-schema"
)
RUNTIME_ARGV = {
    "kics": ["version"],
    "kubeconform": ["-v"],
    "opentofu": ["version"],
    "terraform": ["version"],
    "tflint": ["--version"],
    "trivy": ["--version"],
}
RUNTIME_RECORD_CONTRACT = "phase-e-runtime-smoke-v2"
CACHE_MANIFEST_CONTRACT = "phase-e-cache-manifest-v2"
CACHE_ATTESTATION_CONTRACT = "phase-e-protected-cache-attestation-v2"
ARTIFACT_CACHE_CONTRACT = "phase-e-protected-artifact-cache-v3"
TRIVY_RUNTIME_CONTRACT = "trivy-external-checks-offline-smoke-v3"
TRIVY_NORMALIZED_SCRIPT = """set -eu
/usr/local/bin/trivy config --format json --skip-check-update . >/tmp/report.json 2>/tmp/trivy.log
sed -E 's/\"ReportID\": \"[^\"]*\"/\"ReportID\": \"00000000-0000-0000-0000-000000000000\"/;s/\"CreatedAt\": \"[^\"]*\"/\"CreatedAt\": \"1970-01-01T00:00:00Z\"/' /tmp/report.json
sed -E 's/^[^[:space:]]+[[:space:]]+//' /tmp/trivy.log >&2
"""


class LockValidationError(ValueError):
    """The Phase-E lock is incomplete, mutable, or inconsistent."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LockValidationError(message)


def _digest(value: Any, field: str, *, prefixed: bool = False) -> None:
    matcher = SHA256 if prefixed else HEX_SHA256
    _require(isinstance(value, str) and matcher.fullmatch(value) is not None,
             f"{field} must be a canonical SHA-256")


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def lock_payload_sha256(payload: dict[str, Any]) -> str:
    """Return the review seal over every field except the seal itself."""

    unsigned = copy.deepcopy(payload)
    unsigned.pop("lock_payload_sha256", None)
    return _canonical_sha256(unsigned)


def _validate_signature(signature: Any, field: str, manifest_sha: str) -> None:
    _require(isinstance(signature, dict), f"{field} must be structured evidence")
    required = {
        "method", "status", "signer_identity", "issuer", "subject_digest",
        "signature_url", "signature_sha256", "signature_cache_path",
        "verification_command",
        "verification_record_sha256", "verification_record_cache_path",
        "key_url", "key_sha256", "key_cache_path", "explanation",
    }
    _require(required <= signature.keys(), f"{field} is incomplete")
    status = signature["status"]
    _require(status in SIGNATURE_STATUSES, f"{field}.status is invalid")
    _require(signature["subject_digest"] == manifest_sha,
             f"{field}.subject_digest must bind the checksum manifest")
    if status == "UNAVAILABLE":
        _require(signature["method"] == "NONE" and
                 signature["signature_url"] is None and
                 signature["signature_sha256"] is None and
                 signature["verification_record_sha256"] is None,
                 f"{field} unavailable evidence is contradictory")
        _require(isinstance(signature["explanation"], str) and
                 signature["explanation"].strip(),
                 f"{field}.explanation is required")
        return
    _require(signature["method"] in {"OPENPGP", "SIGSTORE"},
             f"{field}.method is invalid")
    _require(isinstance(signature["signature_url"], str) and
             signature["signature_url"].startswith("https://"),
             f"{field}.signature_url must be immutable HTTPS evidence")
    _digest(signature["signature_sha256"], f"{field}.signature_sha256")
    if status == "VERIFIED":
        _require(signature["method"] == "OPENPGP",
                 f"{field} VERIFIED currently requires reproducible OpenPGP proof")
        for key in ("signer_identity", "issuer", "verification_command",
                    "verification_record_cache_path", "key_url", "key_cache_path"):
            _require(isinstance(signature[key], str) and signature[key].strip(),
                     f"{field}.{key} is required for VERIFIED evidence")
        _digest(signature["verification_record_sha256"],
                f"{field}.verification_record_sha256")
        _digest(signature["key_sha256"], f"{field}.key_sha256")
    else:
        _require(signature["verification_record_sha256"] is None,
                 f"{field} must not claim an unperformed verification record")
        for key in ("signer_identity", "issuer", "verification_command", "explanation"):
            _require(isinstance(signature[key], str) and signature[key].strip(),
                     f"{field}.{key} is required for available evidence")
        if signature["key_sha256"] is not None:
            _digest(signature["key_sha256"], f"{field}.key_sha256")
            _require(isinstance(signature["key_url"], str) and
                     signature["key_url"].startswith("https://") and
                     isinstance(signature["key_cache_path"], str),
                     f"{field} certificate evidence is incomplete")


def _validate_container(container: Any, field: str) -> None:
    _require(isinstance(container, dict), f"{field} must be an object")
    required = {
        "image", "index_digest", "architecture_digests", "execution_references",
        "supported_architectures", "cached_index_path", "verification_status",
    }
    _require(required <= container.keys(), f"{field} is incomplete")
    image = container["image"]
    _require(isinstance(image, str) and ":latest" not in image and "@" not in image,
             f"{field}.image must be a repository without a floating tag")
    _digest(container["index_digest"], f"{field}.index_digest", prefixed=True)
    supported = container["supported_architectures"]
    _require(isinstance(supported, list) and set(ARCHITECTURES) <= set(supported),
             f"{field} must support linux/amd64 and linux/arm64")
    arch_digests = container["architecture_digests"]
    _require(isinstance(arch_digests, dict) and
             set(ARCHITECTURES) <= set(arch_digests),
             f"{field} lacks an architecture child digest")
    refs = container["execution_references"]
    _require(isinstance(refs, dict) and
             {"index", *ARCHITECTURES} <= set(refs),
             f"{field} lacks a canonical execution reference")
    _require(refs["index"] == f"{image}@{container['index_digest']}",
             f"{field}.execution_references.index is not canonical")
    for arch in ARCHITECTURES:
        _digest(arch_digests[arch], f"{field}.architecture_digests.{arch}",
                prefixed=True)
        _require(refs[arch] == f"{image}@{arch_digests[arch]}",
                 f"{field}.execution_references.{arch} is not canonical")
    _require(container["verification_status"] == "CACHED_OCI_INDEX_VERIFIED",
             f"{field} must not claim an unverified OCI index")


def _validate_runtime_smoke(smoke: Any, field: str) -> None:
    _require(isinstance(smoke, dict), f"{field} must be an object")
    required = {
        "version_output", "offline_invocation_result", "output_schema_parse_result",
        "architecture", "execution_digest", "stdout_sha256", "stderr_sha256",
        "network_disabled_proof", "compatibility_status", "stdout_cache_path",
        "stderr_cache_path",
    }
    _require(required <= smoke.keys(), f"{field} is incomplete")
    _require(smoke["architecture"] in ARCHITECTURES,
             f"{field}.architecture is unsupported")
    for key in ("execution_digest", "stdout_sha256", "stderr_sha256"):
        _digest(smoke[key], f"{field}.{key}")
    _require(smoke["network_disabled_proof"] == "docker --network none",
             f"{field} lacks the network-disabled proof")
    _require(smoke["compatibility_status"] in {
        "VERSION_SMOKE_PASS_OUTPUT_CONTRACT_NOT_EXECUTED", "RUNTIME_PASS",
    }, f"{field}.compatibility_status is invalid")


def runtime_execution_digest(record: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(record)
    unsigned.pop("execution_digest", None)
    return _canonical_sha256(unsigned)


def _validate_runtime_record(
    record: Any, field: str, *, tool: str, version: str,
    container: dict[str, Any], architecture: str,
) -> None:
    _require(isinstance(record, dict), f"{field} must be an object")
    required = {
        "contract", "tool", "version", "image_index_digest",
        "image_architecture_digest", "execution_reference", "architecture",
        "argv", "environment_allowlist", "network_mode", "filesystem_mode",
        "exit_code", "stdout_sha256", "stderr_sha256", "version_output",
        "output_schema_result", "duration_ns", "runner_build_identity",
        "stdout_cache_path", "stderr_cache_path", "execution_digest",
    }
    _require(set(record) == required, f"{field} fields are not closed")
    _require(record["contract"] == RUNTIME_RECORD_CONTRACT,
             f"{field}.contract is invalid")
    _require(record["tool"] == tool and record["version"] == version,
             f"{field} tool/version differs from the selected lock")
    _require(record["architecture"] == architecture,
             f"{field}.architecture is inconsistent")
    _require(record["image_index_digest"] == container["index_digest"] and
             record["image_architecture_digest"] ==
             container["architecture_digests"][architecture] and
             record["execution_reference"] ==
             container["execution_references"][architecture],
             f"{field} is not bound to the selected OCI identities")
    _require(record["argv"] == RUNTIME_ARGV[tool],
             f"{field}.argv differs from the closed smoke contract")
    _require(record["environment_allowlist"] == ["HOME=/tmp", "TMPDIR=/tmp"],
             f"{field}.environment_allowlist is not closed")
    _require(record["network_mode"] == "none" and
             record["filesystem_mode"] ==
             "read-only-root,tmpfs-/tmp,no-host-mounts",
             f"{field} lacks network/filesystem isolation")
    _require(record["exit_code"] == 0 and
             type(record["duration_ns"]) is int and record["duration_ns"] > 0,
             f"{field} did not complete successfully")
    for name in ("stdout_sha256", "stderr_sha256", "runner_build_identity"):
        _digest(record[name], f"{field}.{name}")
    _require(isinstance(record["version_output"], str) and
             version in record["version_output"],
             f"{field}.version_output disagrees with the selected version")
    _require(record["output_schema_result"] ==
             "VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION",
             f"{field} overclaims output compatibility")
    _digest(record["execution_digest"], f"{field}.execution_digest")
    _require(record["execution_digest"] == runtime_execution_digest(record),
             f"{field}.execution_digest is not canonical")


def validate_lock(payload: Any) -> None:
    """Raise unless *payload* is the complete sealed E0.1 lock graph."""

    _require(isinstance(payload, dict), "lock must be an object")
    _require(payload.get("lock_contract") == "phase-e-verified-tool-locks-v4",
             "unexpected lock contract")
    _require(payload.get("architectures") == list(ARCHITECTURES),
             "architecture order or set differs from the reviewed matrix")
    seal = payload.get("lock_payload_sha256")
    _digest(seal, "lock_payload_sha256")
    _require(seal == lock_payload_sha256(payload),
             "lock_payload_sha256 does not seal the canonical lock graph")
    _require(payload.get("artifact_cache_contract") == ARTIFACT_CACHE_CONTRACT,
             "artifact cache contract is missing")
    claims = payload.get("verification_claims")
    _require(isinstance(claims, dict) and set(claims) == {
        "schema", "source", "runtime",
    }, "schema, source and runtime claims must be independent")
    _require(
        claims == {
            "schema": "REQUIRES_SCHEMA_VALIDATION",
            "source": "REQUIRES_PROTECTED_CACHE_VERIFICATION",
            "runtime": "REQUIRES_REEXECUTION_OR_SIGNED_ATTESTATION",
        },
        "lock verification requirements are incomplete or overstated",
    )
    cache_attestation = payload.get("protected_cache_attestation")
    _require(isinstance(cache_attestation, dict) and set(cache_attestation) == {
        "contract", "manifest_path", "manifest_sha256", "manifest_root",
        "attestation_path", "attestation_sha256", "signature_path",
        "signature_sha256", "public_key_path", "public_key_sha256",
        "signature_method", "signer_identity",
    }, "protected cache attestation is incomplete")
    _require(cache_attestation["contract"] == CACHE_ATTESTATION_CONTRACT and
             cache_attestation["signature_method"] == "ED25519_OPENSSL",
             "protected cache attestation contract is invalid")
    for name in (
        "manifest_sha256", "manifest_root", "attestation_sha256",
        "signature_sha256", "public_key_sha256",
    ):
        _digest(cache_attestation[name], f"protected_cache_attestation.{name}")

    tools = payload.get("tools")
    _require(isinstance(tools, dict) and set(tools) == EXPECTED_TOOLS,
             "tool set must contain exactly the six reviewed Phase-E tools")
    for name in sorted(EXPECTED_TOOLS):
        tool = tools[name]
        _require(isinstance(tool, dict), f"tools.{name} must be an object")
        required = {
            "version", "release", "archives", "container", "license",
            "invocation_contract", "output_schema_fixture", "offline_requirements",
            "upgrade_policy", "compatibility_test", "runtime_smoke",
        }
        _require(required <= tool.keys(), f"tools.{name} is incomplete")
        _require("signature_attestation" not in tool,
                 f"tools.{name} uses obsolete free-text signature evidence")

        release = tool["release"]
        _require(isinstance(release, dict) and {
            "repository", "tag", "commit", "tag_refs_cache_path",
            "tag_refs_sha256", "verification_status",
        } <= release.keys(), f"tools.{name}.release is incomplete")
        _require(release["repository"] == OFFICIAL_REPOSITORIES[name],
                 f"tools.{name}.release.repository is not the reviewed official source")
        _require(COMMIT.fullmatch(release["commit"]) is not None,
                 f"tools.{name}.release.commit must be a full commit")
        _digest(release["tag_refs_sha256"],
                f"tools.{name}.release.tag_refs_sha256")
        _require(release["verification_status"] == "CACHED_TAG_RELATION_VERIFIED",
                 f"tools.{name}.release is not source-verifying")

        archives = tool["archives"]
        _require(isinstance(archives, dict) and set(ARCHITECTURES) <= set(archives),
                 f"tools.{name}.archives lacks a required architecture")
        for arch in ARCHITECTURES:
            archive = archives[arch]
            field = f"tools.{name}.archives.{arch}"
            _require(isinstance(archive, dict) and {
                "name", "sha256", "cache_path", "acquisition",
                "verification_status",
            } <= archive.keys(), f"{field} is incomplete")
            _digest(archive["sha256"], f"{field}.sha256")
            acquisition = archive["acquisition"]
            _require(isinstance(acquisition, dict) and {
                "immutable_download_url", "retrieval_date", "upstream_subject_identity",
                "checksum_manifest", "signature",
            } <= acquisition.keys(), f"{field}.acquisition is incomplete")
            _require(acquisition["immutable_download_url"].startswith("https://") and
                     tool["version"] in acquisition["immutable_download_url"],
                     f"{field} download URL is not version-pinned")
            _require(DATE.fullmatch(acquisition["retrieval_date"]) is not None,
                     f"{field}.retrieval_date is invalid")
            manifest = acquisition["checksum_manifest"]
            _require(isinstance(manifest, dict) and {
                "url", "sha256", "cache_path",
            } <= manifest.keys(), f"{field}.checksum_manifest is incomplete")
            _digest(manifest["sha256"], f"{field}.checksum_manifest.sha256")
            _validate_signature(acquisition["signature"],
                                f"{field}.signature", manifest["sha256"])
            _require(archive["verification_status"] in {
                "CHECKSUM_AND_SIGNATURE_VERIFIED",
                "CHECKSUM_VERIFIED_SIGNATURE_AVAILABLE_NOT_VERIFIED",
                "CHECKSUM_VERIFIED_SIGNATURE_UNAVAILABLE",
            }, f"{field}.verification_status is invalid")

        _validate_container(tool["container"], f"tools.{name}.container")
        license_record = tool["license"]
        _require(isinstance(license_record, dict) and {
            "id", "sha256", "url", "cache_path",
        } <= license_record.keys(), f"tools.{name}.license is incomplete")
        _digest(license_record["sha256"], f"tools.{name}.license.sha256")
        fixture = tool["output_schema_fixture"]
        _require(isinstance(fixture, dict) and {
            "path", "sha256", "source", "cache_path",
        } <= fixture.keys(), f"tools.{name}.output_schema_fixture is incomplete")
        _digest(fixture["sha256"], f"tools.{name}.output_schema_fixture.sha256")
        compatibility = tool["compatibility_test"]
        _require(isinstance(compatibility, dict) and
                 compatibility.get("result") in STATIC_RESULTS,
                 f"tools.{name}.compatibility_test must remain STATIC_REVIEW")
        _validate_runtime_smoke(tool["runtime_smoke"],
                                f"tools.{name}.runtime_smoke")
        records = tool.get("runtime_records")
        _require(isinstance(records, dict) and set(records) == set(ARCHITECTURES),
                 f"tools.{name}.runtime_records must cover both architectures")
        for architecture in ARCHITECTURES:
            _validate_runtime_record(
                records[architecture],
                f"tools.{name}.runtime_records.{architecture}",
                tool=name, version=tool["version"],
                container=tool["container"], architecture=architecture,
            )

    _require(tools["terraform"].get("distribution_mode") ==
             "USER_SUPPLIED_ONLY_NEVER_BUNDLED",
             "Terraform must remain user-supplied and unbundled")
    _require(tools["tflint"].get("security_role") == "OPTIONAL_NON_SECURITY",
             "TFLint must remain optional and non-security")
    _require(tools["kics"]["version"] == "2.1.20",
             "the reviewed KICS runtime selection is 2.1.20")

    schema = tools["kubeconform"].get("schema_bundle")
    _require(isinstance(schema, dict) and {
        "repository", "commit", "content_digest", "license",
        "supported_kubernetes_versions", "strict_tree", "non_strict_tree",
        "crd_policy", "offline_cache_layout", "cache_root",
    } <= schema.keys(), "kubeconform schema bundle is incomplete")
    _require(schema["repository"] == KUBERNETES_SCHEMA_REPOSITORY,
             "kubeconform schema source repository is not official")
    source_evidence = schema.get("source_evidence")
    _require(isinstance(source_evidence, dict) and set(source_evidence) == {
        "commit_object_cache_path", "commit_object_sha256",
        "ls_tree_cache_path", "ls_tree_sha256", "root_tree_cache_path",
        "root_tree_sha256", "extracted_file_count", "license_evidence",
    }, "kubeconform schema source evidence is incomplete")
    for name in ("commit_object_sha256", "ls_tree_sha256", "root_tree_sha256"):
        _digest(source_evidence[name], f"kubeconform.schema_bundle.{name}")
    _require(source_evidence["extracted_file_count"] == 2608 and
             source_evidence["license_evidence"] ==
             "NO_ROOT_LICENSE_FILE_IN_LOCKED_TREE",
             "kubeconform schema inventory/licence evidence is incomplete")
    _require(COMMIT.fullmatch(schema["commit"]) is not None,
             "kubeconform schema commit is invalid")
    _digest(schema["content_digest"], "kubeconform.schema_bundle.content_digest")
    for tree_name in ("strict_tree", "non_strict_tree"):
        tree = schema[tree_name]
        _require(isinstance(tree, dict) and {
            "relative_path", "manifest_root", "file_count", "total_bytes",
        } <= tree.keys(), f"kubeconform.schema_bundle.{tree_name} is incomplete")
        _digest(tree["manifest_root"],
                f"kubeconform.schema_bundle.{tree_name}.manifest_root")
        _require(tree["file_count"] > 0 and tree["total_bytes"] > 0,
                 f"kubeconform.schema_bundle.{tree_name} is empty")

    checks = tools["trivy"].get("checks")
    _require(isinstance(checks, dict) and {
        "external_repository", "external_manifest_digest", "cached_manifest_path",
        "external_layer_digest", "external_layer_cache_path",
        "external_source_commit", "embedded_checks_identity", "cache_identity",
        "selected_source", "fallback_used", "source_identity_rule",
        "offline_verification",
    } <= checks.keys(), "Trivy checks identity is incomplete")
    _require(checks["external_repository"].endswith(":2.2.0"),
             "Trivy checks must use exact version 2.2.0")
    _require(checks.get("source_repository") == TRIVY_CHECKS_REPOSITORY and
             checks.get("source_tag") == "v2.2.0",
             "Trivy checks source repository/tag is not official and exact")
    _digest(checks.get("source_tag_refs_sha256"),
            "tools.trivy.checks.source_tag_refs_sha256")
    _require(isinstance(checks.get("source_tag_refs_cache_path"), str),
             "Trivy checks source ref evidence is missing")
    _digest(checks["external_manifest_digest"],
            "tools.trivy.checks.external_manifest_digest", prefixed=True)
    _digest(checks["external_layer_digest"],
            "tools.trivy.checks.external_layer_digest", prefixed=True)
    _require(checks["selected_source"] == "external" and
             checks["fallback_used"] is False,
             "Trivy external checks fallback is prohibited")
    offline = checks["offline_verification"]
    _require(isinstance(offline, dict) and
             offline.get("status") == "RUNTIME_PASS" and
             offline.get("fallback_used") is False,
             "Trivy external checks lack an offline no-fallback runtime proof")
    runtime_records = offline.get("runtime_records")
    _require(isinstance(runtime_records, dict) and
             set(runtime_records) == set(ARCHITECTURES),
             "Trivy offline verification must cover both architectures")
    for architecture, record in runtime_records.items():
        _require(isinstance(record, dict) and
                 record.get("contract") == TRIVY_RUNTIME_CONTRACT and
                 record.get("architecture") == architecture and
                 record.get("execution_reference") ==
                 tools["trivy"]["container"]["execution_references"][architecture] and
                 record.get("argv") == ["/bin/sh", "-c", TRIVY_NORMALIZED_SCRIPT] and
                 record.get("environment_allowlist") == ["TRIVY_CACHE_DIR=/cache"] and
                 record.get("checks_manifest_digest") ==
                 checks["external_manifest_digest"] and
                 record.get("layer_digest") == checks["external_layer_digest"] and
                 record.get("cache_identity") == checks["cache_identity"] and
                 record.get("fallback_used") is False and
                 record.get("network_mode") == "none" and
                 record.get("skip_check_update") is True and
                 record.get("exit_code") == 0 and
                 record.get("output_schema_result") == "PASS_SCHEMA_VERSION_2",
                 f"Trivy offline {architecture} record is contradictory")
        for digest_name in (
            "output_sha256", "stderr_sha256", "canonical_output_sha256",
            "execution_digest",
            "runner_build_identity",
        ):
            _digest(record.get(digest_name),
                    f"Trivy offline {architecture}.{digest_name}")
        _require(
            record["execution_digest"] == trivy_offline_execution_digest(record),
            f"Trivy offline {architecture} execution digest is not canonical",
        )

    base = payload.get("hardened_container_base")
    _validate_container(base, "hardened_container_base")


def _safe_cache_file(cache: Path, relative: str) -> Path:
    _require(isinstance(relative, str) and relative and not relative.startswith("/"),
             "artifact cache path must be relative")
    candidate = cache / relative
    resolved_cache = cache.resolve(strict=True)
    try:
        resolved_parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise LockValidationError(f"missing artifact cache parent: {relative}") from exc
    _require(resolved_parent == resolved_cache or resolved_cache in resolved_parent.parents,
             f"artifact cache path escapes cache root: {relative}")
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise LockValidationError(f"cached artifact is missing: {relative}") from exc
    _require(stat.S_ISREG(metadata.st_mode),
             f"cached artifact is missing or unsafe: {relative}")
    return candidate


def _hash_regular_file(path: Path, metadata: os.stat_result) -> str:
    """Hash one lstat-bound regular file without following a replacement symlink."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LockValidationError(f"protected cache file is unreadable: {path}") from exc
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        _require(
            stat.S_ISREG(opened.st_mode)
            and (opened.st_dev, opened.st_ino, opened.st_size)
            == (metadata.st_dev, metadata.st_ino, metadata.st_size),
            f"protected cache entry changed during inventory: {path}",
        )
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        _require(
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns),
            f"protected cache file changed while hashing: {path}",
        )
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def physical_cache_inventory(cache: Path) -> list[dict[str, Any]]:
    """Return one complete no-follow cache inventory; unsafe entry types are fatal."""

    root = Path(cache)
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise LockValidationError("protected cache root is unavailable") from exc
    _require(
        stat.S_ISDIR(root_metadata.st_mode) and not stat.S_ISLNK(root_metadata.st_mode),
        "protected cache root must be a real directory",
    )
    entries: list[dict[str, Any]] = []

    def inspect(directory: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise LockValidationError(
                f"protected cache directory is unreadable: {directory}"
            ) from exc
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise LockValidationError(
                    f"protected cache entry is unreadable: {relative}"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise LockValidationError(
                    f"protected cache contains forbidden symlink: {relative}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                entries.append({
                    "path": relative, "kind": "DIRECTORY",
                    "size": None, "sha256": None,
                })
                inspect(path)
            elif stat.S_ISREG(metadata.st_mode):
                entries.append({
                    "path": relative, "kind": "REGULAR_FILE",
                    "size": metadata.st_size,
                    "sha256": _hash_regular_file(path, metadata),
                })
            else:
                raise LockValidationError(
                    f"protected cache contains forbidden non-regular entry: {relative}"
                )

    inspect(root)
    return entries


def _verify_file(cache: Path, relative: str, expected: str, field: str) -> Path:
    path = _safe_cache_file(cache, relative)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    _require(actual == expected.removeprefix("sha256:"),
             f"{field} cached bytes do not match the lock")
    return path


def _manifest_contains(manifest: Path, archive_name: str, digest: str) -> bool:
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == digest and \
                parts[-1].lstrip("*") == archive_name:
            return True
    return False


def _parse_tag_refs(raw: str, field: str) -> dict[str, str]:
    refs: dict[str, str] = {}
    for line in raw.splitlines():
        parts = line.split("\t")
        _require(len(parts) == 2 and COMMIT.fullmatch(parts[0]) is not None and
                 parts[1].startswith("refs/tags/"),
                 f"{field} contains a malformed cached ref")
        _require(parts[1] not in refs, f"{field} contains a duplicate cached ref")
        refs[parts[1]] = parts[0]
    return refs


def _verify_tag_relation(raw: str, tag: str, commit: str, field: str) -> None:
    refs = _parse_tag_refs(raw, field)
    exact = f"refs/tags/{tag}"
    peeled = f"{exact}^{{}}"
    _require(exact in refs, f"{field} lacks the exact selected tag ref")
    if peeled in refs:
        _require(refs[peeled] == commit and refs[exact] != commit,
                 f"{field} annotated tag does not peel to the locked commit")
    else:
        _require(refs[exact] == commit,
                 f"{field} lightweight tag does not equal the locked commit")


def _verify_openpgp(cache: Path, signature: dict[str, Any], manifest: Path,
                    field: str) -> None:
    sig = _verify_file(cache, signature["signature_cache_path"],
                       signature["signature_sha256"], f"{field}.signature")
    key = _verify_file(cache, signature["key_cache_path"],
                       signature["key_sha256"], f"{field}.key")
    record = _verify_file(cache, signature["verification_record_cache_path"],
                          signature["verification_record_sha256"],
                          f"{field}.verification_record")
    with tempfile.TemporaryDirectory(prefix="iacgv-e01-gpg-") as home:
        os.chmod(home, 0o700)
        imported = subprocess.run(
            ["gpg", "--homedir", home, "--batch", "--import", str(key)],
            check=False, capture_output=True, text=True,
        )
        _require(imported.returncode == 0, f"{field} key import failed")
        verified = subprocess.run(
            ["gpg", "--homedir", home, "--batch", "--status-fd", "1",
             "--verify", str(sig), str(manifest)],
            check=False, capture_output=True, text=True,
        )
        _require(verified.returncode == 0 and "[GNUPG:] VALIDSIG" in verified.stdout,
                 f"{field} OpenPGP signature did not verify")
        _require(signature["signer_identity"] in verified.stdout + verified.stderr,
                 f"{field} signer identity differs from the lock")
        _require(b"VALIDSIG" in record.read_bytes(),
                 f"{field} cached verification record is not a valid proof")


def _tree_manifest(root: Path) -> tuple[str, int, int]:
    _require(root.exists() and root.is_dir() and not root.is_symlink(),
             f"schema tree is missing or unsafe: {root.name}")
    digest = hashlib.sha256()
    count = 0
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        _require(not path.is_symlink(), f"schema tree contains symlink: {path}")
        if path.is_file():
            data = path.read_bytes()
            relative = path.relative_to(root).as_posix()
            file_digest = hashlib.sha256(data).hexdigest()
            digest.update(f"{relative}\0{len(data)}\0{file_digest}\n".encode())
            count += 1
            total += len(data)
    return digest.hexdigest(), count, total


def _git_object_sha1(kind: str, data: bytes) -> str:
    header = f"{kind} {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _repository_file(relative: str) -> Path:
    root = Path(__file__).resolve().parents[1]
    path = root / relative
    _require(path.exists() and path.is_file() and not path.is_symlink(),
             f"repository attestation file is missing or unsafe: {relative}")
    return path


def _verify_cache_attestation(payload: dict[str, Any], cache: Path) -> None:
    record = payload["protected_cache_attestation"]
    manifest_path = _repository_file(record["manifest_path"])
    attestation_path = _repository_file(record["attestation_path"])
    signature_path = _repository_file(record["signature_path"])
    public_key_path = _repository_file(record["public_key_path"])
    for path, field in (
        (manifest_path, "manifest_sha256"),
        (attestation_path, "attestation_sha256"),
        (signature_path, "signature_sha256"),
        (public_key_path, "public_key_sha256"),
    ):
        _require(hashlib.sha256(path.read_bytes()).hexdigest() == record[field],
                 f"protected cache {field} differs from repository evidence")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _require(manifest.get("contract") == CACHE_MANIFEST_CONTRACT and
             isinstance(manifest.get("entries"), list),
             "protected cache manifest is malformed")
    _require(_canonical_sha256(manifest["entries"]) == record["manifest_root"],
             "protected cache manifest root is not canonical")
    expected = {item["path"]: item for item in manifest["entries"]}
    _require(len(expected) == len(manifest["entries"]),
             "protected cache manifest contains duplicate paths")
    actual_entries = physical_cache_inventory(cache)
    _require(actual_entries == manifest["entries"],
             "protected cache physical inventory differs from signed manifest")
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    _require(attestation["manifest_root"] == record["manifest_root"] and
             attestation["manifest_sha256"] == record["manifest_sha256"] and
             attestation["signer_identity"] == record["signer_identity"],
             "protected cache attestation does not bind the selected manifest")
    verified = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
         "-inkey", str(public_key_path), "-sigfile", str(signature_path),
         "-in", str(attestation_path)],
        check=False, capture_output=True, text=True,
    )
    _require(verified.returncode == 0,
             "protected cache Ed25519 attestation signature did not verify")


def verify_cached_artifacts(payload: dict[str, Any], artifact_cache: Path) -> None:
    """Verify real release, OCI, fixture, licence, schema, and checks bytes."""

    validate_lock(payload)
    cache = artifact_cache.resolve(strict=True)
    _verify_cache_attestation(payload, cache)
    tools = payload["tools"]
    for name in sorted(EXPECTED_TOOLS):
        tool = tools[name]
        release = tool["release"]
        refs = _verify_file(cache, release["tag_refs_cache_path"],
                            release["tag_refs_sha256"], f"tools.{name}.release")
        _verify_tag_relation(
            refs.read_text(encoding="utf-8"), release["tag"], release["commit"],
            f"tools.{name}.release",
        )

        verified_manifests: set[str] = set()
        for arch in ARCHITECTURES:
            archive = tool["archives"][arch]
            _verify_file(cache, archive["cache_path"], archive["sha256"],
                         f"tools.{name}.archives.{arch}")
            acquisition = archive["acquisition"]
            manifest_record = acquisition["checksum_manifest"]
            manifest = _verify_file(cache, manifest_record["cache_path"],
                                    manifest_record["sha256"],
                                    f"tools.{name}.checksum_manifest")
            _require(_manifest_contains(manifest, archive["name"], archive["sha256"]),
                     f"tools.{name}.{arch} is absent from the checksum manifest")
            signature = acquisition["signature"]
            if signature["status"] == "VERIFIED" and \
                    manifest_record["cache_path"] not in verified_manifests:
                _verify_openpgp(cache, signature, manifest,
                                f"tools.{name}.signature")
                verified_manifests.add(manifest_record["cache_path"])
            elif signature["status"] == "AVAILABLE_NOT_VERIFIED":
                _verify_file(cache, signature["signature_cache_path"],
                             signature["signature_sha256"],
                             f"tools.{name}.available_signature")
                if signature["key_sha256"] is not None:
                    _verify_file(cache, signature["key_cache_path"],
                                 signature["key_sha256"],
                                 f"tools.{name}.available_certificate")

        _verify_file(cache, tool["license"]["cache_path"],
                     tool["license"]["sha256"], f"tools.{name}.license")
        _verify_file(cache, tool["output_schema_fixture"]["cache_path"],
                     tool["output_schema_fixture"]["sha256"],
                     f"tools.{name}.output_schema_fixture")
        smoke = tool["runtime_smoke"]
        _verify_file(cache, smoke["stdout_cache_path"], smoke["stdout_sha256"],
                     f"tools.{name}.runtime_smoke.stdout")
        _verify_file(cache, smoke["stderr_cache_path"], smoke["stderr_sha256"],
                     f"tools.{name}.runtime_smoke.stderr")
        for architecture, runtime in tool["runtime_records"].items():
            stdout = _verify_file(
                cache, runtime["stdout_cache_path"], runtime["stdout_sha256"],
                f"tools.{name}.runtime_records.{architecture}.stdout",
            )
            _verify_file(
                cache, runtime["stderr_cache_path"], runtime["stderr_sha256"],
                f"tools.{name}.runtime_records.{architecture}.stderr",
            )
            actual_version = stdout.read_text(encoding="utf-8").strip()
            _require(actual_version == runtime["version_output"] and
                     tool["version"] in actual_version,
                     f"tools.{name}.{architecture} cached version output differs")

        container = tool["container"]
        raw = _verify_file(cache, container["cached_index_path"],
                           container["index_digest"], f"tools.{name}.container")
        index = json.loads(raw.read_text(encoding="utf-8"))
        children = {
            f"{item.get('platform', {}).get('os')}/{item.get('platform', {}).get('architecture')}":
            item.get("digest") for item in index.get("manifests", [])
        }
        for arch in ARCHITECTURES:
            _require(children.get(arch) == container["architecture_digests"][arch],
                     f"tools.{name}.container does not bind {arch} to the index")

    base = payload["hardened_container_base"]
    raw_base = _verify_file(cache, base["cached_index_path"], base["index_digest"],
                            "hardened_container_base")
    base_index = json.loads(raw_base.read_text(encoding="utf-8"))
    base_children = {
        f"{item.get('platform', {}).get('os')}/{item.get('platform', {}).get('architecture')}":
        item.get("digest") for item in base_index.get("manifests", [])
    }
    for arch in ARCHITECTURES:
        _require(base_children.get(arch) == base["architecture_digests"][arch],
                 f"hardened base does not bind {arch} to the index")

    schema = tools["kubeconform"]["schema_bundle"]
    schema_root = cache / schema["cache_root"]
    components = []
    for name in ("non_strict_tree", "strict_tree"):
        tree = schema[name]
        actual = _tree_manifest(schema_root / tree["relative_path"])
        expected = (tree["manifest_root"], tree["file_count"], tree["total_bytes"])
        _require(actual == expected, f"kubeconform {name} bytes differ from lock")
        components.append((tree["relative_path"], *actual))
    bundle_hash = hashlib.sha256()
    for relative, digest, count, total in sorted(components):
        bundle_hash.update(f"{relative}\0{digest}\0{count}\0{total}\n".encode())
    _require(bundle_hash.hexdigest() == schema["content_digest"],
             "kubeconform schema bundle content digest differs")
    source = schema["source_evidence"]
    commit_object = _verify_file(
        cache, source["commit_object_cache_path"], source["commit_object_sha256"],
        "kubeconform schema commit object",
    ).read_bytes()
    _require(_git_object_sha1("commit", commit_object) == schema["commit"],
             "kubeconform schema commit object identity differs")
    root_tree = _verify_file(
        cache, source["root_tree_cache_path"], source["root_tree_sha256"],
        "kubeconform schema root tree",
    ).read_text(encoding="utf-8").strip()
    tree_match = re.search(r"^tree ([0-9a-f]{40})$", commit_object.decode().splitlines()[0])
    _require(tree_match is not None and tree_match.group(1) == root_tree,
             "kubeconform cached root-tree evidence does not bind the commit tree")
    ls_tree_path = _verify_file(
        cache, source["ls_tree_cache_path"], source["ls_tree_sha256"],
        "kubeconform schema selected tree",
    )
    selected: dict[str, str] = {}
    for line in ls_tree_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"100644 blob ([0-9a-f]{40})\t(.+)", line)
        _require(match is not None, "kubeconform schema tree contains a non-file entry")
        selected[match.group(2)] = match.group(1)
    _require(len(selected) == source["extracted_file_count"],
             "kubeconform selected tree count differs")
    extracted: dict[str, Path] = {}
    for tree_name in ("non_strict_tree", "strict_tree"):
        relative_root = schema[tree_name]["relative_path"]
        for path in (schema_root / relative_root).rglob("*"):
            if path.is_file() and not path.is_symlink():
                extracted[f"{relative_root}/{path.relative_to(schema_root / relative_root).as_posix()}"] = path
    _require(set(extracted) == set(selected),
             "kubeconform extracted schema paths differ from the locked Git tree")
    for relative, path in extracted.items():
        _require(_git_object_sha1("blob", path.read_bytes()) == selected[relative],
                 f"kubeconform extracted schema blob differs: {relative}")
    _require(not any(
        path.upper() in {"LICENSE", "LICENSE.TXT", "COPYING"}
        for path in selected
    ), "kubeconform licence evidence contradicts the locked source tree")

    checks = tools["trivy"]["checks"]
    checks_refs = _verify_file(
        cache, checks["source_tag_refs_cache_path"],
        checks["source_tag_refs_sha256"], "Trivy checks source tag",
    )
    _verify_tag_relation(
        checks_refs.read_text(encoding="utf-8"), checks["source_tag"],
        checks["external_source_commit"], "Trivy checks source tag",
    )
    checks_manifest = _verify_file(cache, checks["cached_manifest_path"],
                                   checks["external_manifest_digest"],
                                   "trivy checks OCI manifest")
    checks_json = json.loads(checks_manifest.read_text(encoding="utf-8"))
    layers = [layer.get("digest") for layer in checks_json.get("layers", [])]
    _require(checks["external_layer_digest"] in layers,
             "Trivy checks layer is absent from the OCI manifest")
    _verify_file(cache, checks["external_layer_cache_path"],
                 checks["external_layer_digest"], "Trivy checks layer")
    offline = checks["offline_verification"]
    runtime_record_path = _verify_file(cache, offline["record_cache_path"],
                                       offline["record_sha256"],
                                       "Trivy offline verification record")
    runtime = json.loads(runtime_record_path.read_text(encoding="utf-8"))
    _require(runtime["checks_manifest_digest"] == checks["external_manifest_digest"] and
             runtime["fallback_used"] is False and runtime["network_mode"] == "none" and
             runtime["skip_check_update"] is True and runtime["exit_code"] == 0,
             "Trivy offline runtime proof is contradictory")
    metadata_path = _safe_cache_file(cache, offline["cache_metadata_path"])
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    _require(metadata.get("Digest") == checks["external_manifest_digest"],
             "Trivy cache selected a different checks bundle")
    output = _verify_file(cache, offline["output_cache_path"],
                          runtime["output_sha256"], "Trivy offline JSON output")
    output_json = json.loads(output.read_text(encoding="utf-8"))
    _require(output_json.get("SchemaVersion") == 2 and
             output_json.get("Trivy", {}).get("Version") == tools["trivy"]["version"],
             "Trivy offline output schema/version proof differs")
    stderr = _verify_file(cache, offline["stderr_cache_path"],
                          runtime["stderr_sha256"], "Trivy offline stderr")
    stderr_text = stderr.read_text(encoding="utf-8")
    _require("loading from existing cache" in stderr_text and
             "Downloading the checks bundle" not in stderr_text,
             "Trivy checks were not proven to load offline from the exact cache")


def trivy_offline_execution_digest(record: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(record)
    unsigned.pop("execution_digest", None)
    return _canonical_sha256(unsigned)


def _current_runtime_record(
    locked: dict[str, Any], result: Any, duration_ns: int, *, trivy: bool,
) -> dict[str, Any]:
    """Bind the current process bytes and duration to one canonical observation."""

    observed = copy.deepcopy(locked)
    observed["duration_ns"] = duration_ns
    stdout_name = "output_sha256" if trivy else "stdout_sha256"
    observed[stdout_name] = hashlib.sha256(result.stdout).hexdigest()
    observed["stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
    if trivy:
        try:
            decoded = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LockValidationError("current Trivy output is not strict JSON") from exc
        observed["canonical_output_sha256"] = _canonical_sha256(decoded)
        observed["execution_digest"] = trivy_offline_execution_digest(observed)
    else:
        observed["version_output"] = result.stdout.decode("utf-8").strip()
        observed["execution_digest"] = runtime_execution_digest(observed)
    return observed


def _require_current_runtime_matches(
    locked: dict[str, Any], observed: dict[str, Any], field: str,
) -> None:
    """Reject a different current execution; duration/digest identify the new run."""

    ignored = {"duration_ns", "execution_digest"}
    _require(
        {name: value for name, value in observed.items() if name not in ignored}
        == {name: value for name, value in locked.items() if name not in ignored},
        f"{field} current stdout/stderr or execution contract differs from the lock",
    )


def _docker_version() -> str:
    result = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        check=False, capture_output=True, text=True,
    )
    _require(result.returncode == 0 and result.stdout.strip(),
             "Docker engine is unavailable for runtime verification")
    return result.stdout.strip()


def verify_runtime(
    payload: dict[str, Any], artifact_cache: Path,
) -> dict[str, dict[str, Any]]:
    """Re-execute both-architecture version smokes and Trivy offline checks."""

    validate_lock(payload)
    cache = artifact_cache.resolve(strict=True)
    _docker_version()
    runner_identity = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    _verify_cache_attestation(payload, cache)
    observations: dict[str, dict[str, Any]] = {}
    for tool_name in sorted(EXPECTED_TOOLS):
        tool = payload["tools"][tool_name]
        for architecture in ARCHITECTURES:
            record = tool["runtime_records"][architecture]
            _require(record["runner_build_identity"] == runner_identity,
                     f"{tool_name} runtime record uses another runner build")
            command = [
                "docker", "run", "--rm", "--pull", "never",
                "--platform", architecture, "--network", "none", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "128", "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m", "-e", "HOME=/tmp", "-e",
                "TMPDIR=/tmp", record["execution_reference"], *record["argv"],
            ]
            started = time.monotonic_ns()
            result = subprocess.run(command, check=False, capture_output=True)
            duration = time.monotonic_ns() - started
            observed = _current_runtime_record(record, result, duration, trivy=False)
            _require(result.returncode == record["exit_code"] == 0,
                     f"{tool_name} {architecture} runtime smoke failed")
            _require_current_runtime_matches(
                record, observed, f"{tool_name} {architecture} runtime smoke"
            )
            observations[f"{tool_name}:{architecture}"] = observed
            _verify_cache_attestation(payload, cache)

    checks = payload["tools"]["trivy"]["checks"]
    _verify_cache_attestation(payload, cache)
    for architecture in ARCHITECTURES:
        record = checks["offline_verification"]["runtime_records"][architecture]
        _require(record["runner_build_identity"] == runner_identity and
                 record["execution_digest"] ==
                 trivy_offline_execution_digest(record),
                 f"Trivy {architecture} offline runtime record is not canonical")
        reference = payload["tools"]["trivy"]["container"][
            "execution_references"
        ][architecture]
        command = [
            "docker", "run", "--rm", "--pull", "never",
            "--platform", architecture, "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "-e", "TRIVY_CACHE_DIR=/cache",
            "-v", f"{cache / 'runtime-v2/trivy-cache'}:/cache:ro",
            "-v", f"{cache / 'runtime-v2/trivy-input'}:/work:ro",
            "-w", "/work", "--entrypoint", "/bin/sh", reference,
            "-c", TRIVY_NORMALIZED_SCRIPT,
        ]
        started = time.monotonic_ns()
        result = subprocess.run(command, check=False, capture_output=True)
        duration = time.monotonic_ns() - started
        observed = _current_runtime_record(record, result, duration, trivy=True)
        _require_current_runtime_matches(
            record, observed, f"Trivy {architecture} offline runtime"
        )
        try:
            output = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LockValidationError(
                f"Trivy {architecture} offline output is not JSON"
            ) from exc
        stderr = result.stderr.decode("utf-8", errors="strict")
        _require(result.returncode == 0 and output.get("SchemaVersion") == 2 and
                 output.get("Trivy", {}).get("Version") ==
                 payload["tools"]["trivy"]["version"] and
                 "loading from existing cache" in stderr and
                 "Downloading the checks bundle" not in stderr and
                 record["checks_manifest_digest"] == checks["external_manifest_digest"] and
                 record["layer_digest"] == checks["external_layer_digest"] and
                 record["cache_identity"] == checks["cache_identity"] and
                 record["fallback_used"] is False and record["skip_check_update"] is True,
                 f"Trivy {architecture} did not use the exact offline external bundle")
        observations[f"trivy-offline:{architecture}"] = observed
        _verify_cache_attestation(payload, cache)
    return observations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", nargs="?", default="tools/locks/phase-e-locks.json")
    parser.add_argument("--verify-cached-artifacts", action="store_true")
    parser.add_argument("--verify-runtime", action="store_true")
    parser.add_argument("--artifact-cache", type=Path)
    args = parser.parse_args()
    stage = "schema"
    try:
        payload = json.loads(Path(args.lock).read_text(encoding="utf-8"))
        validate_lock(payload)
        if args.verify_cached_artifacts or args.verify_runtime:
            _require(args.artifact_cache is not None,
                     "--artifact-cache is required for source/runtime verification")
            stage = "source"
            verify_cached_artifacts(payload, args.artifact_cache)
        if args.verify_runtime:
            stage = "runtime"
            verify_runtime(payload, args.artifact_cache)
    except (OSError, json.JSONDecodeError, LockValidationError) as exc:
        label = {
            "schema": "PHASE_E_LOCK_SCHEMA",
            "source": "PHASE_E_LOCK_SOURCE",
            "runtime": "PHASE_E_LOCK_RUNTIME",
        }[stage]
        print(f"{label}: FAIL: {exc}")
        return 1
    print("PHASE_E_LOCK_SCHEMA: PASS (sealed structure only)")
    if args.verify_cached_artifacts or args.verify_runtime:
        print("PHASE_E_LOCK_SOURCE: PASS (archives, signatures, OCI, schemas, checks)")
    else:
        print("PHASE_E_LOCK_SOURCE: NOT_RUN")
    if args.verify_runtime:
        print("PHASE_E_LOCK_RUNTIME: PASS (both architectures and Trivy offline checks)")
    else:
        print("PHASE_E_LOCK_RUNTIME: NOT_RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
