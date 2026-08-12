#!/usr/bin/env python3
"""Validate Phase-E locks structurally and against a protected artifact cache."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import tempfile
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


def validate_lock(payload: Any) -> None:
    """Raise unless *payload* is the complete sealed E0.1 lock graph."""

    _require(isinstance(payload, dict), "lock must be an object")
    _require(payload.get("lock_contract") == "phase-e-verified-tool-locks-v2",
             "unexpected lock contract")
    _require(payload.get("architectures") == list(ARCHITECTURES),
             "architecture order or set differs from the reviewed matrix")
    seal = payload.get("lock_payload_sha256")
    _digest(seal, "lock_payload_sha256")
    _require(seal == lock_payload_sha256(payload),
             "lock_payload_sha256 does not seal the canonical lock graph")
    _require(payload.get("artifact_cache_contract") ==
             "phase-e-protected-artifact-cache-v1",
             "artifact cache contract is missing")

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
        _require(release["repository"].startswith("https://github.com/"),
                 f"tools.{name}.release.repository must be official HTTPS")
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
    _require(candidate.exists() and candidate.is_file() and not candidate.is_symlink(),
             f"cached artifact is missing or unsafe: {relative}")
    return candidate


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


def verify_cached_artifacts(payload: dict[str, Any], artifact_cache: Path) -> None:
    """Verify real release, OCI, fixture, licence, schema, and checks bytes."""

    validate_lock(payload)
    cache = artifact_cache.resolve(strict=True)
    tools = payload["tools"]
    for name in sorted(EXPECTED_TOOLS):
        tool = tools[name]
        release = tool["release"]
        refs = _verify_file(cache, release["tag_refs_cache_path"],
                            release["tag_refs_sha256"], f"tools.{name}.release")
        ref_text = refs.read_text(encoding="utf-8")
        _require(release["commit"] in ref_text and
                 f"refs/tags/{release['tag']}" in ref_text,
                 f"tools.{name} cached tag does not resolve to the locked commit")

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

    checks = tools["trivy"]["checks"]
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", nargs="?", default="tools/locks/phase-e-locks.json")
    parser.add_argument("--verify-cached-artifacts", action="store_true")
    parser.add_argument("--artifact-cache", type=Path)
    args = parser.parse_args()
    try:
        payload = json.loads(Path(args.lock).read_text(encoding="utf-8"))
        validate_lock(payload)
        if args.verify_cached_artifacts:
            _require(args.artifact_cache is not None,
                     "--artifact-cache is required with --verify-cached-artifacts")
            verify_cached_artifacts(payload, args.artifact_cache)
    except (OSError, json.JSONDecodeError, LockValidationError) as exc:
        label = "PHASE_E_LOCK_SOURCE" if args.verify_cached_artifacts else \
            "PHASE_E_LOCK_SCHEMA"
        print(f"{label}: FAIL: {exc}")
        return 1
    if args.verify_cached_artifacts:
        print("PHASE_E_LOCK_SOURCE: PASS (archives, signatures, OCI, schemas, checks)")
    else:
        print("PHASE_E_LOCK_SCHEMA: PASS (6 tools, 2 architectures, sealed graph)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
