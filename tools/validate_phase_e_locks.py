#!/usr/bin/env python3
"""Validate the immutable Phase-E dependency-research lock contract."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_TOOLS = {
    "kics",
    "trivy",
    "opentofu",
    "terraform",
    "kubeconform",
    "tflint",
}
REQUIRED_TOOL_KEYS = {
    "version",
    "release",
    "archives",
    "container",
    "signature_attestation",
    "license",
    "invocation_contract",
    "output_schema_fixture",
    "offline_requirements",
    "upgrade_policy",
    "compatibility_test",
}
ARCHITECTURES = {"linux/amd64", "linux/arm64"}


class LockValidationError(ValueError):
    """The Phase-E lock is incomplete, mutable, or internally inconsistent."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LockValidationError(message)


def _digest(value: Any, field: str, *, prefixed: bool = False) -> None:
    matcher = SHA256 if prefixed else HEX_SHA256
    _require(isinstance(value, str) and matcher.fullmatch(value) is not None,
             f"{field} must be a canonical SHA-256")


def _validate_container(container: Any, field: str) -> None:
    _require(isinstance(container, dict), f"{field} must be an object")
    required = {
        "image", "manifest_digest", "selected_architecture",
        "selected_architecture_digest", "supported_architectures",
    }
    _require(required <= container.keys(), f"{field} is incomplete")
    image = container["image"]
    _require(isinstance(image, str) and ":latest" not in image,
             f"{field}.image must not use :latest")
    _digest(container["manifest_digest"], f"{field}.manifest_digest", prefixed=True)
    _digest(container["selected_architecture_digest"],
            f"{field}.selected_architecture_digest", prefixed=True)
    supported = container["supported_architectures"]
    _require(isinstance(supported, list) and ARCHITECTURES <= set(supported),
             f"{field} must support linux/amd64 and linux/arm64")
    _require(container["selected_architecture"] in supported,
             f"{field}.selected_architecture must be supported")


def validate_lock(payload: Any) -> None:
    """Raise ``LockValidationError`` unless *payload* is a complete E0 lock."""

    _require(isinstance(payload, dict), "lock must be an object")
    _require(payload.get("lock_contract") == "phase-e-immutable-tool-locks-v1",
             "unexpected lock contract")
    _require(payload.get("architectures") == ["linux/amd64", "linux/arm64"],
             "architecture order or set differs from the reviewed matrix")
    tools = payload.get("tools")
    _require(isinstance(tools, dict) and set(tools) == EXPECTED_TOOLS,
             "tool set must contain exactly the six reviewed Phase-E tools")

    for name in sorted(EXPECTED_TOOLS):
        tool = tools[name]
        _require(isinstance(tool, dict), f"tools.{name} must be an object")
        _require(REQUIRED_TOOL_KEYS <= tool.keys(), f"tools.{name} is incomplete")
        release = tool["release"]
        _require(isinstance(release, dict) and
                 {"repository", "tag", "commit"} <= release.keys(),
                 f"tools.{name}.release is incomplete")
        _require(isinstance(release["repository"], str) and
                 release["repository"].startswith("https://github.com/"),
                 f"tools.{name}.release.repository must be an official HTTPS source")
        _require(COMMIT.fullmatch(release["commit"]) is not None,
                 f"tools.{name}.release.commit must be a full Git commit")
        _require(isinstance(release["tag"], str) and release["tag"],
                 f"tools.{name}.release.tag is required")

        archives = tool["archives"]
        _require(isinstance(archives, dict) and ARCHITECTURES <= archives.keys(),
                 f"tools.{name}.archives lacks a required architecture")
        for arch in sorted(ARCHITECTURES):
            archive = archives[arch]
            _require(isinstance(archive, dict) and {"name", "sha256"} <= archive.keys(),
                     f"tools.{name}.archives.{arch} is incomplete")
            _digest(archive["sha256"], f"tools.{name}.archives.{arch}.sha256")

        _validate_container(tool["container"], f"tools.{name}.container")
        _require(isinstance(tool["signature_attestation"], str) and
                 tool["signature_attestation"].strip(),
                 f"tools.{name}.signature_attestation is required")
        _require(isinstance(tool["license"], dict) and
                 {"id", "sha256"} <= tool["license"].keys(),
                 f"tools.{name}.license is incomplete")
        _digest(tool["license"]["sha256"], f"tools.{name}.license.sha256")
        invocation = tool["invocation_contract"]
        _require(isinstance(invocation, dict) and
                 {"argv", "contract_version"} <= invocation.keys() and
                 isinstance(invocation["argv"], list) and invocation["argv"],
                 f"tools.{name}.invocation_contract is incomplete")
        fixture = tool["output_schema_fixture"]
        _require(isinstance(fixture, dict) and
                 {"path", "sha256", "source"} <= fixture.keys(),
                 f"tools.{name}.output_schema_fixture is incomplete")
        _digest(fixture["sha256"], f"tools.{name}.output_schema_fixture.sha256")
        _require(isinstance(tool["offline_requirements"], str) and
                 tool["offline_requirements"].strip(),
                 f"tools.{name}.offline_requirements is required")
        _require(isinstance(tool["upgrade_policy"], str) and
                 tool["upgrade_policy"].strip(),
                 f"tools.{name}.upgrade_policy is required")
        compatibility = tool["compatibility_test"]
        _require(isinstance(compatibility, dict) and
                 {"result", "scope"} <= compatibility.keys(),
                 f"tools.{name}.compatibility_test is incomplete")

    _require(tools["terraform"].get("distribution_mode") ==
             "USER_SUPPLIED_ONLY_NEVER_BUNDLED",
             "Terraform must remain user-supplied and unbundled")
    _require(tools["tflint"].get("security_role") == "OPTIONAL_NON_SECURITY",
             "TFLint must remain optional and non-security")
    _require(tools["kics"]["version"] == "2.1.20",
             "the reviewed KICS runtime selection is 2.1.20")

    checks = tools["trivy"].get("checks")
    required_checks = {
        "external_repository", "external_manifest_digest",
        "external_source_commit", "embedded_checks_identity", "cache_identity",
        "selected_source", "fallback_used", "source_identity_rule",
    }
    _require(isinstance(checks, dict) and required_checks <= checks.keys(),
             "Trivy checks identity is incomplete")
    _require(checks["external_repository"].endswith(":2.2.0") and
             not checks["external_repository"].endswith(":2"),
             "Trivy checks must use the immutable reviewed version, not :2")
    _digest(checks["external_manifest_digest"],
            "tools.trivy.checks.external_manifest_digest", prefixed=True)
    _require(checks["selected_source"] == "external" and
             checks["fallback_used"] is False,
             "Trivy source/fallback identity differs from the review")

    base = payload.get("hardened_container_base")
    _require(isinstance(base, dict) and
             {"image", "manifest_digest", "selected_architecture_digests",
              "selection_basis"} <= base.keys(),
             "hardened container base lock is incomplete")
    _require(":latest" not in base["image"], "base image must not use :latest")
    _digest(base["manifest_digest"], "hardened_container_base.manifest_digest",
            prefixed=True)
    arch_digests = base["selected_architecture_digests"]
    _require(isinstance(arch_digests, dict) and ARCHITECTURES <= arch_digests.keys(),
             "base image lacks a required architecture digest")
    for arch in sorted(ARCHITECTURES):
        _digest(arch_digests[arch],
                f"hardened_container_base.selected_architecture_digests.{arch}",
                prefixed=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", nargs="?", default="tools/locks/phase-e-locks.json")
    args = parser.parse_args()
    try:
        payload = json.loads(Path(args.lock).read_text(encoding="utf-8"))
        validate_lock(payload)
    except (OSError, json.JSONDecodeError, LockValidationError) as exc:
        print(f"PHASE_E_LOCKS: FAIL: {exc}")
        return 1
    print("PHASE_E_LOCKS: PASS (6 tools, 2 architectures, immutable digests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
