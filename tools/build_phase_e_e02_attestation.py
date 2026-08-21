#!/usr/bin/env python3
"""Build E0.2 runtime records and a signed portable protected-cache manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from tools.validate_phase_e_locks import (
    ARCHITECTURES,
    ARTIFACT_CACHE_CONTRACT,
    CACHE_ATTESTATION_CONTRACT,
    CACHE_MANIFEST_CONTRACT,
    RUNTIME_ARGV,
    RUNTIME_RECORD_CONTRACT,
    TRIVY_NORMALIZED_SCRIPT,
    TRIVY_RUNTIME_CONTRACT,
    lock_payload_sha256,
    physical_cache_inventory,
    runtime_execution_digest,
    trivy_offline_execution_digest,
)


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "tools/locks/phase-e-locks.json"
MANIFEST_PATH = ROOT / "tools/locks/phase-e-cache-manifest.json"
ATTESTATION_PATH = ROOT / "tools/locks/phase-e-cache-attestation.json"
SIGNATURE_PATH = ROOT / "tools/locks/phase-e-cache-attestation.sig"
PUBLIC_KEY_PATH = ROOT / "tools/locks/phase-e-cache-attestation.pub.pem"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _results(path: Path) -> dict[tuple[str, str], tuple[int, int]]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        tool, architecture, code, start, end = line.split("\t")
        if int(code) != 0:
            raise RuntimeError(f"{tool} {architecture} smoke failed")
        result[(tool, architecture)] = (int(code), int(end) - int(start))
    return result


def _runtime_command(tool: dict, architecture: str, argv: list[str]) -> list[str]:
    return [
        "docker", "run", "--rm", "--pull", "never",
        "--platform", architecture, "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "-e", "HOME=/tmp", "-e", "TMPDIR=/tmp",
        tool["container"]["execution_references"][architecture], *argv,
    ]


def _trivy_command(payload: dict, cache: Path, architecture: str) -> list[str]:
    reference = payload["tools"]["trivy"]["container"]["execution_references"][
        architecture
    ]
    return [
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


def _execute_runtime(payload: dict, cache: Path) -> None:
    """Acquire current deterministic runtime bytes from the exact locked images."""

    runtime_root = cache / "runtime-v2"
    runtime_root.mkdir(parents=True, exist_ok=True)
    version_results = []
    for tool_name in sorted(payload["tools"]):
        tool = payload["tools"][tool_name]
        for architecture in ARCHITECTURES:
            suffix = architecture.removeprefix("linux/")
            started = time.monotonic_ns()
            result = subprocess.run(
                _runtime_command(tool, architecture, RUNTIME_ARGV[tool_name]),
                check=False, capture_output=True,
            )
            ended = time.monotonic_ns()
            if result.returncode != 0:
                raise RuntimeError(f"{tool_name} {architecture} smoke failed")
            (runtime_root / f"{tool_name}-{suffix}.stdout").write_bytes(result.stdout)
            (runtime_root / f"{tool_name}-{suffix}.stderr").write_bytes(result.stderr)
            version_results.append(
                f"{tool_name}\t{architecture}\t{result.returncode}\t{started}\t{ended}"
            )
            physical_cache_inventory(cache)
    (runtime_root / "results.tsv").write_text(
        "\n".join(version_results) + "\n", encoding="utf-8"
    )

    trivy_results = []
    for architecture in ARCHITECTURES:
        suffix = architecture.removeprefix("linux/")
        started = time.monotonic_ns()
        result = subprocess.run(
            _trivy_command(payload, cache, architecture),
            check=False, capture_output=True,
        )
        ended = time.monotonic_ns()
        if result.returncode != 0:
            raise RuntimeError(f"Trivy {architecture} offline smoke failed")
        decoded = json.loads(result.stdout)
        if decoded.get("SchemaVersion") != 2:
            raise RuntimeError(f"Trivy {architecture} output schema differs")
        stderr = result.stderr.decode("utf-8", errors="strict")
        if "loading from existing cache" not in stderr or "Downloading" in stderr:
            raise RuntimeError(f"Trivy {architecture} did not use the external cache")
        (runtime_root / f"trivy-offline-{suffix}.json").write_bytes(result.stdout)
        (runtime_root / f"trivy-offline-{suffix}.stderr").write_bytes(result.stderr)
        trivy_results.append(
            f"{architecture}\t{result.returncode}\t{started}\t{ended}"
        )
        physical_cache_inventory(cache)
    (runtime_root / "trivy-offline-results.tsv").write_text(
        "\n".join(trivy_results) + "\n", encoding="utf-8"
    )


def _runtime_records(payload: dict, cache: Path, runner: str) -> None:
    timing = _results(cache / "runtime-v2/results.tsv")
    for tool_name, tool in payload["tools"].items():
        records = {}
        for architecture in ARCHITECTURES:
            suffix = architecture.removeprefix("linux/")
            stdout_path = Path(f"runtime-v2/{tool_name}-{suffix}.stdout")
            stderr_path = Path(f"runtime-v2/{tool_name}-{suffix}.stderr")
            stdout = (cache / stdout_path).read_bytes()
            stderr = (cache / stderr_path).read_bytes()
            code, duration = timing[(tool_name, architecture)]
            record = {
                "contract": RUNTIME_RECORD_CONTRACT,
                "tool": tool_name,
                "version": tool["version"],
                "image_index_digest": tool["container"]["index_digest"],
                "image_architecture_digest": tool["container"][
                    "architecture_digests"
                ][architecture],
                "execution_reference": tool["container"]["execution_references"][
                    architecture
                ],
                "architecture": architecture,
                "argv": RUNTIME_ARGV[tool_name],
                "environment_allowlist": ["HOME=/tmp", "TMPDIR=/tmp"],
                "network_mode": "none",
                "filesystem_mode": "read-only-root,tmpfs-/tmp,no-host-mounts",
                "exit_code": code,
                "stdout_sha256": _sha(stdout),
                "stderr_sha256": _sha(stderr),
                "version_output": stdout.decode("utf-8").strip(),
                "output_schema_result": (
                    "VERSION_COMMAND_OUTPUT_ONLY_NOT_ADAPTER_AUTHORIZATION"
                ),
                "duration_ns": duration,
                "runner_build_identity": runner,
                "stdout_cache_path": stdout_path.as_posix(),
                "stderr_cache_path": stderr_path.as_posix(),
            }
            record["execution_digest"] = runtime_execution_digest(record)
            records[architecture] = record
            record_path = cache / f"runtime-v2/{tool_name}-{suffix}.record.json"
            record_path.write_bytes(_canonical(record) + b"\n")
        tool["runtime_records"] = records


def _trivy_records(payload: dict, cache: Path, runner: str) -> None:
    timing = {}
    for line in (cache / "runtime-v2/trivy-offline-results.tsv").read_text(
        encoding="utf-8"
    ).splitlines():
        architecture, code, start, end = line.split("\t")
        timing[architecture] = (int(code), int(end) - int(start))
    checks = payload["tools"]["trivy"]["checks"]
    records = {}
    for architecture in ARCHITECTURES:
        suffix = architecture.removeprefix("linux/")
        output_path = Path(f"runtime-v2/trivy-offline-{suffix}.json")
        stderr_path = Path(f"runtime-v2/trivy-offline-{suffix}.stderr")
        output = (cache / output_path).read_bytes()
        stderr = (cache / stderr_path).read_bytes()
        code, duration = timing[architecture]
        decoded = json.loads(output)
        record = {
            "contract": TRIVY_RUNTIME_CONTRACT,
            "architecture": architecture,
            "image_index_digest": payload["tools"]["trivy"]["container"][
                "index_digest"
            ],
            "image_architecture_digest": payload["tools"]["trivy"]["container"][
                "architecture_digests"
            ][architecture],
            "execution_reference": payload["tools"]["trivy"]["container"][
                "execution_references"
            ][architecture],
            "argv": ["/bin/sh", "-c", TRIVY_NORMALIZED_SCRIPT],
            "environment_allowlist": ["TRIVY_CACHE_DIR=/cache"],
            "network_mode": "none",
            "filesystem_mode": "read-only-root,read-only-cache,read-only-input",
            "checks_manifest_digest": checks["external_manifest_digest"],
            "layer_digest": checks["external_layer_digest"],
            "cache_identity": checks["cache_identity"],
            "fallback_used": False,
            "skip_check_update": True,
            "exit_code": code,
            "output_sha256": _sha(output),
            "stderr_sha256": _sha(stderr),
            "canonical_output_sha256": _sha(_canonical(decoded)),
            "output_schema_result": (
                "PASS_SCHEMA_VERSION_2"
                if decoded.get("SchemaVersion") == 2 else "FAIL"
            ),
            "duration_ns": duration,
            "runner_build_identity": runner,
            "output_cache_path": output_path.as_posix(),
            "stderr_cache_path": stderr_path.as_posix(),
        }
        record["execution_digest"] = trivy_offline_execution_digest(record)
        records[architecture] = record
        path = cache / f"runtime-v2/trivy-offline-{suffix}.record.json"
        path.write_bytes(_canonical(record) + b"\n")
    checks["offline_verification"]["runtime_records"] = records


def _source_evidence(payload: dict, cache: Path) -> None:
    schema = payload["tools"]["kubeconform"]["schema_bundle"]
    evidence = {
        "commit_object_cache_path": "schema/source-commit-object.txt",
        "ls_tree_cache_path": "schema/source-ls-tree.txt",
        "root_tree_cache_path": "schema/source-root-tree.txt",
        "extracted_file_count": 2608,
        "license_evidence": "NO_ROOT_LICENSE_FILE_IN_LOCKED_TREE",
    }
    for stem in ("commit_object", "ls_tree", "root_tree"):
        evidence[f"{stem}_sha256"] = _sha(
            (cache / evidence[f"{stem}_cache_path"]).read_bytes()
        )
    schema["source_evidence"] = evidence
    checks = payload["tools"]["trivy"]["checks"]
    checks.update({
        "source_repository": "https://github.com/aquasecurity/trivy-checks",
        "source_tag": "v2.2.0",
        "source_tag_refs_cache_path": "trivy/checks-tag-refs.txt",
        "source_tag_refs_sha256": _sha(
            (cache / "trivy/checks-tag-refs.txt").read_bytes()
        ),
    })


def _cache_manifest(cache: Path) -> dict:
    return {
        "contract": CACHE_MANIFEST_CONTRACT,
        "entries": physical_cache_inventory(cache),
    }


def _attest(payload: dict, cache: Path, runner: str) -> None:
    manifest = _cache_manifest(cache)
    MANIFEST_PATH.write_bytes(_canonical(manifest) + b"\n")
    manifest_sha = _sha(MANIFEST_PATH.read_bytes())
    manifest_root = _sha(_canonical(manifest["entries"]))
    docker = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="iacgv-e02-key-") as directory:
        private = Path(directory) / "private.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
            check=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(PUBLIC_KEY_PATH)],
            check=True,
        )
        public_sha = _sha(PUBLIC_KEY_PATH.read_bytes())
        signer = f"e02-local-acquisition-ed25519:{public_sha}"
        retrieval_sources = sorted({
            tool["release"]["repository"] for tool in payload["tools"].values()
        } | {
            payload["tools"]["trivy"]["checks"]["source_repository"],
            payload["tools"]["kubeconform"]["schema_bundle"]["repository"],
        })
        runtime_ids = {
            tool_name: {
                architecture: record["execution_digest"]
                for architecture, record in tool["runtime_records"].items()
            }
            for tool_name, tool in payload["tools"].items()
        }
        runtime_ids["trivy_offline"] = {
            architecture: record["execution_digest"]
            for architecture, record in payload["tools"]["trivy"]["checks"][
                "offline_verification"
            ]["runtime_records"].items()
        }
        attestation = {
            "contract": CACHE_ATTESTATION_CONTRACT,
            "cache_contract": ARTIFACT_CACHE_CONTRACT,
            "manifest_sha256": manifest_sha,
            "manifest_root": manifest_root,
            "cache_generation_tool_identity": _sha(Path(__file__).read_bytes()),
            "verification_runner_identity": runner,
            "retrieval_sources": retrieval_sources,
            "execution_architecture": platform.machine(),
            "container_engine": docker,
            "runtime_record_identities": runtime_ids,
            "creation_timestamp": datetime.now(timezone.utc).isoformat(),
            "signature_method": "ED25519_OPENSSL",
            "signer_identity": signer,
            "authorization_scope": (
                "local reproducible acquisition signature; tool release authority "
                "remains the independently verified upstream evidence"
            ),
        }
        ATTESTATION_PATH.write_bytes(_canonical(attestation) + b"\n")
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private),
             "-in", str(ATTESTATION_PATH), "-out", str(SIGNATURE_PATH)],
            check=True,
        )
    payload["protected_cache_attestation"] = {
        "contract": CACHE_ATTESTATION_CONTRACT,
        "manifest_path": MANIFEST_PATH.relative_to(ROOT).as_posix(),
        "manifest_sha256": manifest_sha,
        "manifest_root": manifest_root,
        "attestation_path": ATTESTATION_PATH.relative_to(ROOT).as_posix(),
        "attestation_sha256": _sha(ATTESTATION_PATH.read_bytes()),
        "signature_path": SIGNATURE_PATH.relative_to(ROOT).as_posix(),
        "signature_sha256": _sha(SIGNATURE_PATH.read_bytes()),
        "public_key_path": PUBLIC_KEY_PATH.relative_to(ROOT).as_posix(),
        "public_key_sha256": _sha(PUBLIC_KEY_PATH.read_bytes()),
        "signature_method": "ED25519_OPENSSL",
        "signer_identity": signer,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-cache", type=Path, required=True)
    args = parser.parse_args()
    cache = args.artifact_cache.resolve(strict=True)
    payload = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    payload["lock_contract"] = "phase-e-verified-tool-locks-v4"
    payload["artifact_cache_contract"] = ARTIFACT_CACHE_CONTRACT
    payload["verification_claims"] = {
        "schema": "REQUIRES_SCHEMA_VALIDATION",
        "source": "REQUIRES_PROTECTED_CACHE_VERIFICATION",
        "runtime": "REQUIRES_REEXECUTION_OR_SIGNED_ATTESTATION",
    }
    payload["tools"]["trivy"]["invocation_contract"]["argv"] = [
        item for item in payload["tools"]["trivy"]["invocation_contract"]["argv"]
        if item != "--offline-scan"
    ]
    runner = _sha((ROOT / "tools/validate_phase_e_locks.py").read_bytes())
    physical_cache_inventory(cache)
    _execute_runtime(payload, cache)
    _runtime_records(payload, cache, runner)
    _trivy_records(payload, cache, runner)
    _source_evidence(payload, cache)
    _attest(payload, cache, runner)
    payload["lock_payload_sha256"] = lock_payload_sha256(payload)
    LOCK_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
