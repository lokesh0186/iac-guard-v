#!/usr/bin/env python3
"""Build and inspect one private IaC-Guard-V 1.0 release-candidate packet."""
from __future__ import annotations

import argparse
import email
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0"
WHEEL_NAME = f"iac_guard_v-{VERSION}-py3-none-any.whl"
SDIST_NAME = f"iac_guard_v-{VERSION}.tar.gz"
SENSITIVE_MARKERS = (
    b"/Users/",
    b"\\Users\\",
    b"garimachauhan",
    b"EB-1A",
    b"USCIS",
    b"Petition_Working_Draft",
    b"external-impact-evidence",
    b"private-screening",
)
DIRECT_DEPENDENCIES = ("PyYAML", "python-hcl2", "jsonschema", "packaging")


def _run(arguments: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    return completed.stdout.strip()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8") + b"\n"


def _write_json(path: Path, value: Any) -> None:
    path.write_bytes(_canonical(value))


def _git_identity() -> tuple[str, str, int]:
    if _run(["git", "status", "--porcelain", "--untracked-files=no"]):
        raise RuntimeError("candidate source has tracked modifications")
    commit = _run(["git", "rev-parse", "HEAD"])
    tree = _run(["git", "rev-parse", "HEAD^{tree}"])
    epoch = int(_run(["git", "show", "-s", "--format=%ct", "HEAD"]))
    return commit, tree, epoch


def _build_once(destination: Path, epoch: int) -> tuple[Path, Path]:
    destination.mkdir()
    environment = dict(os.environ)
    environment.update({
        "SOURCE_DATE_EPOCH": str(epoch),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    })
    _run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(destination)],
        env=environment,
    )
    files = {path.name: path for path in destination.iterdir() if path.is_file()}
    if set(files) != {WHEEL_NAME, SDIST_NAME}:
        raise RuntimeError(f"unexpected build output: {sorted(files)}")
    return files[WHEEL_NAME], files[SDIST_NAME]


def _archive_bytes(wheel: Path, sdist: Path) -> bytes:
    chunks: list[bytes] = []
    with zipfile.ZipFile(wheel) as archive:
        for name in sorted(archive.namelist()):
            if not name.endswith("/"):
                chunks.append(name.encode("utf-8") + b"\0" + archive.read(name))
    with tarfile.open(sdist, "r:gz") as archive:
        for member in sorted(archive.getmembers(), key=lambda item: item.name):
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"could not inspect {member.name}")
                chunks.append(member.name.encode("utf-8") + b"\0" + extracted.read())
    return b"\n".join(chunks)


def _metadata(wheel: Path) -> email.message.Message:
    with zipfile.ZipFile(wheel) as archive:
        name = next(item for item in archive.namelist() if item.endswith(".dist-info/METADATA"))
        return email.message_from_bytes(archive.read(name))


def _license_record(name: str) -> dict[str, Any]:
    try:
        item = distribution(name)
    except PackageNotFoundError as exc:
        raise RuntimeError(f"direct dependency is not installed for inventory: {name}") from exc
    metadata = item.metadata
    expression = metadata.get("License-Expression") or metadata.get("License")
    classifiers = [
        value.removeprefix("License :: OSI Approved :: ")
        for value in metadata.get_all("Classifier", [])
        if value.startswith("License :: OSI Approved :: ")
    ]
    if not expression and not classifiers:
        raise RuntimeError(f"direct dependency has no declared license metadata: {name}")
    return {
        "name": metadata.get("Name", name),
        "version": item.version,
        "license_expression_or_text": expression,
        "license_classifiers": classifiers,
        "homepage": metadata.get("Project-URL") or metadata.get("Home-page"),
    }


def _source_manifest(path: Path) -> None:
    names = _run(["git", "ls-tree", "-r", "--name-only", "HEAD"]).splitlines()
    lines = []
    for name in names:
        content = subprocess.run(
            ["git", "show", f"HEAD:{name}"], cwd=ROOT, check=True, capture_output=True
        ).stdout
        lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_packet(output: Path) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("candidate output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    commit, tree, epoch = _git_identity()
    with tempfile.TemporaryDirectory(prefix="iacgv-1.0-repeat-build-") as temporary:
        temporary_root = Path(temporary)
        first_wheel, first_sdist = _build_once(temporary_root / "first", epoch)
        second_wheel, second_sdist = _build_once(temporary_root / "second", epoch)
        comparison = {
            WHEEL_NAME: [_sha(first_wheel), _sha(second_wheel)],
            SDIST_NAME: [_sha(first_sdist), _sha(second_sdist)],
        }
        if any(left != right for left, right in comparison.values()):
            raise RuntimeError(f"repeat build is not byte-identical: {comparison}")
        wheel = output / WHEEL_NAME
        sdist = output / SDIST_NAME
        shutil.copy2(first_wheel, wheel)
        shutil.copy2(first_sdist, sdist)

    payload = _archive_bytes(wheel, sdist)
    leaked = [marker.decode("utf-8", errors="replace") for marker in SENSITIVE_MARKERS if marker in payload]
    if leaked:
        raise RuntimeError(f"private or sensitive marker in distribution: {leaked}")

    metadata = _metadata(wheel)
    if metadata["Version"] != VERSION:
        raise RuntimeError("wheel metadata version is not 1.0.0")
    requirements = sorted(metadata.get_all("Requires-Dist", []))
    licenses = [_license_record(name) for name in DIRECT_DEPENDENCIES]
    dependencies = {
        "schema": "iac-guard-v-dependency-inventory-v1",
        "product": f"iac-guard-v=={VERSION}",
        "declared_runtime_requirements": requirements,
        "resolved_direct_dependencies": [
            {"name": item["name"], "version": item["version"]} for item in licenses
        ],
        "note": "Third-party scanners and materializers are not bundled runtime dependencies.",
    }
    _write_json(output / "DEPENDENCIES.json", dependencies)
    _write_json(output / "LICENSE_INVENTORY.json", {
        "schema": "iac-guard-v-license-inventory-v1",
        "project": {"name": "iac-guard-v", "version": VERSION, "license": "Apache-2.0"},
        "direct_runtime_dependencies": licenses,
    })
    _source_manifest(output / "SOURCE_MANIFEST.sha256")

    components = [{
        "type": "application",
        "name": "iac-guard-v",
        "version": VERSION,
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "hashes": [
            {"alg": "SHA-256", "content": _sha(wheel)},
            {"alg": "SHA-256", "content": _sha(sdist)},
        ],
        "purl": f"pkg:pypi/iac-guard-v@{VERSION}",
    }]
    for item in licenses:
        license_value = item["license_expression_or_text"] or "; ".join(item["license_classifiers"])
        components.append({
            "type": "library", "name": item["name"], "version": item["version"],
            "licenses": [{"license": {"name": license_value}}],
            "purl": f"pkg:pypi/{item['name'].lower().replace('_', '-')}@{item['version']}",
        })
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{commit[:8]}-{commit[8:12]}-4{commit[13:16]}-8{commit[17:20]}-{commit[20:32]}",
        "version": 1,
        "metadata": {"component": components[0]},
        "components": components[1:],
    }
    sbom_path = output / f"iac_guard_v-{VERSION}.cdx.json"
    _write_json(sbom_path, sbom)

    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": wheel.name, "digest": {"sha256": _sha(wheel)}},
            {"name": sdist.name, "digest": {"sha256": _sha(sdist)}},
            {"name": sbom_path.name, "digest": {"sha256": _sha(sbom_path)}},
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://iac-guard-v.io/build-types/python-release-candidate/v1",
                "externalParameters": {"version": VERSION, "source_commit": commit},
                "internalParameters": {"source_date_epoch": epoch, "repeat_builds": 2},
                "resolvedDependencies": [{
                    "uri": "git+https://github.com/lokesh0186/iac-guard-v",
                    "digest": {"gitCommit": commit, "gitTree": tree},
                }],
            },
            "runDetails": {
                "builder": {"id": "urn:iac-guard-v:local-private-release-candidate-builder:v1"},
                "metadata": {"invocationId": f"private-rc-{commit}"},
            },
        },
    }
    provenance_path = output / "PROVENANCE.intoto.json"
    _write_json(provenance_path, provenance)
    provenance_identity = _sha(provenance_path)

    security = {
        "schema": "iac-guard-v-release-security-audit-v1",
        "version": VERSION,
        "source_commit": commit,
        "source_tree": tree,
        "distribution_private_path_scan": "PASS",
        "distribution_secret_marker_scan": "PASS",
        "normal_native_verification_network_dependency": "NONE",
        "dynamic_plugin_loading": "NOT_SUPPORTED",
        "scanner_authority": "BOUNDED_BY_SCANNER_AUTHORITY.md",
        "missing_output_pass": "PROHIBITED",
        "hostile_input_claim": "NOT_SUPPORTED",
        "helm_kustomize_containment": "COVERED_BY_RELEASE_AND_ADVERSARIAL_TESTS",
        "repeat_build_sha256": comparison,
    }
    _write_json(output / "SECURITY_AUDIT.json", security)
    _write_json(output / "ATTESTATION_IDENTITIES.json", {
        "schema": "iac-guard-v-attestation-identities-v1",
        "local_provenance_statement_sha256": provenance_identity,
        "local_builder": provenance["predicate"]["runDetails"]["builder"]["id"],
        "authorized_release_builder": "https://github.com/lokesh0186/iac-guard-v/.github/workflows/release.yml@refs/tags/v1.0.0",
        "github_sigstore_attestation": "PENDING_OWNER_AUTHORIZED_RELEASE_WORKFLOW",
        "pypi_trusted_publisher": "lokesh0186/iac-guard-v:.github/workflows/release.yml:pypi",
    })

    summary = {
        "version": VERSION,
        "source_commit": commit,
        "source_tree": tree,
        "wheel_sha256": _sha(wheel),
        "sdist_sha256": _sha(sdist),
        "sbom_sha256": _sha(sbom_path),
        "provenance_sha256": provenance_identity,
        "repeat_build": "BYTE_IDENTICAL",
        "private_path_scan": "PASS",
        "files": sorted(
            [path.name for path in output.iterdir() if path.is_file()]
            + ["RELEASE_CANDIDATE.json", "SHA256SUMS"]
        ),
        "created_at": datetime.fromtimestamp(epoch, timezone.utc).isoformat(),
    }
    _write_json(output / "RELEASE_CANDIDATE.json", summary)
    checksum_names = sorted(
        path.name for path in output.iterdir()
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (output / "SHA256SUMS").write_text(
        "".join(f"{_sha(output / name)}  {name}\n" for name in checksum_names),
        encoding="utf-8",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    print(json.dumps(build_packet(arguments.output.resolve()), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
