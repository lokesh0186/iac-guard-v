#!/usr/bin/env python3
"""Fail-closed replay driver for the content-bound a8 55-surface corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from iac_guard_v import __version__
from iac_guard_v.helm import HelmMaterializationError, HelmRenderSpec, materialize_helm
from iac_guard_v.kustomize import (
    KustomizeBuildSpec,
    KustomizeMaterializationError,
    materialize_kustomize,
)


CORPUS_SCHEMA = "iac-guard-v-a8-55-surface-corpus-v1"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha(value: object) -> str:
    return sha256_bytes(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8"))


def _archive_records(archive: Path) -> tuple[str, list[dict], list[tarfile.TarInfo]]:
    records: list[dict] = []
    members: list[tarfile.TarInfo] = []
    prefix: str | None = None
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            raw = PurePosixPath(member.name)
            if raw.is_absolute() or ".." in raw.parts or not raw.parts:
                raise RuntimeError(f"CORPUS_ARCHIVE_UNSAFE_PATH: {member.name}")
            if prefix is None:
                prefix = raw.parts[0]
            if raw.parts[0] != prefix:
                raise RuntimeError("CORPUS_ARCHIVE_MULTIPLE_ROOTS")
            relative = PurePosixPath(*raw.parts[1:])
            if not relative.parts or member.isdir():
                members.append(member)
                continue
            if member.isfile():
                stream = bundle.extractfile(member)
                if stream is None:
                    raise RuntimeError("CORPUS_ARCHIVE_MEMBER_UNREADABLE")
                content = stream.read()
                records.append({
                    "path": relative.as_posix(), "type": "file",
                    "mode": member.mode & 0o777, "size": len(content),
                    "sha256": sha256_bytes(content),
                })
            elif member.issym():
                target = PurePosixPath(member.linkname)
                if target.is_absolute():
                    raise RuntimeError("CORPUS_ARCHIVE_ABSOLUTE_SYMLINK")
                records.append({
                    "path": relative.as_posix(), "type": "symlink",
                    "mode": member.mode & 0o777, "target": member.linkname,
                })
            else:
                raise RuntimeError("CORPUS_ARCHIVE_UNSUPPORTED_MEMBER_TYPE")
            members.append(member)
    if prefix is None:
        raise RuntimeError("CORPUS_ARCHIVE_EMPTY")
    return prefix, sorted(records, key=lambda item: item["path"]), members


def _apply_aux_records(corpus: Path, repository: dict, records: list[dict]) -> list[dict]:
    by_path = {item["path"]: item for item in records}
    for item in repository["auxiliary_protected_inputs"]:
        source = corpus / item["source_path"]
        if not source.is_file() or sha256_file(source) != item["sha256"]:
            raise RuntimeError("CORPUS_AUXILIARY_INPUT_IDENTITY_MISMATCH")
        if item["target_path"] in by_path:
            raise RuntimeError("CORPUS_AUXILIARY_INPUT_OVERWRITE")
        by_path[item["target_path"]] = {
            "path": item["target_path"], "type": "file", "mode": 0o644,
            "size": source.stat().st_size, "sha256": item["sha256"],
        }
    return sorted(by_path.values(), key=lambda row: row["path"])


def validate_manifest(path: Path) -> tuple[dict, Path]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != CORPUS_SCHEMA:
        raise RuntimeError("CORPUS_MANIFEST_SCHEMA_UNSUPPORTED")
    expected_payload = manifest.get("manifest_payload_sha256")
    body = dict(manifest)
    body.pop("manifest_payload_sha256", None)
    if expected_payload != canonical_sha(body):
        raise RuntimeError("CORPUS_MANIFEST_PAYLOAD_MISMATCH")
    surfaces = manifest.get("surfaces")
    repositories = manifest.get("repositories")
    if type(surfaces) is not list or len(surfaces) != 55:
        raise RuntimeError("CORPUS_SURFACE_COUNT_MISMATCH")
    if type(repositories) is not dict or len(repositories) != 28:
        raise RuntimeError("CORPUS_REPOSITORY_COUNT_MISMATCH")
    ids = [item.get("surface_id") for item in surfaces]
    if len(ids) != len(set(ids)) or any(type(item) is not str for item in ids):
        raise RuntimeError("CORPUS_SURFACE_IDENTITY_COLLISION")
    corpus = path.resolve().parent / "a8-coverage-corpus"
    if not corpus.is_dir():
        raise RuntimeError("CORPUS_CONTENT_ROOT_UNAVAILABLE")
    for repo_id, repository in sorted(repositories.items()):
        archive = corpus / repository["archive_path"]
        if not archive.is_file() or sha256_file(archive) != repository["archive_sha256"]:
            raise RuntimeError(f"CORPUS_ARCHIVE_IDENTITY_MISMATCH: {repo_id}")
        prefix, records, _members = _archive_records(archive)
        if prefix != repository["archive_root_prefix"]:
            raise RuntimeError(f"CORPUS_ARCHIVE_ROOT_MISMATCH: {repo_id}")
        records = _apply_aux_records(corpus, repository, records)
        if canonical_sha(records) != repository["snapshot_manifest_root"]:
            raise RuntimeError(f"CORPUS_SNAPSHOT_MANIFEST_MISMATCH: {repo_id}")
    for name in ("helm", "kustomize"):
        tool = manifest["tool_contract"][name]
        executable = corpus / tool["path"]
        if not executable.is_file() or sha256_file(executable) != tool["sha256"]:
            raise RuntimeError(f"CORPUS_TOOL_IDENTITY_MISMATCH: {name}")
    return manifest, corpus


def _safe_extract(archive: Path, destination: Path, expected_prefix: str) -> None:
    destination.mkdir(mode=0o700, parents=True)
    symlinks: list[tuple[Path, str]] = []
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            raw = PurePosixPath(member.name)
            if not raw.parts or raw.parts[0] != expected_prefix:
                raise RuntimeError("CORPUS_ARCHIVE_ROOT_MISMATCH")
            relative = PurePosixPath(*raw.parts[1:])
            if not relative.parts:
                continue
            target = destination.joinpath(*relative.parts)
            try:
                target.parent.resolve().relative_to(destination.resolve())
            except ValueError as exc:
                raise RuntimeError("CORPUS_ARCHIVE_PATH_ESCAPE") from exc
            if member.isdir():
                target.mkdir(mode=member.mode & 0o777 or 0o755, parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                stream = bundle.extractfile(member)
                if stream is None:
                    raise RuntimeError("CORPUS_ARCHIVE_MEMBER_UNREADABLE")
                with target.open("xb") as output:
                    shutil.copyfileobj(stream, output)
                target.chmod(member.mode & 0o777 or 0o644)
            elif member.issym():
                symlinks.append((target, member.linkname))
            else:
                raise RuntimeError("CORPUS_ARCHIVE_UNSUPPORTED_MEMBER_TYPE")
    for target, link_name in symlinks:
        link = PurePosixPath(link_name)
        if link.is_absolute():
            raise RuntimeError("CORPUS_ARCHIVE_ABSOLUTE_SYMLINK")
        resolved = (target.parent / Path(*link.parts)).resolve(strict=False)
        try:
            resolved.relative_to(destination.resolve())
        except ValueError as exc:
            raise RuntimeError("CORPUS_ARCHIVE_SYMLINK_ESCAPE") from exc
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        target.symlink_to(link_name)


def _install_aux(corpus: Path, repository: dict, destination: Path) -> None:
    for item in repository["auxiliary_protected_inputs"]:
        source = corpus / item["source_path"]
        target = destination / item["target_path"]
        if target.exists() or target.is_symlink():
            raise RuntimeError("CORPUS_AUXILIARY_INPUT_OVERWRITE")
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o644)


def _source_implementation_identity(workspace: Path) -> dict:
    source = workspace / "src/iac_guard_v"
    records = []
    for path in sorted(source.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            records.append({
                "path": path.relative_to(workspace).as_posix(),
                "sha256": sha256_file(path), "size": path.stat().st_size,
            })
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=workspace, check=True, capture_output=True, text=True,
        ).stdout.strip()
    return {
        "package_version": __version__,
        "git_head": git("rev-parse", "HEAD"),
        "git_tree": git("rev-parse", "HEAD^{tree}"),
        "working_tree_dirty": bool(git("status", "--short")),
        "implementation_source_manifest_sha256": canonical_sha(records),
        "implementation_source_file_count": len(records),
    }


def _run_surface(surface: dict, repository_root: Path, corpus: Path, output: Path) -> dict:
    request = {
        "surface_id": surface["surface_id"],
        "artifact_class": surface["artifact_class"],
        "root_path": surface["root_path"],
        "configuration": surface["configuration"],
        "release_name": surface["release_name"],
        "namespace": surface["namespace"],
        "kube_version": surface["kube_version"],
        "api_versions": surface["api_versions"],
        "selected_property_request": surface["selected_property_request"],
    }
    root = repository_root if surface["root_path"] == "." else repository_root / surface["root_path"]
    try:
        if surface["artifact_class"] == "HELM":
            config = surface["configuration"]
            spec = HelmRenderSpec(
                chart_root=root,
                protected_repository_root=repository_root,
                helm_executable=corpus / "tools/helm-v4.2.4-darwin-arm64",
                release_name=surface["release_name"],
                namespace=surface["namespace"],
                kube_version=surface["kube_version"],
                values_files=tuple(config["values_files"]),
                set_values=tuple(tuple(item) for item in config["set_values"]),
                set_strings=tuple(tuple(item) for item in config["set_strings"]),
                api_versions=tuple(surface["api_versions"]),
                include_crds=config["include_crds"],
                include_tests=config["include_tests"],
            )
            evidence = materialize_helm(spec, output)
        elif surface["artifact_class"] == "KUSTOMIZE":
            spec = KustomizeBuildSpec(
                repository_root=repository_root,
                build_root=root,
                executable=corpus / "tools/kustomize",
            )
            evidence = materialize_kustomize(spec, output)
        else:
            raise RuntimeError("CORPUS_ARTIFACT_CLASS_UNSUPPORTED")
        canonical = evidence.canonical_dict()
        observed = "SUPPORTED"
        return {
            "status": observed,
            "reason_code": canonical["reason_code"],
            "materialization_identity": evidence.materialization_identity,
            "protected_input_manifest_root": (
                canonical["build"].get("transitive_input_manifest_sha256")
                if surface["artifact_class"] == "KUSTOMIZE"
                else canonical["chart"]["inventory_root_sha256"]
            ),
            "scanner_universe_identity": canonical["output"]["rendered_bundle_sha256"],
            "resource_count": canonical["output"]["resource_count"],
            "evidence_digest": canonical_sha(canonical),
            "request_digest": canonical_sha(request),
            "selected_property_request": surface["selected_property_request"],
        }
    except (HelmMaterializationError, KustomizeMaterializationError) as exc:
        observed = (
            "PARTIALLY_REACHABLE" if exc.reason_code == "HELM_RENDER_FAILED"
            else "FAIL_CLOSED_PRODUCT_BOUNDARY"
        )
        failure = {
            "status": observed, "reason_code": exc.reason_code,
            "detail": exc.safe_detail, "request": request,
        }
        return {
            "status": observed,
            "reason_code": exc.reason_code,
            "safe_detail": exc.safe_detail,
            "materialization_identity": None,
            "protected_input_manifest_root": None,
            "scanner_universe_identity": None,
            "resource_count": None,
            "evidence_digest": canonical_sha(failure),
            "request_digest": canonical_sha(request),
            "selected_property_request": surface["selected_property_request"],
        }


def run(manifest_path: Path, output_path: Path) -> None:
    manifest, corpus = validate_manifest(manifest_path)
    if output_path.exists():
        raise RuntimeError("CORPUS_REPLAY_OUTPUT_ALREADY_EXISTS")
    workspace = manifest_path.resolve().parent
    results = []
    with tempfile.TemporaryDirectory(prefix="iacgv-a8-55-corpus-") as temporary:
        extraction_root = Path(temporary) / "repositories"
        rendered_root = Path(temporary) / "rendered"
        repositories = {}
        for repo_id, repository in sorted(manifest["repositories"].items()):
            destination = extraction_root / repo_id
            _safe_extract(
                corpus / repository["archive_path"], destination,
                repository["archive_root_prefix"],
            )
            _install_aux(corpus, repository, destination)
            repositories[repo_id] = destination
        for index, surface in enumerate(manifest["surfaces"], 1):
            outcome = _run_surface(
                surface, repositories[surface["repository_id"]], corpus,
                rendered_root / f"{index:03d}",
            )
            predicted = surface["original_design_prediction"]
            outcome["surface_id"] = surface["surface_id"]
            outcome["repository"] = surface["repository"]
            outcome["commit_sha"] = surface["commit_sha"]
            outcome["artifact_class"] = surface["artifact_class"]
            outcome["root_path"] = surface["root_path"]
            outcome["original_design_prediction"] = predicted
            outcome["comparison_classification"] = (
                "MATCH" if predicted == outcome["status"] else "PENDING_REVIEW"
            )
            results.append(outcome)
            print(
                f"[{index:02d}/55] {surface['surface_id']}: "
                f"{outcome['status']} {outcome['reason_code']}",
                flush=True,
            )
    observed_counts = {}
    for item in results:
        observed_counts[item["status"]] = observed_counts.get(item["status"], 0) + 1
    report = {
        "schema_version": "iac-guard-v-a8-coverage-replay-result-v1",
        "corpus_id": manifest["corpus_id"],
        "manifest_file_sha256": sha256_file(manifest_path),
        "manifest_payload_sha256": manifest["manifest_payload_sha256"],
        "driver_sha256": sha256_file(Path(__file__)),
        "implementation": _source_implementation_identity(workspace),
        "tools": manifest["tool_contract"],
        "protocol": manifest["replay_protocol"],
        "surface_count": len(results),
        "observed_counts": observed_counts,
        "pending_comparison_review": sum(
            item["comparison_classification"] == "PENDING_REVIEW" for item in results
        ),
        "results": results,
    }
    report["replay_evidence_root_sha256"] = canonical_sha(report)
    output_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    manifest, _corpus = validate_manifest(args.manifest)
    if args.validate_only:
        print(json.dumps({
            "status": "PASS", "reason_code": "COVERAGE_CORPUS_VALIDATED",
            "surface_count": manifest["surface_count"],
            "manifest_payload_sha256": manifest["manifest_payload_sha256"],
        }, sort_keys=True))
        return
    if args.output is None:
        parser.error("--output is required unless --validate-only is used")
    run(args.manifest, args.output)


if __name__ == "__main__":
    main()
