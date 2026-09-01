"""Protected OpenTofu file-set selection and bounded source parsing."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from ..models import DomainError, canonical_repo_path
from ..terraform_parser import TerraformParserError, parse_terraform_structure
from .model import canonical_digest


OPENTOFU_FILESET_CONTRACT = "opentofu-fileset-v1"
OPENTOFU_MAX_FILE_BYTES = 4 * 1024 * 1024
OPENTOFU_MAX_JSON_DEPTH = 128
OPENTOFU_MAX_JSON_NODES = 100_000
_EXTENSIONS = (".tofu.json", ".tf.json", ".tofu", ".tf")


@dataclass(frozen=True, slots=True)
class OpenTofuFileEvidence:
    file_path: str
    sha256: str
    size: int
    disposition: str
    file_class: str
    syntax: str
    shadowed_by: str | None
    module_identity: str

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "sha256": self.sha256,
            "size": self.size,
            "disposition": self.disposition,
            "file_class": self.file_class,
            "syntax": self.syntax,
            "shadowed_by": self.shadowed_by,
            "module_identity": self.module_identity,
        }


@dataclass(frozen=True, slots=True)
class ParsedOpenTofuResource:
    identity: str
    resource_type: str
    resource_name: str
    body: Mapping[str, Any]
    attribute_sources: Mapping[str, Mapping[str, Any]]
    module_identity: str


@dataclass(frozen=True, slots=True)
class OpenTofuFileSet:
    files: tuple[OpenTofuFileEvidence, ...]
    resources: tuple[ParsedOpenTofuResource, ...]
    module_issues: tuple[Mapping[str, Any], ...]
    source_set_digest: str


def _suffix(name: str) -> str | None:
    for suffix in _EXTENSIONS:
        if name.endswith(suffix):
            return suffix
    return None


def _base(name: str, suffix: str) -> str:
    return name[:-len(suffix)]


def _file_class(name: str, suffix: str) -> str:
    base = _base(name, suffix)
    return "OVERRIDE" if base == "override" or base.endswith("_override") else "NORMAL"


def _strict_json(content: bytes, relative: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise DomainError(f"OpenTofu JSON {relative} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            content.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                DomainError(f"OpenTofu JSON {relative} contains {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DomainError(f"protected OpenTofu source {relative} is invalid") from exc
    if type(value) is not dict:
        raise DomainError(f"OpenTofu JSON {relative} must contain an object")
    pending: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if depth > OPENTOFU_MAX_JSON_DEPTH:
            raise DomainError(f"OpenTofu JSON {relative} exceeds maximum nesting depth")
        if nodes > OPENTOFU_MAX_JSON_NODES:
            raise DomainError(f"OpenTofu JSON {relative} exceeds maximum node count")
        if type(current) is dict:
            pending.extend((item, depth + 1) for item in current.values())
        elif type(current) is list:
            pending.extend((item, depth + 1) for item in current)
    return value


def _document(content: bytes, relative: str, syntax: str) -> tuple[dict[str, Any], str]:
    try:
        text = content.decode("utf-8", errors="strict")
        if syntax == "JSON":
            return _strict_json(content, relative), text
        return parse_terraform_structure(content).document, text
    except (UnicodeDecodeError, TerraformParserError) as exc:
        raise DomainError(f"protected OpenTofu source {relative} is invalid") from exc


def _resource_blocks(document: Mapping[str, Any], syntax: str) -> tuple[tuple[str, str, Mapping[str, Any]], ...]:
    raw = document.get("resource", {} if syntax == "JSON" else [])
    outer = [raw] if type(raw) is dict else raw
    if type(outer) is not list:
        raise DomainError("OpenTofu resource structure is invalid")
    result: list[tuple[str, str, Mapping[str, Any]]] = []
    for block in outer:
        if type(block) is not dict:
            raise DomainError("OpenTofu resource block is invalid")
        for resource_type, instances in block.items():
            if type(resource_type) is not str or type(instances) is not dict:
                raise DomainError("OpenTofu resource identity is invalid")
            for resource_name, body in instances.items():
                if type(resource_name) is not str or type(body) is not dict:
                    raise DomainError("OpenTofu resource body is invalid")
                result.append((resource_type, resource_name, body))
    return tuple(result)


def _module_blocks(document: Mapping[str, Any], syntax: str) -> tuple[tuple[str, Mapping[str, Any]], ...]:
    raw = document.get("module", {} if syntax == "JSON" else [])
    outer = [raw] if type(raw) is dict else raw
    if type(outer) is not list:
        raise DomainError("OpenTofu module structure is invalid")
    result: list[tuple[str, Mapping[str, Any]]] = []
    for block in outer:
        if type(block) is not dict:
            raise DomainError("OpenTofu module block is invalid")
        for name, body in block.items():
            if type(name) is not str or type(body) is not dict:
                raise DomainError("OpenTofu module identity is invalid")
            result.append((name, body))
    return tuple(result)


def _select_module_files(
    project_root: Path,
    module_dir: Path,
    module_identity: str,
    read_regular: Callable[[Path], bytes],
) -> tuple[tuple[OpenTofuFileEvidence, bytes], ...]:
    candidates: dict[str, tuple[Path, bytes, str, str]] = {}
    try:
        children = tuple(module_dir.iterdir())
    except OSError as exc:
        raise DomainError("protected OpenTofu module is unreadable") from exc
    for path in children:
        suffix = _suffix(path.name)
        if suffix is None:
            continue
        content = read_regular(path)
        if len(content) > OPENTOFU_MAX_FILE_BYTES:
            raise DomainError("protected OpenTofu source exceeds maximum file size")
        relative = canonical_repo_path(path.relative_to(project_root).as_posix())
        syntax = "JSON" if suffix.endswith(".json") else "HCL"
        candidates[path.name] = (path, content, suffix, syntax)
    if not candidates:
        raise DomainError("protected OpenTofu module contains no eligible source files")

    shadowed: dict[str, str] = {}
    for name, (_, _, suffix, _) in candidates.items():
        base = _base(name, suffix)
        if suffix == ".tf" and f"{base}.tofu" in candidates:
            shadowed[name] = f"{base}.tofu"
        elif suffix == ".tf.json" and f"{base}.tofu.json" in candidates:
            shadowed[name] = f"{base}.tofu.json"

    selected: list[tuple[OpenTofuFileEvidence, bytes]] = []
    for name in sorted(candidates):
        _, content, suffix, syntax = candidates[name]
        relative = canonical_repo_path((module_dir / name).relative_to(project_root).as_posix())
        winner = shadowed.get(name)
        evidence = OpenTofuFileEvidence(
            relative,
            hashlib.sha256(content).hexdigest(),
            len(content),
            "SHADOWED_BY_TOFU" if winner else "EFFECTIVE",
            _file_class(name, suffix),
            syntax,
            canonical_repo_path((module_dir / winner).relative_to(project_root).as_posix()) if winner else None,
            module_identity,
        )
        selected.append((evidence, content))
    return tuple(selected)


def load_opentofu_file_set(
    project_root: Path,
    read_regular: Callable[[Path], bytes],
) -> OpenTofuFileSet:
    """Load one protected OpenTofu root and bounded literal local-module closure."""
    files: list[OpenTofuFileEvidence] = []
    resources: list[ParsedOpenTofuResource] = []
    issues: list[Mapping[str, Any]] = []
    pending: list[tuple[str, Path, tuple[Path, ...]]] = [("root", project_root, ())]
    visited: set[tuple[str, Path]] = set()

    while pending:
        module_identity, module_dir, ancestors = pending.pop(0)
        resolved = module_dir.resolve(strict=True)
        try:
            resolved.relative_to(project_root)
        except ValueError as exc:
            raise DomainError("OpenTofu local module escapes the protected root") from exc
        if module_dir.is_symlink() or resolved in ancestors:
            raise DomainError("OpenTofu local module symlink or cycle is unsupported")
        key = (module_identity, resolved)
        if key in visited:
            continue
        visited.add(key)
        selected = _select_module_files(project_root, resolved, module_identity, read_regular)
        files.extend(item[0] for item in selected)
        effective = tuple(item for item in selected if item[0].disposition == "EFFECTIVE")
        normal = tuple(item for item in effective if item[0].file_class == "NORMAL")
        overrides = tuple(item for item in effective if item[0].file_class == "OVERRIDE")

        resource_map: dict[str, dict[str, Any]] = {}
        module_calls: list[tuple[str, Mapping[str, Any], OpenTofuFileEvidence]] = []
        for evidence, content in normal:
            document, source_text = _document(content, evidence.file_path, evidence.syntax)
            for resource_type, resource_name, body in _resource_blocks(document, evidence.syntax):
                local = f"{resource_type}.{resource_name}"
                if local in resource_map:
                    raise DomainError("duplicate effective OpenTofu resource identity")
                definition_origin = {
                    "file_path": evidence.file_path,
                    "source_sha256": evidence.sha256,
                    "source_format": evidence.syntax,
                    "source_text": source_text,
                }
                origins = {
                    name: {
                        "file_path": evidence.file_path,
                        "source_sha256": evidence.sha256,
                        "source_format": evidence.syntax,
                        "source_text": source_text,
                    }
                    for name in body
                }
                origins["__resource__"] = definition_origin
                resource_map[local] = {
                    "type": resource_type, "name": resource_name,
                    "body": dict(body), "origins": origins,
                }
            module_calls.extend(
                (name, body, evidence) for name, body in _module_blocks(document, evidence.syntax)
            )

        for evidence, content in overrides:
            document, source_text = _document(content, evidence.file_path, evidence.syntax)
            if _module_blocks(document, evidence.syntax):
                issues.append({
                    "module_identity": module_identity,
                    "reason": "OPENTOFU_MODULE_OVERRIDE_UNSUPPORTED",
                    "file_path": evidence.file_path,
                })
            for resource_type, resource_name, body in _resource_blocks(document, evidence.syntax):
                local = f"{resource_type}.{resource_name}"
                current = resource_map.get(local)
                if current is None:
                    raise DomainError("OpenTofu override resource has no protected base resource")
                for name, value in body.items():
                    if type(value) in (dict, list):
                        issues.append({
                            "module_identity": module_identity,
                            "reason": "OPENTOFU_COMPLEX_OVERRIDE_UNSUPPORTED",
                            "file_path": evidence.file_path,
                            "resource": local,
                            "attribute": name,
                        })
                        continue
                    current["body"][name] = value
                    current["origins"][name] = {
                        "file_path": evidence.file_path,
                        "source_sha256": evidence.sha256,
                        "source_format": evidence.syntax,
                        "source_text": source_text,
                    }

        prefix = "" if module_identity == "root" else f"{module_identity}::"
        for local in sorted(resource_map):
            item = resource_map[local]
            resources.append(ParsedOpenTofuResource(
                f"{prefix}{local}", item["type"], item["name"],
                item["body"], item["origins"], module_identity,
            ))

        for name, body, evidence in sorted(module_calls, key=lambda item: item[0]):
            source = body.get("source")
            child_identity = f"module.{name}" if module_identity == "root" else f"{module_identity}.module.{name}"
            if type(source) is not str or source.startswith("${"):
                issues.append({
                    "module_identity": child_identity,
                    "reason": "OPENTOFU_DYNAMIC_MODULE_SOURCE_UNSUPPORTED",
                    "file_path": evidence.file_path,
                })
                continue
            if not source.startswith(("./", "../")):
                issues.append({
                    "module_identity": child_identity,
                    "reason": "OPENTOFU_REMOTE_MODULE_UNSUPPORTED",
                    "file_path": evidence.file_path,
                    "source": source,
                })
                continue
            candidate = resolved / source
            if candidate.is_symlink():
                raise DomainError("OpenTofu local module symlink is unsupported")
            child = candidate.resolve(strict=False)
            try:
                child.relative_to(project_root)
            except ValueError:
                raise DomainError("OpenTofu local module escapes the protected root")
            if not child.exists() or not child.is_dir():
                issues.append({
                    "module_identity": child_identity,
                    "reason": "OPENTOFU_LOCAL_MODULE_MISSING",
                    "file_path": evidence.file_path,
                })
                continue
            pending.append((child_identity, child, ancestors + (resolved,)))

    files.sort(key=lambda item: (item.module_identity, item.file_path))
    resources.sort(key=lambda item: item.identity)
    identities = [item.identity for item in resources]
    if len(identities) != len(set(identities)):
        raise DomainError("duplicate effective OpenTofu resource identity")
    issues.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    digest = canonical_digest({
        "contract": OPENTOFU_FILESET_CONTRACT,
        "files": [item.canonical_dict() for item in files],
        "modules": sorted({item.module_identity for item in files}),
        "issues": issues,
    })
    return OpenTofuFileSet(tuple(files), tuple(resources), tuple(issues), digest)


__all__ = [
    "OPENTOFU_FILESET_CONTRACT", "OPENTOFU_MAX_FILE_BYTES",
    "OPENTOFU_MAX_JSON_DEPTH", "OPENTOFU_MAX_JSON_NODES",
    "OpenTofuFileEvidence", "OpenTofuFileSet",
    "ParsedOpenTofuResource", "load_opentofu_file_set",
]
