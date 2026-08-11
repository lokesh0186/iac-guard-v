"""Loader-attested policy provenance and the closed verdict boundary."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import InitVar, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from .engine import (
    GovernedConfigEvidence,
    VerificationResult,
    require_trusted_verification_result,
)
from .enums import (
    EXIT_CODES,
    INCONCLUSIVE_OUTCOMES,
    PASSING_OUTCOMES,
    TRUSTED_EXCEPTION_ORIGINS,
    UNDECIDED_STATES,
    ExceptionOrigin,
    ArtifactKind,
    Outcome,
    Status,
    Verdict,
)
from .models import (
    DomainError,
    ExceptionPolicy,
    ExceptionRecord,
    ResolvedTargetBinding,
    TargetDecision,
    TargetIdentity,
    canonical_identifier,
    canonical_repo_path,
    require_date,
    require_enum,
    require_exact_type,
    validate_permitted_outcomes,
)


_TRUSTED_BUNDLE_CONTEXT = object()
_TRUSTED_POLICY_CONTEXT = object()
_TRUSTED_POLICY_EVIDENCE_CONTEXT = object()
_TRUSTED_GIT_SOURCE_CONTEXT = object()
_OPTIONAL_GATE_NAMES = frozenset({"regression", "suppression"})
_POLICY_FIELDS = frozenset({"exceptions", "optional_gates"})
_EXCEPTION_FIELDS = frozenset({
    "exception_id", "target", "reason", "owner", "created", "expires", "origin",
    "permitted_outcomes",
})
_TARGET_FIELDS = frozenset({
    "scanner", "rule_id", "scope", "file_path", "artifact_kind",
    "scanner_native_lookup",
})
_MAX_POLICY_BYTES = 1024 * 1024
_MAX_POLICY_JSON_DEPTH = 64
_CANDIDATE_POLICY_STATES = frozenset({"present", "missing", "not_compared"})
_GIT_SHA = __import__("re").compile(r"^[0-9a-f]{40,64}$")


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _git_command(repository: Path, arguments: tuple[str, ...]) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        raise DomainError("git executable is unavailable for source attestation")
    try:
        result = subprocess.run(
            [
                executable,
                "-c", "core.hooksPath=/dev/null",
                "-c", "credential.helper=",
                *arguments,
            ],
            cwd=repository,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DomainError("git policy-source attestation failed") from exc
    if result.returncode != 0:
        raise DomainError("git policy-source object could not be resolved")
    return result.stdout


def _resolve_git_commit(repository: Path, ref: str) -> str:
    if type(ref) is not str or not ref or ref.startswith("-") or any(
        ord(char) < 0x20 or char == "\x7f" for char in ref
    ):
        raise DomainError("git base ref is malformed")
    output = _git_command(
        repository, ("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
    ).decode("ascii", errors="strict").strip()
    if not _GIT_SHA.fullmatch(output):
        raise DomainError("git base ref did not resolve to a commit SHA")
    return output


def _require_git_repository_root(repository: Path) -> None:
    try:
        reported = Path(
            _git_command(repository, ("rev-parse", "--show-toplevel"))
            .decode("utf-8", errors="strict")
            .strip()
        ).resolve(strict=True)
    except (OSError, UnicodeError) as exc:
        raise DomainError("Git repository root evidence is malformed") from exc
    if reported != repository:
        raise DomainError("Git policy source must name the canonical repository root")


def _git_object_bytes(repository: Path, commit: str, relative: str) -> bytes:
    relative = canonical_repo_path(relative, "Git governed path")
    object_name = f"{commit}:{relative}"
    tree_entry = _git_command(
        repository, ("ls-tree", "-z", commit, "--", relative)
    )
    if not tree_entry.endswith(b"\x00") or b"\t" not in tree_entry:
        raise DomainError("Git policy object has no exact tree entry")
    metadata, recorded_path = tree_entry[:-1].split(b"\t", 1)
    fields = metadata.split()
    if (
        len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or recorded_path.decode("utf-8", errors="strict") != relative
    ):
        raise DomainError("Git policy object must be a regular repository file")
    size_raw = _git_command(repository, ("cat-file", "-s", object_name))
    try:
        size = int(size_raw.decode("ascii", errors="strict").strip())
    except ValueError as exc:
        raise DomainError("Git policy object size is malformed") from exc
    if size <= 0:
        raise DomainError("Git policy object must be nonempty")
    if size > _MAX_POLICY_BYTES:
        raise DomainError("Git policy object exceeds the trusted byte limit")
    payload = _git_command(repository, ("cat-file", "blob", object_name))
    if len(payload) != size:
        raise DomainError("Git policy object size changed during read")
    return payload


@dataclass(frozen=True, slots=True)
class TrustedGitSource:
    """Mechanically resolved Git source capability for policy loaders."""

    repository_root: Path
    commit_sha: str
    candidate_root: Path
    governed_paths: tuple
    source_origin: ExceptionOrigin
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if _trusted_context is not _TRUSTED_GIT_SOURCE_CONTEXT:
            raise DomainError("TrustedGitSource requires mechanical attestation")
        for name in ("repository_root", "candidate_root"):
            value = getattr(self, name)
            if not isinstance(value, Path):
                raise DomainError(f"{name} must be pathlib.Path")
            object.__setattr__(self, name, value.resolve(strict=True))
        if not _GIT_SHA.fullmatch(self.commit_sha):
            raise DomainError("trusted Git commit must be a full commit SHA")
        if type(self.governed_paths) is not tuple or not self.governed_paths:
            raise DomainError("trusted Git governed paths must be a nonempty tuple")
        paths = tuple(sorted({canonical_repo_path(item) for item in self.governed_paths}))
        if len(paths) != len(self.governed_paths):
            raise DomainError("trusted Git governed paths contain duplicates")
        object.__setattr__(self, "governed_paths", paths)
        require_enum(self.source_origin, ExceptionOrigin, "Git policy source origin")
        if self.source_origin not in {
            ExceptionOrigin.TRUSTED_BASE, ExceptionOrigin.PROTECTED_POLICY_REPO
        }:
            raise DomainError("Git policy source origin is not protected")
        object.__setattr__(self, "_trusted", True)

    @property
    def source_identity(self) -> str:
        prefix = (
            "git_commit" if self.source_origin is ExceptionOrigin.TRUSTED_BASE
            else "protected_git_commit"
        )
        return f"{prefix}_{self.commit_sha}"


def attest_git_source(
    repository_root: Path,
    base_ref: str,
    candidate_root: Path,
    governed_paths: tuple,
) -> TrustedGitSource:
    """Resolve a base ref to an actual commit and stamp a non-serializable capability."""
    if not isinstance(repository_root, Path) or not isinstance(candidate_root, Path):
        raise DomainError("Git source roots must be pathlib.Path")
    try:
        repository = repository_root.resolve(strict=True)
        candidate = candidate_root.resolve(strict=True)
    except OSError as exc:
        raise DomainError("Git source root could not be strictly resolved") from exc
    if not _within(candidate, repository):
        raise DomainError("candidate root must be inside the attested Git repository")
    _require_git_repository_root(repository)
    commit = _resolve_git_commit(repository, base_ref)
    return TrustedGitSource(
        repository, commit, candidate, governed_paths, ExceptionOrigin.TRUSTED_BASE,
        _trusted_context=_TRUSTED_GIT_SOURCE_CONTEXT,
    )


def attest_protected_policy_repository(
    repository_root: Path,
    pinned_commit_sha: str,
    evaluated_workspace: Path,
    governed_paths: tuple,
) -> TrustedGitSource:
    """Attest an exact protected-repository commit outside evaluated workspace."""
    if not isinstance(repository_root, Path) or not isinstance(evaluated_workspace, Path):
        raise DomainError("protected policy roots must be pathlib.Path")
    try:
        repository = repository_root.resolve(strict=True)
        workspace = evaluated_workspace.resolve(strict=True)
    except OSError as exc:
        raise DomainError("protected policy roots could not be strictly resolved") from exc
    if _within(repository, workspace) or _within(workspace, repository):
        raise DomainError("protected policy repository must be outside evaluated workspace")
    _require_git_repository_root(repository)
    if not _GIT_SHA.fullmatch(pinned_commit_sha):
        raise DomainError("protected policy commit must be a pinned full SHA")
    try:
        resolved = _resolve_git_commit(repository, pinned_commit_sha)
    except DomainError as exc:
        raise DomainError("protected policy pinned commit could not be resolved") from exc
    if resolved != pinned_commit_sha:
        raise DomainError("protected policy repository did not resolve the pinned commit")
    return TrustedGitSource(
        repository, resolved, workspace, governed_paths,
        ExceptionOrigin.PROTECTED_POLICY_REPO,
        _trusted_context=_TRUSTED_GIT_SOURCE_CONTEXT,
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise DomainError(f"duplicate policy JSON key: {key!r}")
        result[key] = value
    return result


def _json_depth(payload: bytes) -> None:
    """Enforce depth without relying on CPython's decoder recursion threshold."""
    in_string = escaped = False
    depth = 0
    for byte in payload:
        char = chr(byte)
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > _MAX_POLICY_JSON_DEPTH:
                raise DomainError("policy JSON depth exceeds the trusted limit")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise DomainError("policy JSON structure is unbalanced")


def _parse_policy_bytes(payload: bytes) -> dict:
    if type(payload) is not bytes or not payload or len(payload) > _MAX_POLICY_BYTES:
        raise DomainError("policy bytes must be nonempty and within the trusted limit")
    _json_depth(payload)
    try:
        parsed = json.loads(payload, object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DomainError("policy document must be strict JSON") from exc
    if type(parsed) is not dict:
        raise DomainError("policy document must be a JSON object")
    return parsed


def _canonical_payload(payload: Mapping) -> bytes:
    if type(payload) is not dict:
        raise DomainError("policy payload must be an exact dict")
    try:
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise DomainError("policy payload must contain bounded JSON values") from exc
    return encoded


def _read_policy_bytes(path: Path, *, required: bool) -> bytes | None:
    if not isinstance(path, Path):
        raise DomainError("policy source must be a pathlib.Path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if not required:
            return None
        raise DomainError("trusted policy source does not exist") from None
    except OSError as exc:
        raise DomainError("policy source could not be opened with no-follow safeguards") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise DomainError("policy source must be a regular file")
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, _MAX_POLICY_BYTES + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_POLICY_BYTES:
                raise DomainError("policy source exceeds the trusted byte limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _parse_date(value: object, name: str) -> date:
    if type(value) is not str:
        raise DomainError(f"{name} must be an ISO date string")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise DomainError(f"{name} must be an ISO date string") from exc
    if parsed.isoformat() != value:
        raise DomainError(f"{name} must use canonical YYYY-MM-DD form")
    return parsed


def _parse_outcomes(value: object) -> frozenset:
    if type(value) is not list or not value:
        raise DomainError("permitted_outcomes must be a nonempty JSON array")
    if any(type(item) is not str for item in value):
        raise DomainError("permitted_outcomes entries must be exact strings")
    if len(value) != len(set(value)):
        raise DomainError("permitted_outcomes must not contain duplicates")
    try:
        outcomes = frozenset(Outcome(item) for item in value)
    except ValueError as exc:
        raise DomainError("permitted_outcomes contains an unknown outcome") from exc
    return validate_permitted_outcomes(outcomes)


def _build_exception(payload: Mapping, origin: ExceptionOrigin) -> ExceptionRecord:
    if type(payload) is not dict:
        raise DomainError("exception record must be an exact JSON object")
    unknown = set(payload) - _EXCEPTION_FIELDS
    if unknown:
        raise DomainError(f"unknown exception fields: {sorted(unknown)}")
    target = payload.get("target")
    if type(target) is not dict or set(target) != _TARGET_FIELDS:
        raise DomainError(
            "exception target must contain exact scanner/rule/resource/file/artifact/native identity"
        )
    identity = TargetIdentity(target["scanner"], target["rule_id"], target["scope"])
    try:
        artifact_kind = ArtifactKind(target["artifact_kind"])
    except (TypeError, ValueError) as exc:
        raise DomainError("exception target artifact_kind is unsupported") from exc
    binding = ResolvedTargetBinding(
        identity,
        target["file_path"],
        artifact_kind,
        target["scanner_native_lookup"],
    )
    return ExceptionRecord(
        exception_id=payload.get("exception_id", ""),
        target=identity,
        reason=payload.get("reason", ""),
        owner=payload.get("owner", ""),
        created=_parse_date(payload.get("created"), "exception created"),
        expires=_parse_date(payload.get("expires"), "exception expires"),
        origin=origin,
        permitted_outcomes=_parse_outcomes(payload.get("permitted_outcomes")),
        resolved_target=binding,
    )


def load_trusted_exception(
    payload: Mapping, origin: ExceptionOrigin
) -> ExceptionRecord:
    """Stamp an exception read through a trusted loader; ignore payload ``origin``."""
    require_enum(origin, ExceptionOrigin, "trusted exception source")
    if origin not in TRUSTED_EXCEPTION_ORIGINS:
        raise DomainError("trusted exception loader requires a protected source")
    return _build_exception(payload, origin)


def load_candidate_exception(payload: Mapping) -> ExceptionRecord:
    """Stamp candidate policy data as untrusted, ignoring any claimed origin."""
    return _build_exception(payload, ExceptionOrigin.CANDIDATE_HEAD)


def _parse_document(payload: Mapping, origin: ExceptionOrigin) -> tuple[ExceptionPolicy, frozenset]:
    if type(payload) is not dict:
        raise DomainError("policy payload must be an exact JSON object")
    unknown = set(payload) - _POLICY_FIELDS
    if unknown:
        raise DomainError(f"unknown policy fields: {sorted(unknown)}")
    raw_records = payload.get("exceptions", [])
    if type(raw_records) is not list:
        raise DomainError("policy exceptions must be a JSON array")
    records = tuple(
        load_trusted_exception(item, origin)
        if origin in TRUSTED_EXCEPTION_ORIGINS else load_candidate_exception(item)
        for item in raw_records
    )
    raw_optional = payload.get("optional_gates", [])
    if type(raw_optional) is not list or any(type(item) is not str for item in raw_optional):
        raise DomainError("optional_gates must be a JSON array of exact strings")
    if len(raw_optional) != len(set(raw_optional)):
        raise DomainError("optional_gates must not contain duplicates")
    optional = frozenset(raw_optional)
    unknown_optional = optional - _OPTIONAL_GATE_NAMES
    if unknown_optional:
        raise DomainError(f"unknown optional gates: {sorted(unknown_optional)}")
    return ExceptionPolicy(records), optional


def _capture_time(clock: Callable[[], datetime] | None) -> tuple[date, str, str]:
    value = datetime.now(timezone.utc) if clock is None else clock()
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise DomainError("trusted policy clock must return a timezone-aware datetime")
    utc = value.astimezone(timezone.utc)
    return utc.date(), "UTC", "trusted_execution_clock"


@dataclass(frozen=True, slots=True)
class TrustedPolicyBundle:
    """Immutable policy material carrying private loader provenance."""

    policy: ExceptionPolicy
    optional_gates: frozenset
    source_origin: ExceptionOrigin
    source_identity: str
    trusted_policy_sha256: str
    candidate_policy_sha256: str | None
    candidate_policy_state: str
    differing_governed_paths: tuple
    evaluation_date: date
    evaluation_timezone: str
    evaluation_time_provenance: str
    governed_config_evidence: tuple = ()
    source_repository: str = ""
    source_commit: str = ""
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_exact_type(self.policy, ExceptionPolicy, "trusted exception policy")
        if type(self.optional_gates) is not frozenset or not self.optional_gates <= _OPTIONAL_GATE_NAMES:
            raise DomainError("trusted optional gates are malformed")
        require_enum(self.source_origin, ExceptionOrigin, "policy source origin")
        if self.source_origin not in TRUSTED_EXCEPTION_ORIGINS:
            raise DomainError("TrustedPolicyBundle requires a protected source")
        object.__setattr__(
            self, "source_identity", canonical_identifier(self.source_identity, "policy source identity")
        )
        value = self.trusted_policy_sha256
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise DomainError("trusted_policy_sha256 must be a lowercase SHA-256 digest")
        if self.candidate_policy_state not in _CANDIDATE_POLICY_STATES:
            raise DomainError("candidate policy state is invalid")
        if self.candidate_policy_state == "present":
            value = self.candidate_policy_sha256
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise DomainError("candidate_policy_sha256 must bind present candidate bytes")
        elif self.candidate_policy_sha256 is not None:
            raise DomainError("absent or unobserved candidate policy has no byte digest")
        if type(self.differing_governed_paths) is not tuple:
            raise DomainError("differing governed paths must be an exact tuple")
        paths = tuple(sorted({canonical_repo_path(item) for item in self.differing_governed_paths}))
        object.__setattr__(self, "differing_governed_paths", paths)
        drift_expected = (
            any(item.state != "stable" for item in self.governed_config_evidence)
            if self.governed_config_evidence
            else (
                self.candidate_policy_state == "missing"
                or (
                    self.candidate_policy_state == "present"
                    and self.trusted_policy_sha256 != self.candidate_policy_sha256
                )
            )
        )
        if drift_expected != bool(paths):
            raise DomainError("policy digests and differing governed paths contradict")
        require_date(self.evaluation_date, "trusted evaluation date")
        if self.evaluation_timezone != "UTC":
            raise DomainError("trusted policy evaluation timezone must be UTC")
        object.__setattr__(
            self,
            "evaluation_time_provenance",
            canonical_identifier(self.evaluation_time_provenance, "evaluation time provenance"),
        )
        if any(record.origin is not self.source_origin for record in self.policy.records):
            raise DomainError("exception origin disagrees with its policy loader")
        if any(record.resolved_target is None for record in self.policy.records):
            raise DomainError("trusted exceptions require exact resolved target binding")
        if type(self.governed_config_evidence) is not tuple or any(
            type(item) is not GovernedConfigEvidence
            for item in self.governed_config_evidence
        ):
            raise DomainError("governed policy evidence must be an exact typed tuple")
        if self.governed_config_evidence:
            evidence_paths = tuple(sorted(
                item.file_path for item in self.governed_config_evidence
                if item.state != "stable"
            ))
            if evidence_paths != self.differing_governed_paths:
                raise DomainError("governed policy evidence contradicts differing paths")
        if self.source_commit:
            if not _GIT_SHA.fullmatch(self.source_commit):
                raise DomainError("policy source commit must be a full Git SHA")
            if not self.source_repository:
                raise DomainError("Git policy evidence requires repository identity")
        elif self.source_repository:
            raise DomainError("non-Git policy evidence cannot claim a repository")
        if _trusted_context is not _TRUSTED_BUNDLE_CONTEXT:
            raise DomainError("TrustedPolicyBundle requires production loader provenance")
        object.__setattr__(self, "_trusted", True)

    @property
    def policy_drift(self) -> bool:
        return bool(self.differing_governed_paths)

    def canonical_dict(self) -> dict:
        return {
            "source_identity": self.source_identity,
            "source_origin": self.source_origin.value,
            "trusted_policy_sha256": self.trusted_policy_sha256,
            "candidate_policy_sha256": self.candidate_policy_sha256,
            "candidate_policy_state": self.candidate_policy_state,
            "differing_governed_paths": list(self.differing_governed_paths),
            "optional_gates": sorted(self.optional_gates),
            "evaluation_date": self.evaluation_date.isoformat(),
            "evaluation_timezone": self.evaluation_timezone,
            "evaluation_time_provenance": self.evaluation_time_provenance,
            "governed_config_evidence": [
                item.canonical_dict() for item in self.governed_config_evidence
            ],
            "source_repository": self.source_repository,
            "source_commit": self.source_commit,
        }


def _bundle(
    trusted_payload: dict,
    trusted_bytes: bytes,
    candidate_bytes: bytes | None,
    candidate_state: str,
    origin: ExceptionOrigin,
    source_identity: str,
    governed_path: str,
    clock: Callable[[], datetime] | None,
    *,
    governed_evidence: tuple = (),
    source_repository: str = "",
    source_commit: str = "",
) -> TrustedPolicyBundle:
    require_enum(origin, ExceptionOrigin, "policy loader origin")
    if origin not in TRUSTED_EXCEPTION_ORIGINS:
        raise DomainError("trusted policy bundle requires a protected source")
    governed_path = canonical_repo_path(governed_path, "governed policy path")
    policy, optional = _parse_document(trusted_payload, origin)
    trusted_digest = _sha256(trusted_bytes)
    if candidate_state == "present":
        if candidate_bytes is None:
            raise DomainError("present candidate policy requires bytes")
        candidate_digest = _sha256(candidate_bytes)
    else:
        candidate_digest = None
    differs = (
        candidate_state == "missing"
        or (candidate_state == "present" and candidate_digest != trusted_digest)
    )
    differing = (
        tuple(item.file_path for item in governed_evidence if item.state != "stable")
        if governed_evidence else (governed_path,) if differs else ()
    )
    evaluated, zone, provenance = _capture_time(clock)
    return TrustedPolicyBundle(
        policy,
        optional,
        origin,
        source_identity,
        trusted_digest,
        candidate_digest,
        candidate_state,
        differing,
        evaluated,
        zone,
        provenance,
        governed_evidence,
        source_repository,
        source_commit,
        _trusted_context=_TRUSTED_BUNDLE_CONTEXT,
    )


def _optional_git_object(source: TrustedGitSource, relative: str) -> bytes | None:
    relative = canonical_repo_path(relative)
    entry = _git_command(
        source.repository_root,
        ("ls-tree", "-z", source.commit_sha, "--", relative),
    )
    if entry == b"":
        return None
    return _git_object_bytes(source.repository_root, source.commit_sha, relative)


def _source_governed_evidence(source: TrustedGitSource) -> tuple:
    evidence = []
    for relative in source.governed_paths:
        trusted = _optional_git_object(source, relative)
        candidate = _read_policy_bytes(source.candidate_root / relative, required=False)
        if trusted is None and candidate is None:
            continue
        trusted_digest = None if trusted is None else _sha256(trusted)
        candidate_digest = None if candidate is None else _sha256(candidate)
        state = (
            "added" if trusted is None
            else "removed" if candidate is None
            else "stable" if trusted_digest == candidate_digest
            else "changed"
        )
        evidence.append(
            GovernedConfigEvidence(
                relative, trusted_digest, candidate_digest, state
            )
        )
    return tuple(evidence)


def _load_git_source_bundle(
    source: TrustedGitSource,
    origin: ExceptionOrigin,
    governed_path: str,
    clock: Callable[[], datetime] | None,
) -> TrustedPolicyBundle:
    require_exact_type(source, TrustedGitSource, "attested Git policy source")
    if not source._trusted or source.source_origin is not origin:
        raise DomainError("Git policy source provenance does not match loader")
    governed_path = canonical_repo_path(governed_path, "governed policy path")
    if governed_path not in source.governed_paths:
        raise DomainError("governed policy path is outside the attested Git source")
    trusted_bytes = _git_object_bytes(
        source.repository_root, source.commit_sha, governed_path
    )
    candidate_bytes = _read_policy_bytes(
        source.candidate_root / governed_path, required=False
    )
    candidate_state = "missing" if candidate_bytes is None else "present"
    repository_identity = "git_repo_" + _sha256(
        str(source.repository_root).encode("utf-8")
    )
    return _bundle(
        _parse_policy_bytes(trusted_bytes),
        trusted_bytes,
        candidate_bytes,
        candidate_state,
        origin,
        source.source_identity,
        governed_path,
        clock,
        governed_evidence=_source_governed_evidence(source),
        source_repository=repository_identity,
        source_commit=source.commit_sha,
    )


def load_base_commit_policy(
    source: TrustedGitSource,
    *,
    governed_path: str = ".iac-guard.json",
    _clock: Callable[[], datetime] | None = None,
) -> TrustedPolicyBundle:
    return _load_git_source_bundle(
        source, ExceptionOrigin.TRUSTED_BASE, governed_path, _clock
    )


def load_protected_policy_repository(
    source: TrustedGitSource,
    *,
    governed_path: str = ".iac-guard.json",
    _clock: Callable[[], datetime] | None = None,
) -> TrustedPolicyBundle:
    return _load_git_source_bundle(
        source, ExceptionOrigin.PROTECTED_POLICY_REPO, governed_path, _clock
    )


def load_operator_policy(
    trusted_payload: Mapping,
    *,
    source_identity: str,
    candidate_payload: Mapping | None = None,
    governed_path: str = ".iac-guard.json",
    _clock: Callable[[], datetime] | None = None,
) -> TrustedPolicyBundle:
    trusted_bytes = _canonical_payload(trusted_payload)
    candidate_bytes = (
        None if candidate_payload is None else _canonical_payload(candidate_payload)
    )
    candidate_state = "not_compared" if candidate_payload is None else "present"
    return _bundle(
        _parse_policy_bytes(trusted_bytes), trusted_bytes, candidate_bytes,
        candidate_state, ExceptionOrigin.OPERATOR, source_identity, governed_path, _clock,
    )


def load_candidate_policy(source: Mapping | Path) -> ExceptionPolicy:
    """Parse candidate policy for reporting; it can never create a trusted bundle."""
    if isinstance(source, Path):
        raw = _read_policy_bytes(source, required=True)
        payload = _parse_policy_bytes(raw)
    elif type(source) is dict:
        payload = _parse_policy_bytes(_canonical_payload(source))
    else:
        raise DomainError("candidate policy source must be an exact dict or pathlib.Path")
    policy, _optional = _parse_document(payload, ExceptionOrigin.CANDIDATE_HEAD)
    return policy


@dataclass(frozen=True, slots=True)
class AppliedExceptionSource:
    exception_id: str
    source_origin: ExceptionOrigin
    source_identity: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "exception_id", canonical_identifier(self.exception_id, "exception id"))
        require_enum(self.source_origin, ExceptionOrigin, "exception source origin")
        object.__setattr__(
            self, "source_identity", canonical_identifier(self.source_identity, "exception source identity")
        )

    def canonical_dict(self) -> dict:
        return {
            "exception_id": self.exception_id,
            "source_origin": self.source_origin.value,
            "source_identity": self.source_identity,
        }


@dataclass(frozen=True, slots=True)
class PolicyEvidence:
    bundle: TrustedPolicyBundle
    applied_exception_sources: tuple
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_exact_type(self.bundle, TrustedPolicyBundle, "policy evidence bundle")
        if not self.bundle._trusted:
            raise DomainError("policy evidence bundle lacks loader provenance")
        if type(self.applied_exception_sources) is not tuple or any(
            type(item) is not AppliedExceptionSource for item in self.applied_exception_sources
        ):
            raise DomainError("applied exception sources must be typed evidence")
        ids = [item.exception_id for item in self.applied_exception_sources]
        if len(ids) != len(set(ids)):
            raise DomainError("applied exception source ids must be unique")
        if _trusted_context is not _TRUSTED_POLICY_EVIDENCE_CONTEXT:
            raise DomainError("PolicyEvidence requires trusted policy evaluation")
        object.__setattr__(
            self, "applied_exception_sources",
            tuple(sorted(self.applied_exception_sources, key=lambda item: item.exception_id)),
        )
        object.__setattr__(self, "_trusted", True)

    def canonical_dict(self) -> dict:
        result = self.bundle.canonical_dict()
        result["applied_exception_sources"] = [
            item.canonical_dict() for item in self.applied_exception_sources
        ]
        return result


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """Factory-proven engine evidence plus one loader-attested policy bundle."""

    verification: VerificationResult
    policy_bundle: TrustedPolicyBundle

    def __post_init__(self) -> None:
        require_trusted_verification_result(self.verification)
        require_exact_type(self.policy_bundle, TrustedPolicyBundle, "TrustedPolicyBundle")
        if not self.policy_bundle._trusted:
            raise DomainError("TrustedPolicyBundle lacks loader provenance")


def _permission_for(
    binding: ResolvedTargetBinding,
    outcome: Outcome,
    policy: ExceptionPolicy,
    evaluation_date: date,
) -> TargetDecision:
    matching = tuple(
        record for record in policy.records
        if record.resolved_target is not None
        and record.resolved_target.canonical_key == binding.canonical_key
        and outcome in record.permitted_outcomes
    )
    rejection = ""
    for record in matching:
        if record.origin not in TRUSTED_EXCEPTION_ORIGINS:
            rejection = f"exception origin {record.origin.value!r} is not trusted"
            continue
        if evaluation_date < record.created:
            rejection = "exception is not yet in force"
            continue
        if evaluation_date > record.expires:
            rejection = "exception is expired"
            continue
        return TargetDecision(
            binding.identity, outcome, True, record.exception_id,
            resolved_target=binding,
        )
    if not rejection and outcome is not Outcome.FIXED:
        rejection = "no trusted target-scoped exception authorises this outcome"
    return TargetDecision(
        binding.identity, outcome, False, rejection_reason=rejection,
        resolved_target=binding,
    )


def _gate_undecided(status: Status, name: str, optional: frozenset) -> bool:
    if status is Status.SKIPPED and name in optional:
        return False
    return status in UNDECIDED_STATES


@dataclass(frozen=True, slots=True)
class PolicyResult:
    verdict: Verdict
    exit_code: int
    decisions: tuple
    policy_evidence: PolicyEvidence
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_enum(self.verdict, Verdict, "verdict")
        if type(self.exit_code) is not int or self.exit_code != EXIT_CODES[self.verdict]:
            raise DomainError("exit_code does not match the closed verdict mapping")
        if type(self.decisions) is not tuple or not self.decisions:
            raise DomainError("policy decisions must be a nonempty exact tuple")
        if any(type(item) is not TargetDecision for item in self.decisions):
            raise DomainError("policy decisions must contain exact TargetDecision values")
        keys = [
            item.identity.canonical_key
            if item.resolved_target is None else item.resolved_target.canonical_key
            for item in self.decisions
        ]
        if len(keys) != len(set(keys)):
            raise DomainError("policy decisions contain duplicate target identities")
        require_exact_type(self.policy_evidence, PolicyEvidence, "policy evidence")
        if not self.policy_evidence._trusted:
            raise DomainError("policy evidence lacks policy-factory provenance")
        if _trusted_context is not _TRUSTED_POLICY_CONTEXT:
            raise DomainError("PolicyResult requires trusted policy evaluation")
        object.__setattr__(self, "decisions", tuple(sorted(self.decisions, key=lambda x: x.canonical_key)))
        object.__setattr__(self, "_trusted", True)

    @property
    def evaluation_date(self) -> date:
        return self.policy_evidence.bundle.evaluation_date

    def canonical_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "exit_code": self.exit_code,
            "evaluation_date": self.evaluation_date.isoformat(),
            "decisions": [item.canonical_dict() for item in self.decisions],
            "policy_evidence": self.policy_evidence.canonical_dict(),
        }


def evaluate_policy(request: PolicyRequest) -> PolicyResult:
    """Evaluate the section-7 table using only loader-attested policy material."""
    require_exact_type(request, PolicyRequest, "policy request")
    engine = require_trusted_verification_result(request.verification)
    bundle = request.policy_bundle
    decisions = tuple(
        _permission_for(
            item.binding, item.outcome, bundle.policy, bundle.evaluation_date
        )
        for item in engine.target_outcomes
    )
    undecided = (
        engine.preflight.status is not Status.PASS
        or engine.scanner_integrity.status is not Status.PASS
        or any(item.status in UNDECIDED_STATES for item in engine.validator_results)
        or any(item.status in UNDECIDED_STATES for item in engine.oracle_results)
        or any(item.outcome in INCONCLUSIVE_OUTCOMES for item in decisions)
        or engine.coverage_decreased_on_required_scanner
        or engine.rule_substituted_on_required_target
        or _gate_undecided(engine.regression.status, "regression", bundle.optional_gates)
        or _gate_undecided(engine.suppression.status, "suppression", bundle.optional_gates)
    )
    if undecided:
        verdict = Verdict.INCONCLUSIVE
    else:
        unresolved = tuple(
            item for item in decisions
            if item.outcome not in PASSING_OUTCOMES and not item.policy_permitted
        )
        failed = (
            any(item.status is Status.FAIL for item in engine.validator_results)
            or any(item.status is Status.FAIL for item in engine.oracle_results)
            or engine.policy_drift
            or bundle.policy_drift
            or bool(unresolved)
            or engine.regression.status is Status.FAIL
            or engine.suppression.status is Status.FAIL
        )
        verdict = Verdict.FAILED if failed else Verdict.VERIFIED
    applied = tuple(
        AppliedExceptionSource(
            decision.exception_id,
            bundle.policy.get(decision.exception_id).origin,
            bundle.source_identity,
        )
        for decision in decisions if decision.policy_permitted
    )
    evidence = PolicyEvidence(
        bundle, applied, _trusted_context=_TRUSTED_POLICY_EVIDENCE_CONTEXT
    )
    return PolicyResult(
        verdict,
        EXIT_CODES[verdict],
        decisions,
        evidence,
        _trusted_context=_TRUSTED_POLICY_CONTEXT,
    )


def require_trusted_policy_result(value: object) -> PolicyResult:
    require_exact_type(value, PolicyResult, "policy result")
    if not value._trusted:
        raise DomainError("policy result is caller-authored, not trusted policy evidence")
    return value


__all__ = [
    "AppliedExceptionSource", "PolicyEvidence", "PolicyRequest", "PolicyResult",
    "TrustedGitSource", "TrustedPolicyBundle", "attest_git_source",
    "attest_protected_policy_repository", "evaluate_policy", "load_base_commit_policy",
    "load_candidate_exception", "load_candidate_policy", "load_operator_policy",
    "load_protected_policy_repository", "load_trusted_exception",
    "require_trusted_policy_result",
]
