"""Loader-attested policy provenance and the closed verdict boundary."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import InitVar, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from .engine import (
    GovernedConfigEvidence,
    GovernedPathRecord,
    TrustedVerificationConfigBundle,
    VerificationResult,
    _governed_file,
    require_trusted_verification_result,
)
from .enums import (
    EXIT_CODES,
    INCONCLUSIVE_OUTCOMES,
    PASSING_OUTCOMES,
    TRUSTED_EXCEPTION_ORIGINS,
    UNDECIDED_STATES,
    ExceptionOrigin,
    ExecutionMode,
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
_TRUSTED_EXECUTION_CONTEXT_CONTEXT = object()
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


def _portable_repository_identity(repository: Path) -> str:
    roots = _git_command(
        repository, ("rev-list", "--max-parents=0", "--all")
    ).decode("ascii", errors="strict").splitlines()
    roots = sorted(item for item in roots if _GIT_SHA.fullmatch(item))
    if not roots:
        raise DomainError("Git repository has no portable root-object identity")
    try:
        remote = _git_command(
            repository, ("config", "--get", "remote.origin.url")
        ).decode("utf-8", errors="strict").strip()
    except DomainError:
        remote = ""
    payload = json.dumps(
        {"root_commits": roots, "protected_remote": remote},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return "git_repo_v1_" + hashlib.sha256(payload).hexdigest()


def _candidate_checkout_tree(
    repository: Path,
    candidate_root: Path,
    candidate_commit: str,
    prefix: str,
) -> str:
    """Prove that a checked-out candidate is the exact authorized Git tree."""
    head = _resolve_git_commit(repository, "HEAD")
    if head != candidate_commit:
        raise DomainError("candidate checkout HEAD does not equal authorized commit")
    if candidate_root.resolve(strict=True) != (
        repository if prefix == "." else repository / prefix
    ).resolve(strict=True):
        raise DomainError("candidate repository-relative prefix does not match its root")
    dirty = _git_command(
        repository,
        ("status", "--porcelain=v1", "--untracked-files=all"),
    )
    if dirty:
        raise DomainError("candidate checkout differs from authorized commit")
    ignored = _git_command(
        repository,
        ("ls-files", "-z", "--others", "--ignored", "--exclude-standard"),
    )
    for raw_path in (item for item in ignored.split(b"\x00") if item):
        try:
            relative = raw_path.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise DomainError("ignored candidate path is not valid UTF-8") from exc
        path = Path(relative)
        supported = (
            path.suffix.lower() in {".tf", ".yaml", ".yml", ".json"}
            or path.name.lower().endswith(".tf.json")
        )
        if supported or _governed_file(path, relative):
            raise DomainError(
                "candidate checkout contains ignored supported or governed input"
            )
    tree_object = (
        f"{candidate_commit}^{{tree}}"
        if prefix == "."
        else f"{candidate_commit}:{prefix}"
    )
    tree_sha = _git_command(
        repository, ("rev-parse", "--verify", "--end-of-options", tree_object)
    ).decode("ascii", errors="strict").strip()
    if not _GIT_SHA.fullmatch(tree_sha):
        raise DomainError("candidate repository subtree identity is malformed")
    return tree_sha


@dataclass(frozen=True, slots=True)
class TrustedExecutionContext:
    """Protected runtime roles, source authorization, and UTC clock evidence."""

    mode: ExecutionMode
    repository_root: Path | None
    repository_identity: str
    authorized_base_commit: str
    candidate_root: Path
    candidate_commit: str
    protected_policy_repository: Path | None
    protected_policy_repository_identity: str
    protected_policy_commit: str
    governed_paths: tuple
    verification_config_sha256: str
    context_identity: str
    evaluated_at: datetime
    clock_source: str
    repository_relative_candidate_prefix: str = "."
    candidate_snapshot_sha256: str = ""
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)
    candidate_tree_sha: str = field(init=False, default="")

    def __post_init__(self, _trusted_context: object) -> None:
        require_enum(self.mode, ExecutionMode, "execution mode")
        if not isinstance(self.candidate_root, Path):
            raise DomainError("candidate root must be pathlib.Path")
        object.__setattr__(self, "candidate_root", self.candidate_root.resolve(strict=True))
        prefix = self.repository_relative_candidate_prefix
        if prefix != ".":
            prefix = canonical_repo_path(prefix, "candidate repository-relative prefix")
        object.__setattr__(self, "repository_relative_candidate_prefix", prefix)
        paths = tuple(sorted(canonical_repo_path(item) for item in self.governed_paths))
        if type(self.governed_paths) is not tuple or not paths or len(paths) != len(set(paths)):
            raise DomainError("execution governed paths must be a nonempty unique tuple")
        object.__setattr__(self, "governed_paths", paths)
        for name in ("verification_config_sha256",):
            value = getattr(self, name)
            if type(value) is not str or not __import__("re").fullmatch(r"[0-9a-f]{64}", value):
                raise DomainError(f"{name} must be a lowercase SHA-256 digest")
        object.__setattr__(
            self, "context_identity",
            canonical_identifier(self.context_identity, "execution context identity"),
        )
        object.__setattr__(
            self, "clock_source", canonical_identifier(self.clock_source, "clock source")
        )
        if type(self.evaluated_at) is not datetime or self.evaluated_at.tzinfo is None:
            raise DomainError("trusted execution time must be timezone aware")
        object.__setattr__(self, "evaluated_at", self.evaluated_at.astimezone(timezone.utc))
        if self.mode is ExecutionMode.EXPLICIT_OPERATOR:
            if any((self.repository_root, self.repository_identity, self.authorized_base_commit,
                    self.candidate_commit, self.protected_policy_repository,
                    self.protected_policy_repository_identity, self.protected_policy_commit)):
                raise DomainError("operator execution context cannot claim protected Git roles")
            if prefix != ".":
                raise DomainError("operator execution context cannot claim a Git subpath")
            snapshot = self.candidate_snapshot_sha256 or hashlib.sha256(
                b"operator-unbound-snapshot"
            ).hexdigest()
            object.__setattr__(self, "candidate_snapshot_sha256", snapshot)
        else:
            if not isinstance(self.repository_root, Path):
                raise DomainError("protected execution context requires a repository root")
            repository = self.repository_root.resolve(strict=True)
            _require_git_repository_root(repository)
            object.__setattr__(self, "repository_root", repository)
            if self.repository_identity != _portable_repository_identity(repository):
                raise DomainError("execution repository identity does not match Git objects")
            for name in ("authorized_base_commit", "candidate_commit"):
                value = getattr(self, name)
                if not _GIT_SHA.fullmatch(value) or _resolve_git_commit(repository, value) != value:
                    raise DomainError(f"{name} is not an exact repository commit")
            if not _within(self.candidate_root, repository):
                raise DomainError("execution candidate root is outside evaluated repository")
            actual_prefix = self.candidate_root.relative_to(repository).as_posix() or "."
            if prefix != actual_prefix:
                raise DomainError("candidate repository-relative prefix does not match its root")
            if not __import__("re").fullmatch(
                r"[0-9a-f]{64}", self.candidate_snapshot_sha256
            ):
                raise DomainError("candidate snapshot digest must bind protected D5 evidence")
            tree_sha = _candidate_checkout_tree(
                repository, self.candidate_root, self.candidate_commit, prefix
            )
            object.__setattr__(self, "candidate_tree_sha", tree_sha)
            if self.mode is ExecutionMode.PR_BASE:
                if any((self.protected_policy_repository,
                        self.protected_policy_repository_identity,
                        self.protected_policy_commit)):
                    raise DomainError("PR-base context cannot claim a protected-policy repository")
            else:
                if not isinstance(self.protected_policy_repository, Path):
                    raise DomainError("protected-policy mode requires its authorized repository")
                protected = self.protected_policy_repository.resolve(strict=True)
                _require_git_repository_root(protected)
                object.__setattr__(self, "protected_policy_repository", protected)
                if _within(protected, self.candidate_root) or _within(self.candidate_root, protected):
                    raise DomainError("protected policy repository overlaps evaluated workspace")
                if self.protected_policy_repository_identity != _portable_repository_identity(protected):
                    raise DomainError("protected policy repository identity is not authorized")
                if (
                    not _GIT_SHA.fullmatch(self.protected_policy_commit)
                    or _resolve_git_commit(protected, self.protected_policy_commit)
                    != self.protected_policy_commit
                ):
                    raise DomainError("protected policy commit is not exactly pinned")
        if _trusted_context is not _TRUSTED_EXECUTION_CONTEXT_CONTEXT:
            raise DomainError("TrustedExecutionContext requires protected runtime provenance")
        object.__setattr__(self, "_trusted", True)

    @property
    def evaluation_date(self) -> date:
        return self.evaluated_at.date()


def _default_governed_paths(config: TrustedVerificationConfigBundle) -> tuple[str, ...]:
    return tuple(sorted({
        ".iac-guard.json", ".iac-guard.yml", ".iac-guard.yaml",
        *(item.file_path for item in config.governed_config),
    }))


def load_operator_execution_context(
    config: TrustedVerificationConfigBundle,
) -> TrustedExecutionContext:
    """Create the only public context: explicit local/operator mode at current UTC."""
    require_exact_type(config, TrustedVerificationConfigBundle, "verification config")
    authorization = config.policy_source_authorization
    if authorization.mode is not ExecutionMode.EXPLICIT_OPERATOR:
        raise DomainError("operator context requires explicit-operator authorization")
    return TrustedExecutionContext(
        ExecutionMode.EXPLICIT_OPERATOR, None, "", "", config.candidate_root, "",
        None, "", "", tuple(sorted(_default_governed_paths(config))),
        config.config_sha256, authorization.context_identity,
        datetime.now(timezone.utc), "system_utc_clock",
        ".", config.candidate_source_snapshot_sha256,
        _trusted_context=_TRUSTED_EXECUTION_CONTEXT_CONTEXT,
    )


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


def _prefixed_path(prefix: str, relative: str) -> str:
    relative = canonical_repo_path(relative, "governed path")
    if prefix == ".":
        return relative
    return canonical_repo_path(f"{prefix}/{relative}", "prefixed governed path")


def _git_tree_entry(
    repository: Path, commit: str, relative: str
) -> tuple[str, str, str] | None:
    entry = _git_command(repository, ("ls-tree", "-z", commit, "--", relative))
    if entry == b"":
        return None
    if not entry.endswith(b"\x00") or entry.count(b"\x00") != 1 or b"\t" not in entry:
        raise DomainError("Git governed object tree entry is malformed")
    metadata, recorded_path = entry[:-1].split(b"\t", 1)
    fields = metadata.decode("ascii", errors="strict").split()
    if len(fields) != 3 or recorded_path.decode("utf-8", errors="strict") != relative:
        raise DomainError("Git governed object tree entry is inconsistent")
    return fields[0], fields[1], fields[2]


def _git_governed_record(
    repository: Path, commit: str, relative: str, report_path: str
) -> GovernedPathRecord | None:
    entry = _git_tree_entry(repository, commit, relative)
    if entry is None:
        return None
    mode, kind, object_id = entry
    if mode in {"100644", "100755"} and kind == "blob":
        payload = _git_object_bytes(repository, commit, relative)
        record_kind = "REGULAR_FILE"
    elif mode == "120000" and kind == "blob":
        payload = _git_command(repository, ("cat-file", "blob", object_id))
        if len(payload) > _MAX_POLICY_BYTES:
            raise DomainError("Git governed symlink exceeds the trusted byte limit")
        record_kind = "SYMLINK"
    elif mode == "040000" and kind == "tree":
        listing = _git_command(repository, ("ls-tree", "-r", "-z", commit, "--", relative))
        records = []
        total = 0
        entries = [item for item in listing.split(b"\x00") if item]
        if len(entries) > 10_000:
            raise DomainError("Git governed directory exceeds its file-count limit")
        for raw in entries:
            if b"\t" not in raw:
                raise DomainError("Git governed directory entry is malformed")
            metadata, path_bytes = raw.split(b"\t", 1)
            fields = metadata.decode("ascii", errors="strict").split()
            if len(fields) != 3:
                raise DomainError("Git governed directory metadata is malformed")
            child_mode, child_kind, child_oid = fields
            child_path = path_bytes.decode("utf-8", errors="strict")
            child_payload = _git_command(
                repository, ("cat-file", "blob", child_oid)
            ) if child_kind == "blob" else b""
            total += len(child_payload)
            if len(child_payload) > _MAX_POLICY_BYTES or total > 100 * _MAX_POLICY_BYTES:
                raise DomainError("Git governed directory exceeds its byte limit")
            records.append({
                "path": child_path,
                "mode": child_mode,
                "kind": child_kind,
                "sha256": _sha256(child_payload),
                "size": len(child_payload),
            })
        payload = json.dumps(
            records, sort_keys=True, separators=(",", ":")
        ).encode()
        record_kind = "REAL_DIRECTORY"
    else:
        payload = f"{mode}:{kind}:{object_id}".encode("ascii")
        record_kind = "OTHER"
    return GovernedPathRecord(
        report_path, record_kind, _sha256(payload), len(payload)
    )


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


def _read_policy_bytes(
    path: Path, *, required: bool, trusted_root: Path | None = None
) -> bytes | None:
    if not isinstance(path, Path):
        raise DomainError("policy source must be a pathlib.Path")
    if trusted_root is not None:
        root = trusted_root.resolve(strict=True)
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise DomainError("policy source is outside its trusted root") from exc
        cursor = root
        for component in relative.parts[:-1]:
            cursor = cursor / component
            try:
                metadata = cursor.lstat()
            except OSError as exc:
                raise DomainError("policy parent path could not be inspected") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise DomainError("policy source has a symlinked parent component")
            if not stat.S_ISDIR(metadata.st_mode):
                raise DomainError("policy parent component is not a directory")
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
    execution_mode: ExecutionMode = ExecutionMode.EXPLICIT_OPERATOR
    execution_context_identity: str = "legacy_unbound_context"
    verification_config_sha256: str = "0" * 64
    candidate_root_identity: str = ""
    candidate_snapshot_sha256: str = "0" * 64
    candidate_tree_sha: str = ""
    repository_relative_candidate_prefix: str = "."
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
        require_enum(self.execution_mode, ExecutionMode, "policy execution mode")
        object.__setattr__(
            self, "execution_context_identity",
            canonical_identifier(self.execution_context_identity, "execution context identity"),
        )
        if not __import__("re").fullmatch(r"[0-9a-f]{64}", self.verification_config_sha256):
            raise DomainError("policy verification config digest is malformed")
        object.__setattr__(
            self, "candidate_root_identity",
            canonical_identifier(self.candidate_root_identity or "operator_candidate", "candidate root identity"),
        )
        if not __import__("re").fullmatch(r"[0-9a-f]{64}", self.candidate_snapshot_sha256):
            raise DomainError("policy candidate snapshot digest is malformed")
        if self.candidate_tree_sha and not _GIT_SHA.fullmatch(self.candidate_tree_sha):
            raise DomainError("policy candidate tree identity is malformed")
        prefix = self.repository_relative_candidate_prefix
        if prefix != ".":
            prefix = canonical_repo_path(prefix, "policy candidate repository prefix")
        object.__setattr__(self, "repository_relative_candidate_prefix", prefix)
        if self.execution_mode is ExecutionMode.EXPLICIT_OPERATOR:
            if self.candidate_tree_sha or prefix != ".":
                raise DomainError("operator policy cannot claim a Git candidate tree")
        elif not self.candidate_tree_sha:
            raise DomainError("protected policy requires an exact candidate tree identity")
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
            "execution_mode": self.execution_mode.value,
            "execution_context_identity": self.execution_context_identity,
            "verification_config_sha256": self.verification_config_sha256,
            "candidate_root_identity": self.candidate_root_identity,
            "candidate_snapshot_sha256": self.candidate_snapshot_sha256,
            "candidate_tree_sha": self.candidate_tree_sha,
            "repository_relative_candidate_prefix": (
                self.repository_relative_candidate_prefix
            ),
        }


def _bundle(
    trusted_payload: dict,
    trusted_bytes: bytes,
    candidate_bytes: bytes | None,
    candidate_state: str,
    origin: ExceptionOrigin,
    source_identity: str,
    governed_path: str,
    context: TrustedExecutionContext,
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
    require_exact_type(context, TrustedExecutionContext, "trusted execution context")
    if not context._trusted:
        raise DomainError("trusted execution context lacks runtime provenance")
    evaluated = context.evaluation_date
    zone = "UTC"
    provenance = context.clock_source
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
        context.mode,
        context.context_identity,
        context.verification_config_sha256,
        (
            f"git_candidate_{context.candidate_commit}"
            if context.candidate_commit
            else f"operator_candidate_{context.context_identity}"
        ),
        context.candidate_snapshot_sha256,
        context.candidate_tree_sha,
        context.repository_relative_candidate_prefix,
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


def _source_governed_evidence(
    source: TrustedGitSource, context: TrustedExecutionContext
) -> tuple:
    evidence = []
    for relative in source.governed_paths:
        trusted_path = (
            _prefixed_path(context.repository_relative_candidate_prefix, relative)
            if source.source_origin is ExceptionOrigin.TRUSTED_BASE
            else relative
        )
        candidate_path = _prefixed_path(
            context.repository_relative_candidate_prefix, relative
        )
        trusted = _git_governed_record(
            source.repository_root, source.commit_sha, trusted_path, relative
        )
        candidate = _git_governed_record(
            context.repository_root, context.candidate_commit, candidate_path, relative
        )
        if trusted is None and candidate is None:
            continue
        trusted_digest = None if trusted is None else trusted.sha256
        candidate_digest = None if candidate is None else candidate.sha256
        state = (
            "added" if trusted is None
            else "removed" if candidate is None
            else "type_changed" if trusted.kind != candidate.kind
            else "stable" if (
                trusted.kind in {"REGULAR_FILE", "REAL_DIRECTORY"}
                and trusted_digest == candidate_digest
            )
            else "changed"
        )
        evidence.append(
            GovernedConfigEvidence(
                relative, trusted_digest, candidate_digest, state,
                "ABSENT" if trusted is None else trusted.kind,
                "ABSENT" if candidate is None else candidate.kind,
                0 if trusted is None else trusted.size,
                0 if candidate is None else candidate.size,
            )
        )
    return tuple(evidence)


def _load_git_source_bundle(
    source: TrustedGitSource,
    origin: ExceptionOrigin,
    governed_path: str,
    context: TrustedExecutionContext,
) -> TrustedPolicyBundle:
    require_exact_type(source, TrustedGitSource, "attested Git policy source")
    if not source._trusted or source.source_origin is not origin:
        raise DomainError("Git policy source provenance does not match loader")
    require_exact_type(context, TrustedExecutionContext, "trusted execution context")
    if not context._trusted:
        raise DomainError("trusted execution context lacks protected provenance")
    current_tree = _candidate_checkout_tree(
        context.repository_root,
        context.candidate_root,
        context.candidate_commit,
        context.repository_relative_candidate_prefix,
    )
    if current_tree != context.candidate_tree_sha:
        raise DomainError("candidate tree changed after execution-context attestation")
    expected_mode = (
        ExecutionMode.PR_BASE if origin is ExceptionOrigin.TRUSTED_BASE
        else ExecutionMode.PROTECTED_POLICY_REPOSITORY
    )
    if context.mode is not expected_mode:
        raise DomainError("policy loader mode is not authorized by execution context")
    expected_repository = (
        context.repository_root if origin is ExceptionOrigin.TRUSTED_BASE
        else context.protected_policy_repository
    )
    expected_commit = (
        context.authorized_base_commit if origin is ExceptionOrigin.TRUSTED_BASE
        else context.protected_policy_commit
    )
    expected_identity = (
        context.repository_identity if origin is ExceptionOrigin.TRUSTED_BASE
        else context.protected_policy_repository_identity
    )
    if (
        source.repository_root != expected_repository
        or source.commit_sha != expected_commit
        or source.candidate_root != context.candidate_root
        or source.governed_paths != context.governed_paths
        or _portable_repository_identity(source.repository_root) != expected_identity
    ):
        raise DomainError("policy source role does not match authorized execution context")
    governed_path = canonical_repo_path(governed_path, "governed policy path")
    if governed_path not in source.governed_paths:
        raise DomainError("governed policy path is outside the attested Git source")
    trusted_object_path = (
        _prefixed_path(context.repository_relative_candidate_prefix, governed_path)
        if origin is ExceptionOrigin.TRUSTED_BASE else governed_path
    )
    candidate_object_path = _prefixed_path(
        context.repository_relative_candidate_prefix, governed_path
    )
    trusted_bytes = _git_object_bytes(
        source.repository_root, source.commit_sha, trusted_object_path
    )
    candidate_entry = _git_tree_entry(
        context.repository_root, context.candidate_commit, candidate_object_path
    )
    candidate_bytes = (
        None if candidate_entry is None
        else _git_object_bytes(
            context.repository_root, context.candidate_commit, candidate_object_path
        )
    )
    candidate_state = "missing" if candidate_bytes is None else "present"
    repository_identity = expected_identity
    return _bundle(
        _parse_policy_bytes(trusted_bytes),
        trusted_bytes,
        candidate_bytes,
        candidate_state,
        origin,
        source.source_identity,
        governed_path,
        context,
        governed_evidence=_source_governed_evidence(source, context),
        source_repository=repository_identity,
        source_commit=source.commit_sha,
    )


def load_base_commit_policy(
    context: TrustedExecutionContext,
    *,
    governed_path: str = ".iac-guard.json",
) -> TrustedPolicyBundle:
    require_exact_type(context, TrustedExecutionContext, "trusted execution context")
    if context.mode is not ExecutionMode.PR_BASE:
        raise DomainError("base policy loader requires PR_BASE execution mode")
    source = TrustedGitSource(
        context.repository_root, context.authorized_base_commit,
        context.candidate_root, context.governed_paths, ExceptionOrigin.TRUSTED_BASE,
        _trusted_context=_TRUSTED_GIT_SOURCE_CONTEXT,
    )
    return _load_git_source_bundle(
        source, ExceptionOrigin.TRUSTED_BASE, governed_path, context
    )


def load_protected_policy_repository(
    context: TrustedExecutionContext,
    *,
    governed_path: str = ".iac-guard.json",
) -> TrustedPolicyBundle:
    require_exact_type(context, TrustedExecutionContext, "trusted execution context")
    if context.mode is not ExecutionMode.PROTECTED_POLICY_REPOSITORY:
        raise DomainError("protected policy loader requires protected-repository mode")
    source = TrustedGitSource(
        context.protected_policy_repository, context.protected_policy_commit,
        context.candidate_root, context.governed_paths,
        ExceptionOrigin.PROTECTED_POLICY_REPO,
        _trusted_context=_TRUSTED_GIT_SOURCE_CONTEXT,
    )
    return _load_git_source_bundle(
        source, ExceptionOrigin.PROTECTED_POLICY_REPO, governed_path, context
    )


def load_operator_policy(
    trusted_payload: Mapping,
    *,
    context: TrustedExecutionContext,
    candidate_payload: Mapping | None = None,
    governed_path: str = ".iac-guard.json",
) -> TrustedPolicyBundle:
    require_exact_type(context, TrustedExecutionContext, "trusted execution context")
    if context.mode is not ExecutionMode.EXPLICIT_OPERATOR:
        raise DomainError("operator policy requires explicit operator execution mode")
    trusted_bytes = _canonical_payload(trusted_payload)
    candidate_bytes = (
        None if candidate_payload is None else _canonical_payload(candidate_payload)
    )
    candidate_state = "not_compared" if candidate_payload is None else "present"
    return _bundle(
        _parse_policy_bytes(trusted_bytes), trusted_bytes, candidate_bytes,
        candidate_state, ExceptionOrigin.OPERATOR, context.context_identity,
        governed_path, context,
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
        config = self.verification.verification_config
        authorization = config.policy_source_authorization
        if (
            self.policy_bundle.execution_mode is not authorization.mode
            or self.policy_bundle.execution_context_identity
            != authorization.context_identity
            or self.policy_bundle.verification_config_sha256 != config.config_sha256
            or self.policy_bundle.candidate_root_identity
            != authorization.candidate_identity
            or self.policy_bundle.candidate_snapshot_sha256
            != self.verification.candidate_snapshot.snapshot_sha256
            or self.policy_bundle.repository_relative_candidate_prefix
            != self.verification.candidate_snapshot.repository_relative_subpath
        ):
            raise DomainError("policy bundle is not authorized for this verification config")
        expected_origin = {
            ExecutionMode.EXPLICIT_OPERATOR: ExceptionOrigin.OPERATOR,
            ExecutionMode.PR_BASE: ExceptionOrigin.TRUSTED_BASE,
            ExecutionMode.PROTECTED_POLICY_REPOSITORY:
                ExceptionOrigin.PROTECTED_POLICY_REPO,
        }[authorization.mode]
        if self.policy_bundle.source_origin is not expected_origin:
            raise DomainError("policy origin does not match authorized execution mode")
        if authorization.repository_identity:
            if (
                self.policy_bundle.source_repository != authorization.repository_identity
                or self.policy_bundle.source_commit != authorization.commit_sha
            ):
                raise DomainError("policy repository/commit is not authorized by verification")


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
    "TrustedExecutionContext", "TrustedGitSource", "TrustedPolicyBundle", "attest_git_source",
    "attest_protected_policy_repository", "evaluate_policy", "load_base_commit_policy",
    "load_candidate_exception", "load_candidate_policy", "load_operator_policy",
    "load_operator_execution_context",
    "load_protected_policy_repository", "load_trusted_exception",
    "require_trusted_policy_result",
]
