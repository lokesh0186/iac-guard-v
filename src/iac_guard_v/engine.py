"""Verification engine: trusted execution evidence to outcomes and gates.

The public request deliberately has no field for ``ScannerRun``, matching, delta, or
target-evaluation evidence.  Those values are obtained in this module by invoking the
adapter and the D3 factories.  The engine emits evidence and events; only ``policy.py``
may collapse them to a verdict.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import stat
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Callable

import hcl2
import yaml
from yaml.constructor import ConstructorError
from yaml.events import (
    AliasEvent,
    MappingEndEvent,
    MappingStartEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)
from yaml.nodes import MappingNode

from .adapters.checkov import (
    CheckovAdapter,
    CheckovKubernetesIdentity,
    CheckovScanRequest,
    evaluate_checkov_target,
)
from .adapters.base import AdapterReason
from .diffing import FindingDiffResult, diff_findings, require_trusted_diff_result
from .enums import (
    CheckTargetReason,
    ArtifactKind,
    DeltaClass,
    Outcome,
    SEVERITY_ORDER,
    Severity,
    Status,
)
from .models import (
    DomainError,
    ExpectedResource,
    GateResult,
    RequiredGates,
    ScannerRun,
    Target,
    TargetIdentity,
    canonical_identifier,
    require_enum,
    require_exact_type,
    require_trusted_scanner_run,
)


_TRUSTED_ENGINE_CONTEXT = object()
_TRUSTED_SCAN_PLAN_CONTEXT = object()
_SHA256 = __import__("re").compile(r"^[0-9a-f]{64}$")


def _digest(value: object, name: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise DomainError(f"{name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class ScanPlanFile:
    file_path: str
    file_type: str
    size: int
    sha256: str
    content: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.file_path) is not str or not self.file_path:
            raise DomainError("scan-plan file path must be nonblank")
        if type(self.file_type) is not str or not self.file_type:
            raise DomainError("scan-plan file type must be nonblank")
        if type(self.size) is not int or self.size < 0 or self.size != len(self.content):
            raise DomainError("scan-plan file size does not match bound content")
        _digest(self.sha256, "scan-plan file digest")
        if hashlib.sha256(self.content).hexdigest() != self.sha256:
            raise DomainError("scan-plan file digest does not match bound content")

    def canonical_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_type": self.file_type,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class TrustedScanPlan:
    """Private-factory scan plan whose resources were detected from bound bytes."""

    request: CheckovScanRequest
    files: tuple
    resources: tuple
    inventory_sha256: str
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_exact_type(self.request, CheckovScanRequest, "scan-plan request")
        if type(self.files) is not tuple or any(type(item) is not ScanPlanFile for item in self.files):
            raise DomainError("scan-plan files must be exact ScanPlanFile values")
        if type(self.resources) is not tuple or any(type(item) is not ExpectedResource for item in self.resources):
            raise DomainError("scan-plan resources must be exact ExpectedResource values")
        _digest(self.inventory_sha256, "resource inventory digest")
        if tuple(self.request.expected_resources) != self.resources:
            raise DomainError("scan-plan resources disagree with its adapter request")
        if _trusted_context is not _TRUSTED_SCAN_PLAN_CONTEXT:
            raise DomainError("TrustedScanPlan requires independent detector provenance")
        object.__setattr__(self, "_trusted", True)

    @property
    def scan_root(self) -> Path:
        return self.request.scan_root

    @property
    def executable(self) -> Path:
        return self.request.executable

    @property
    def expected_executable_sha256(self) -> str:
        return self.request.expected_executable_sha256

    @property
    def expected_scanner_environment_sha256(self) -> str:
        return self.request.expected_scanner_environment_sha256

    @property
    def expected_policy_inventory_sha256(self) -> str:
        return self.request.expected_policy_inventory_sha256

    @property
    def files_eligible(self) -> tuple:
        return self.request.files_eligible

    @property
    def expected_resources(self) -> tuple:
        return self.resources

    @property
    def eligible_file_evidence(self) -> tuple:
        return self.request.eligible_file_evidence

    def canonical_dict(self) -> dict:
        return {
            "files": [item.canonical_dict() for item in self.files],
            "resources": [item.canonical_dict() for item in self.resources],
            "inventory_sha256": self.inventory_sha256,
        }


def _terraform_resources(relative: str, content: bytes) -> tuple[ExpectedResource, ...]:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DomainError("Terraform source must be UTF-8") from exc
    block_start = text.find("/*")
    if block_start >= 0 and text.find("*/", block_start + 2) < 0:
        raise DomainError("unterminated Terraform block comment")
    escaped = False
    quote_count = 0
    for character in text:
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            quote_count += 1
    if quote_count % 2:
        raise DomainError("unterminated Terraform string")
    try:
        document = hcl2.loads(text)
    except Exception as exc:
        raise DomainError("Terraform HCL syntax is invalid or unsupported") from exc
    if type(document) is not dict:
        raise DomainError("Terraform HCL parser returned an invalid document")
    resources: list[ExpectedResource] = []
    seen: set[str] = set()
    blocks = document.get("resource", [])
    if type(blocks) is not list:
        raise DomainError("Terraform resource structure is invalid")
    for block in blocks:
        if type(block) is not dict:
            raise DomainError("Terraform resource block is invalid")
        for resource_type, instances in block.items():
            if type(resource_type) is not str or type(instances) is not dict:
                raise DomainError("Terraform resource identity is invalid")
            for resource_name in instances:
                if type(resource_name) is not str:
                    raise DomainError("Terraform resource name is invalid")
                address = f"{resource_type}.{resource_name}"
                if address in seen:
                    raise DomainError("duplicate Terraform resource identity")
                seen.add(address)
                resources.append(
                    ExpectedResource(
                        relative, address, ArtifactKind.TERRAFORM_HCL, address
                    )
                )
    return tuple(sorted(resources, key=lambda item: item.canonical_key))


_MAX_YAML_DEPTH = 64
_MAX_YAML_DOCUMENTS = 128
_MAX_YAML_NODES = 10_000


class _StrictSafeLoader(yaml.SafeLoader):
    """Safe loader with a closed mapping-key and duplicate-key contract."""


def _construct_unique_mapping(
    loader: _StrictSafeLoader, node: MappingNode, deep: bool = False
) -> dict:
    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a YAML mapping", node.start_mark)
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if type(key) is not str:
            raise ConstructorError(
                "while constructing a mapping", node.start_mark,
                "YAML mapping keys must be strings", key_node.start_mark,
            )
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"duplicate YAML mapping key {key!r}", key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _bounded_yaml_documents(content: bytes) -> tuple:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DomainError("Kubernetes YAML must be UTF-8") from exc
    depth = 0
    documents = 0
    nodes = 0
    try:
        for event in yaml.parse(text, Loader=_StrictSafeLoader):
            if isinstance(event, AliasEvent):
                raise DomainError("Kubernetes YAML aliases are unsupported")
            if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                depth += 1
                nodes += 1
                if depth > _MAX_YAML_DEPTH:
                    raise DomainError("Kubernetes YAML depth limit exceeded")
                if nodes > _MAX_YAML_NODES:
                    raise DomainError("Kubernetes YAML node limit exceeded")
            elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                depth -= 1
        values = tuple(yaml.load_all(text, Loader=_StrictSafeLoader))
        documents = len(values)
    except DomainError:
        raise
    except ConstructorError as exc:
        message = str(exc).lower()
        reason = "duplicate mapping key" if "duplicate" in message else "unsafe/custom YAML tag"
        raise DomainError(f"Kubernetes YAML rejected: {reason}") from exc
    except (yaml.YAMLError, RecursionError) as exc:
        raise DomainError("Kubernetes YAML syntax is malformed or unsupported") from exc
    if documents > _MAX_YAML_DOCUMENTS:
        raise DomainError("Kubernetes YAML document limit exceeded")
    return values


def _kubernetes_identity(
    relative: str, value: object
) -> tuple[ExpectedResource, CheckovKubernetesIdentity]:
    if type(value) is not dict:
        raise DomainError("unsupported Kubernetes identity shape")
    api_version = value.get("apiVersion")
    kind = value.get("kind")
    metadata = value.get("metadata")
    if type(api_version) is not str or not api_version.strip():
        raise DomainError("incomplete Kubernetes resource identity: apiVersion")
    if type(kind) is not str or not kind.strip():
        raise DomainError("incomplete Kubernetes resource identity: kind")
    if type(metadata) is not dict:
        raise DomainError("incomplete Kubernetes resource identity: metadata")
    name = metadata.get("name")
    namespace = metadata.get("namespace", "default")
    if name is None or name == "":
        raise DomainError("incomplete Kubernetes resource identity: metadata.name")
    if type(name) is not str:
        raise DomainError("unsupported complex Kubernetes metadata.name")
    if namespace is None:
        namespace = "default"
    if type(namespace) is not str:
        raise DomainError("unsupported complex Kubernetes metadata.namespace")
    if not namespace.strip():
        raise DomainError("unsupported Kubernetes identity shape: metadata.namespace")
    api_version = api_version.strip()
    kind = kind.strip()
    name = name.strip()
    namespace = namespace.strip()
    canonical = f"{api_version}/{kind}/{namespace}/{name}"
    native = f"{kind}.{namespace}.{name}"
    return (
        ExpectedResource(relative, canonical, ArtifactKind.KUBERNETES_YAML, native),
        CheckovKubernetesIdentity(
            relative, native, api_version, kind, namespace, name
        ),
    )


def _kubernetes_resources(
    relative: str, content: bytes
) -> tuple[tuple[ExpectedResource, ...], tuple[CheckovKubernetesIdentity, ...]]:
    resources: list[ExpectedResource] = []
    identities: list[CheckovKubernetesIdentity] = []
    for document in _bounded_yaml_documents(content):
        if document is None:
            continue
        if type(document) is not dict:
            raise DomainError("unsupported Kubernetes YAML document shape")
        has_identity_evidence = any(
            key in document for key in ("apiVersion", "kind", "metadata")
        )
        if not has_identity_evidence:
            continue
        if document.get("kind") == "List":
            if type(document.get("apiVersion")) is not str:
                raise DomainError("incomplete Kubernetes List identity")
            items = document.get("items")
            if type(items) is not list:
                raise DomainError("unsupported Kubernetes List items shape")
            for item in items:
                resource, identity = _kubernetes_identity(relative, item)
                resources.append(resource)
                identities.append(identity)
        else:
            resource, identity = _kubernetes_identity(relative, document)
            resources.append(resource)
            identities.append(identity)
    keys = [item.canonical_key for item in resources]
    if len(keys) != len(set(keys)):
        raise DomainError("duplicate Kubernetes resource identity")
    return (
        tuple(sorted(resources, key=lambda item: item.canonical_key)),
        tuple(sorted(identities, key=lambda item: (item.file_path, item.canonical_address))),
    )


def _read_detector_file(path: Path, root: Path, max_bytes: int) -> bytes:
    """Read one bounded regular file through a no-follow descriptor."""
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise DomainError("independent detector path escaped its scan root") from exc
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    chunks: list[bytes] = []
    size = 0
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise DomainError("independent detector input is not a regular file")
            while True:
                chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise DomainError("independent detector input exceeds its per-file limit")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise DomainError("independent detector could not safely open an input") from exc
    return b"".join(chunks)


def attest_checkov_scan_plan(untrusted: CheckovScanRequest) -> TrustedScanPlan:
    """Re-discover eligible files/resources from bytes; ignore caller inventories."""
    require_exact_type(untrusted, CheckovScanRequest, "unattested Checkov request")
    files: list[ScanPlanFile] = []
    resources: list[ExpectedResource] = []
    kubernetes: list[CheckovKubernetesIdentity] = []
    eligible: list[str] = []
    root = untrusted.scan_root
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        is_tf_json = path.name.lower().endswith(".tf.json")
        if path.is_symlink():
            if path.suffix.lower() in {".tf", ".yaml", ".yml"} or is_tf_json:
                raise DomainError("independent detector refuses symlinked IaC input")
            continue
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        if is_tf_json and "terraform" in untrusted.frameworks:
            raise DomainError("Terraform JSON (.tf.json) is explicitly unsupported")
        content = _read_detector_file(path, root, untrusted.max_file_bytes)
        detected: tuple[ExpectedResource, ...] = ()
        file_type = ""
        if suffix == ".tf" and "terraform" in untrusted.frameworks:
            detected = _terraform_resources(relative, content)
            file_type = ArtifactKind.TERRAFORM_HCL.value
        elif suffix in {".yaml", ".yml"} and "kubernetes" in untrusted.frameworks:
            detected, identities = _kubernetes_resources(relative, content)
            if not detected:
                continue
            kubernetes.extend(identities)
            file_type = ArtifactKind.KUBERNETES_YAML.value
        else:
            continue
        if len(eligible) >= untrusted.max_eligible_files:
            raise DomainError("independent detector input exceeds its eligible-file limit")
        total_bytes += len(content)
        if total_bytes > untrusted.max_total_eligible_bytes:
            raise DomainError("independent detector input exceeds its total-byte limit")
        eligible.append(relative)
        resources.extend(detected)
        files.append(
            ScanPlanFile(
                relative, file_type, len(content), hashlib.sha256(content).hexdigest(), content
            )
        )
    request = CheckovScanRequest(
        executable=untrusted.executable,
        scan_root=untrusted.scan_root,
        workspace_root=untrusted.workspace_root,
        frameworks=untrusted.frameworks,
        files_eligible=tuple(eligible),
        expected_version=untrusted.expected_version,
        expected_executable_sha256=untrusted.expected_executable_sha256,
        expected_scanner_environment_sha256=untrusted.expected_scanner_environment_sha256,
        expected_policy_inventory_sha256=untrusted.expected_policy_inventory_sha256,
        kubernetes_identities=tuple(kubernetes),
        expected_resources=tuple(resources),
        timeout_seconds=untrusted.timeout_seconds,
        max_output_bytes=untrusted.max_output_bytes,
        max_eligible_files=untrusted.max_eligible_files,
        max_file_bytes=untrusted.max_file_bytes,
        max_total_eligible_bytes=untrusted.max_total_eligible_bytes,
    )
    evidence_by_path = {item.file_path: item for item in request.eligible_file_evidence}
    if any(
        evidence_by_path[item.file_path].sha256 != item.sha256
        or evidence_by_path[item.file_path].size != item.size
        for item in files
    ):
        raise DomainError("source bytes changed during independent scan-plan attestation")
    ordered_resources = tuple(sorted(resources, key=lambda item: item.canonical_key))
    inventory_payload = [item.canonical_dict() for item in ordered_resources]
    inventory_digest = hashlib.sha256(
        json.dumps(inventory_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return TrustedScanPlan(
        request,
        tuple(sorted(files, key=lambda item: item.file_path)),
        ordered_resources,
        inventory_digest,
        _trusted_context=_TRUSTED_SCAN_PLAN_CONTEXT,
    )


@dataclass(frozen=True, slots=True)
class VerificationRequest:
    """Paths, targets, and protected configuration; never derived scan evidence."""

    baseline_scan: TrustedScanPlan
    candidate_scan: TrustedScanPlan
    targets: tuple
    required_gates: RequiredGates
    trusted_governed_config_sha256: str
    candidate_governed_config_sha256: str
    severity_floor: Severity = Severity.HIGH
    fail_on_location_change: bool = False

    def __post_init__(self) -> None:
        require_exact_type(self.baseline_scan, TrustedScanPlan, "baseline trusted scan plan")
        require_exact_type(self.candidate_scan, TrustedScanPlan, "candidate trusted scan plan")
        if not self.baseline_scan._trusted or not self.candidate_scan._trusted:
            raise DomainError("verification scan plans require detector provenance")
        require_exact_type(self.required_gates, RequiredGates, "required gates")
        require_enum(self.severity_floor, Severity, "severity_floor")
        if type(self.fail_on_location_change) is not bool:
            raise DomainError("fail_on_location_change must be a bool")
        if type(self.targets) is not tuple or not self.targets:
            raise DomainError("targets must be a nonempty exact tuple")
        rebuilt: list[Target] = []
        for item in self.targets:
            require_exact_type(item, Target, "verification target")
            rebuilt.append(
                Target(
                    TargetIdentity(
                        item.identity.scanner,
                        item.identity.rule_id,
                        item.identity.scope,
                    ),
                    item.baseline_occurrences,
                )
            )
        keys = [item.identity.canonical_key for item in rebuilt]
        if len(keys) != len(set(keys)):
            raise DomainError("verification targets contain duplicate identities")
        if any(item.scanner != "checkov" for item in rebuilt):
            raise DomainError("D5 supports Checkov targets only")
        object.__setattr__(self, "targets", tuple(sorted(rebuilt, key=lambda x: x.identity.canonical_key)))
        object.__setattr__(
            self,
            "trusted_governed_config_sha256",
            _digest(self.trusted_governed_config_sha256, "trusted governed-config digest"),
        )
        object.__setattr__(
            self,
            "candidate_governed_config_sha256",
            _digest(self.candidate_governed_config_sha256, "candidate governed-config digest"),
        )


@dataclass(frozen=True, slots=True)
class TargetObservation:
    """Typed facts used by the total target classifier.

    ``PASS`` means the named positive property was established; ``FAIL`` means its
    specified contrary was established; every operational state remains uncertainty.
    """

    identity: TargetIdentity
    baseline_occurrences: int
    candidate_matches: int
    scanner_integrity: Status
    ruleset_integrity: Status
    artifact_eligibility: Status
    target_file_presence: Status
    target_resource_presence: Status
    suppression_absence: Status
    occurrence_evidence: Status
    affirmative_target_pass: Status

    def __post_init__(self) -> None:
        require_exact_type(self.identity, TargetIdentity, "target identity")
        for name in ("baseline_occurrences", "candidate_matches"):
            value = getattr(self, name)
            if type(value) is not int or value < (1 if name == "baseline_occurrences" else 0):
                raise DomainError(f"{name} is outside its valid count domain")
        for name in (
            "scanner_integrity", "ruleset_integrity", "artifact_eligibility",
            "target_file_presence", "target_resource_presence", "suppression_absence",
            "occurrence_evidence", "affirmative_target_pass",
        ):
            require_enum(getattr(self, name), Status, name)


def classify_target(observation: TargetObservation) -> Outcome:
    """Apply semantics section 4 in fail-closed order."""
    require_exact_type(observation, TargetObservation, "target observation")
    o = observation
    if o.scanner_integrity is not Status.PASS:
        return Outcome.SCANNER_ERROR
    if o.ruleset_integrity is Status.FAIL:
        return Outcome.RULE_OR_SCANNER_DRIFT
    if o.ruleset_integrity is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.artifact_eligibility is Status.FAIL:
        return Outcome.OUT_OF_SCOPE
    if o.artifact_eligibility is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.target_file_presence is Status.FAIL:
        return Outcome.FILE_DELETED_OR_RENAMED
    if o.target_file_presence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.target_resource_presence is Status.FAIL:
        return Outcome.RESOURCE_DELETED
    if o.target_resource_presence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.suppression_absence is Status.FAIL:
        return Outcome.SUPPRESSED
    if o.suppression_absence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.occurrence_evidence is not Status.PASS:
        return Outcome.INCONCLUSIVE
    if o.baseline_occurrences > 1 and 0 < o.candidate_matches < o.baseline_occurrences:
        return Outcome.PARTIALLY_FIXED
    if o.candidate_matches >= o.baseline_occurrences:
        return Outcome.STILL_PRESENT
    if o.candidate_matches == 0 and o.affirmative_target_pass is Status.PASS:
        return Outcome.FIXED
    return Outcome.INCONCLUSIVE


@dataclass(frozen=True, slots=True)
class TargetOutcomeEvidence:
    identity: TargetIdentity
    outcome: Outcome
    observation: TargetObservation
    target_reason: str
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_exact_type(self.identity, TargetIdentity, "target identity")
        require_enum(self.outcome, Outcome, "target outcome")
        require_exact_type(self.observation, TargetObservation, "target observation")
        if self.identity.canonical_key != self.observation.identity.canonical_key:
            raise DomainError("target outcome identity disagrees with its observation")
        if self.outcome is not classify_target(self.observation):
            raise DomainError("target outcome does not satisfy its classification predicate")
        object.__setattr__(self, "target_reason", canonical_identifier(self.target_reason, "target reason"))
        if _trusted_context is not _TRUSTED_ENGINE_CONTEXT:
            raise DomainError("target outcome evidence requires trusted engine execution")
        object.__setattr__(self, "_trusted", True)

    @property
    def canonical_key(self) -> tuple:
        return (*self.identity.canonical_key, self.outcome.value)

    def canonical_dict(self) -> dict:
        return {
            "identity": self.identity.canonical_dict(),
            "outcome": self.outcome.value,
            "target_reason": self.target_reason,
            "counts": {
                "baseline": self.observation.baseline_occurrences,
                "candidate": self.observation.candidate_matches,
            },
        }


GateExecutor = Callable[[str, str, Path], GateResult]


_ENGINE_DELTA_CLASSES = frozenset({
    DeltaClass.RULE_SUBSTITUTED,
    DeltaClass.COVERAGE_DECREASED,
    DeltaClass.DIAGNOSTIC_ADDED,
    DeltaClass.DESTRUCTIVE_CHANGE,
    DeltaClass.POLICY_DRIFT,
})


@dataclass(frozen=True, slots=True)
class EngineEventEvaluation:
    """Typed evaluation of one delta class that D3 finding evidence cannot prove."""

    delta_class: DeltaClass
    status: Status
    reason_code: str
    affected_resources: tuple = ()
    affected_paths: tuple = ()
    detail: str = ""

    def __post_init__(self) -> None:
        require_enum(self.delta_class, DeltaClass, "engine delta class")
        if self.delta_class not in _ENGINE_DELTA_CLASSES:
            raise DomainError("EngineEventEvaluation accepts only D5-derived delta classes")
        require_enum(self.status, Status, "engine event status")
        object.__setattr__(self, "reason_code", canonical_identifier(self.reason_code, "engine event reason"))
        for name in ("affected_resources", "affected_paths"):
            raw = getattr(self, name)
            if type(raw) is not tuple or any(type(item) is not str or not item for item in raw):
                raise DomainError(f"{name} must be an exact tuple of nonblank strings")
            object.__setattr__(self, name, tuple(sorted(set(raw))))
        if type(self.detail) is not str:
            raise DomainError("engine event detail must be a string")

    @property
    def canonical_key(self) -> tuple:
        return (self.delta_class.value, self.status.value, self.reason_code,
                self.affected_resources, self.affected_paths, self.detail)

    def canonical_dict(self) -> dict:
        return {
            "delta_class": self.delta_class.value,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "affected_resources": list(self.affected_resources),
            "affected_paths": list(self.affected_paths),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ChangeMetrics:
    """Deterministic V4 metrics; unavailable values are named, never omitted."""

    lines_added: int
    lines_removed: int
    lines_changed: int
    diff_ratio: float
    files_changed: int
    resources_changed: int
    resources_added: int
    resources_deleted: int
    policy_files_changed: int | None
    unavailable_metrics: tuple = ()

    def __post_init__(self) -> None:
        for name in (
            "lines_added", "lines_removed", "lines_changed", "files_changed",
            "resources_changed", "resources_added", "resources_deleted",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise DomainError(f"{name} must be a nonnegative exact int")
        if type(self.diff_ratio) is not float or self.diff_ratio < 0:
            raise DomainError("diff_ratio must be a nonnegative float")
        if self.policy_files_changed is not None and (
            type(self.policy_files_changed) is not int or self.policy_files_changed < 0
        ):
            raise DomainError("policy_files_changed must be a nonnegative int or None")
        if type(self.unavailable_metrics) is not tuple:
            raise DomainError("unavailable_metrics must be an exact tuple")
        object.__setattr__(self, "unavailable_metrics", tuple(sorted(set(self.unavailable_metrics))))

    def canonical_dict(self) -> dict:
        return {
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            "lines_changed": self.lines_changed,
            "diff_ratio": self.diff_ratio,
            "files_changed": self.files_changed,
            "resources_changed": self.resources_changed,
            "resources_added": self.resources_added,
            "resources_deleted": self.resources_deleted,
            "policy_files_changed": self.policy_files_changed,
            "unavailable_metrics": list(self.unavailable_metrics),
        }


@dataclass(frozen=True, slots=True)
class VerificationResult:
    baseline_run: ScannerRun
    candidate_run: ScannerRun
    finding_diff: FindingDiffResult
    target_outcomes: tuple
    preflight: GateResult
    scanner_integrity: GateResult
    validator_results: tuple
    oracle_results: tuple
    regression: GateResult
    suppression: GateResult
    engine_events: tuple
    change_metrics: ChangeMetrics
    required_gates: RequiredGates
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        require_trusted_scanner_run(self.baseline_run)
        require_trusted_scanner_run(self.candidate_run)
        require_trusted_diff_result(self.finding_diff)
        require_exact_type(self.required_gates, RequiredGates, "required gates")
        for name in ("preflight", "scanner_integrity", "regression", "suppression"):
            require_exact_type(getattr(self, name), GateResult, name)
        for name, expected_ids in (
            ("validator_results", self.required_gates.validator_ids),
            ("oracle_results", self.required_gates.oracle_ids),
        ):
            values = getattr(self, name)
            if type(values) is not tuple or any(type(item) is not GateResult for item in values):
                raise DomainError(f"{name} must be an exact tuple of GateResult")
            if tuple(item.gate_id for item in values) != expected_ids:
                raise DomainError(f"{name} do not exactly cover required gate identities")
        if type(self.target_outcomes) is not tuple or not self.target_outcomes:
            raise DomainError("target outcomes must be a nonempty exact tuple")
        if any(type(item) is not TargetOutcomeEvidence or not item._trusted for item in self.target_outcomes):
            raise DomainError("target outcomes contain caller-authored evidence")
        if type(self.engine_events) is not tuple:
            raise DomainError("engine_events must be an exact tuple")
        expected_classes = _ENGINE_DELTA_CLASSES
        actual_classes = {item.delta_class for item in self.engine_events
                          if type(item) is EngineEventEvaluation}
        if any(type(item) is not EngineEventEvaluation for item in self.engine_events):
            raise DomainError("engine_events must contain exact EngineEventEvaluation values")
        if actual_classes != expected_classes or len(self.engine_events) != len(expected_classes):
            raise DomainError("engine_events must evaluate every D5-derived delta class exactly once")
        require_exact_type(self.change_metrics, ChangeMetrics, "change metrics")
        if _trusted_context is not _TRUSTED_ENGINE_CONTEXT:
            raise DomainError("VerificationResult requires trusted engine execution")
        object.__setattr__(self, "target_outcomes", tuple(sorted(self.target_outcomes, key=lambda x: x.canonical_key)))
        object.__setattr__(self, "engine_events", tuple(sorted(self.engine_events, key=lambda x: x.canonical_key)))
        object.__setattr__(self, "_trusted", True)

    def _event(self, delta_class: DeltaClass) -> EngineEventEvaluation:
        return next(item for item in self.engine_events if item.delta_class is delta_class)

    @property
    def policy_drift(self) -> bool:
        return self._event(DeltaClass.POLICY_DRIFT).status is Status.FAIL

    @property
    def coverage_decreased_on_required_scanner(self) -> bool:
        return self._event(DeltaClass.COVERAGE_DECREASED).status is not Status.PASS

    @property
    def rule_substituted_on_required_target(self) -> bool:
        return self._event(DeltaClass.RULE_SUBSTITUTED).status is not Status.PASS

    def canonical_dict(self) -> dict:
        return {
            "preflight": self.preflight.canonical_dict(),
            "scanner_integrity": self.scanner_integrity.canonical_dict(),
            "validators": [item.canonical_dict() for item in self.validator_results],
            "oracles": [item.canonical_dict() for item in self.oracle_results],
            "targets": [item.canonical_dict() for item in self.target_outcomes],
            "finding_diff": self.finding_diff.canonical_dict(),
            "regression": self.regression.canonical_dict(),
            "suppression": self.suppression.canonical_dict(),
            "engine_events": [item.canonical_dict() for item in self.engine_events],
            "change_metrics": self.change_metrics.canonical_dict(),
            "baseline_run": self.baseline_run.canonical_dict(),
            "candidate_run": self.candidate_run.canonical_dict(),
        }


def require_trusted_verification_result(value: object) -> VerificationResult:
    require_exact_type(value, VerificationResult, "verification result")
    if not value._trusted:
        raise DomainError("verification result is caller-authored, not trusted engine evidence")
    return value


def _gate_results(
    ids: tuple,
    kind: str,
    root: Path,
    executor: GateExecutor | None,
) -> tuple[GateResult, ...]:
    results: list[GateResult] = []
    for gate_id in ids:
        if executor is None:
            result = GateResult(gate_id, Status.UNSUPPORTED, "GATE_EXECUTOR_UNAVAILABLE")
        else:
            result = executor(kind, gate_id, root)
            require_exact_type(result, GateResult, f"{kind} executor result")
            if result.gate_id != gate_id:
                raise DomainError(f"{kind} executor substituted {result.gate_id!r} for {gate_id!r}")
            result = GateResult(result.gate_id, result.status, result.reason_code, result.detail)
        results.append(result)
    return tuple(results)


def _target_paths(run: ScannerRun, target: Target) -> tuple[str, ...]:
    return tuple(sorted({
        finding.location.file_path
        for finding in run.findings
        if finding.scanner == target.scanner
        and finding.rule_id == target.rule_id
        and finding.resource_address == target.scope
    }))


def _execution_identity(run: ScannerRun) -> tuple:
    return (
        run.scanner,
        run.scanner_version,
        run.launcher_digest,
        run.scanner_environment_digest,
        run.policy_inventory_digest,
        run.invocation_config_digest,
    )


def _occurrence_complete_pass(
    target: Target,
    baseline_findings: tuple,
    candidate: ScannerRun,
    candidate_resource_paths: frozenset[str],
) -> bool:
    """A generic positive record closes one occurrence, never an arbitrary multiset."""
    passed = tuple(
        item for item in candidate.evaluations
        if item.rule_id == target.rule_id
        and item.resource_address == target.scope
        and item.native_result.value == "PASSED"
        and item.file_path in candidate_resource_paths
    )
    if not passed:
        return False
    if target.baseline_occurrences == 1:
        return True
    baseline_tokens = {
        item.native_fingerprint for item in baseline_findings if item.native_fingerprint
    }
    evaluated_tokens = {
        key for item in passed for key in item.evaluated_keys if key
    }
    if len(baseline_tokens) == target.baseline_occurrences:
        return baseline_tokens <= evaluated_tokens
    distinct_evaluated_scopes = {
        (item.file_path, item.evaluated_keys)
        for item in passed if item.evaluated_keys
    }
    return len(distinct_evaluated_scopes) >= target.baseline_occurrences


def _target_observation(
    target: Target,
    baseline: ScannerRun,
    candidate: ScannerRun,
    diff: FindingDiffResult,
    request: VerificationRequest,
) -> tuple[TargetObservation, str]:
    run_ok = baseline.status is Status.PASS and candidate.status is Status.PASS
    stable = (
        baseline.scanner == candidate.scanner == target.scanner
        and _execution_identity(baseline) == _execution_identity(candidate)
        and baseline.ruleset_integrity is Status.PASS
        and candidate.ruleset_integrity is Status.PASS
    )
    baseline_findings = tuple(
        f for f in baseline.findings
        if f.rule_id == target.rule_id and f.resource_address == target.scope
    )
    candidate_findings = tuple(
        f for f in candidate.findings
        if f.rule_id == target.rule_id and f.resource_address == target.scope and not f.suppressed
    )
    baseline_paths = _target_paths(baseline, target)
    eligible = set(request.candidate_scan.files_eligible)
    target_resource_records = tuple(
        item for item in request.candidate_scan.expected_resources
        if item.resource_address == target.scope
    )
    expected_resources = {item.resource_address for item in request.candidate_scan.expected_resources}
    resource_present = target.scope in expected_resources
    path_present = resource_present or any(path in eligible for path in baseline_paths)
    physical_present = any((request.candidate_scan.scan_root / path).is_file() for path in baseline_paths)
    if resource_present or path_present:
        file_state = Status.PASS
        eligibility = Status.PASS
    elif baseline_paths and physical_present:
        file_state = Status.PASS
        eligibility = Status.FAIL
    elif baseline_paths:
        file_state = Status.FAIL
        eligibility = Status.PASS
    else:
        file_state = Status.INCONCLUSIVE
        eligibility = Status.INCONCLUSIVE
    resource_state = Status.PASS if resource_present else Status.FAIL
    ambiguity = any(
        any(f.rule_id == target.rule_id and f.resource_address == target.scope
            for f in (*item.baseline, *item.candidate))
        for item in diff.ambiguities
    )
    target_evidence = evaluate_checkov_target(
        candidate, target.rule_id, target.scope,
        baseline_paths[0] if len(baseline_paths) == 1 and baseline_paths[0] in eligible else None,
    )
    suppressed = (
        target_evidence.reason is CheckTargetReason.TARGET_SUPPRESSED
        or any(f.suppressed for f in candidate.findings
               if f.rule_id == target.rule_id and f.resource_address == target.scope)
    )
    baseline_count_ok = len(baseline_findings) == target.baseline_occurrences
    candidate_resource_paths = frozenset(item.file_path for item in target_resource_records)
    artifact_kinds = {item.artifact_kind for item in baseline_findings}
    candidate_artifact_kinds = {item.artifact_kind for item in target_resource_records}
    domain_bound = (
        len(artifact_kinds) == 1
        and artifact_kinds == candidate_artifact_kinds
        and bool(candidate_resource_paths)
    )
    complete_pass = (
        target_evidence.status is Status.PASS
        and domain_bound
        and _occurrence_complete_pass(
            target, baseline_findings, candidate, candidate_resource_paths
        )
    )
    affirmative_status = (
        Status.PASS if complete_pass
        else Status.INCONCLUSIVE if target_evidence.status is Status.PASS
        else target_evidence.status
    )
    observation = TargetObservation(
        identity=target.identity,
        baseline_occurrences=target.baseline_occurrences,
        candidate_matches=len(candidate_findings),
        scanner_integrity=Status.PASS if run_ok else Status.ERROR,
        ruleset_integrity=Status.PASS if stable else Status.FAIL,
        artifact_eligibility=eligibility,
        target_file_presence=file_state,
        target_resource_presence=resource_state,
        suppression_absence=Status.FAIL if suppressed else Status.PASS,
        occurrence_evidence=(Status.PASS if baseline_count_ok and not ambiguity else Status.INCONCLUSIVE),
        affirmative_target_pass=affirmative_status,
    )
    reason = (
        "OCCURRENCE_PASS_COVERAGE_INCOMPLETE"
        if target_evidence.status is Status.PASS and not complete_pass
        else target_evidence.reason.value
    )
    return observation, reason


def _regression_result(
    request: VerificationRequest,
    diff: FindingDiffResult,
    outcomes: tuple,
    engine_events: tuple,
) -> GateResult:
    if diff.ambiguities:
        return GateResult("regression", Status.INCONCLUSIVE, "MATCHING_INCONCLUSIVE")
    decisive = []
    uncertain = []
    floor = SEVERITY_ORDER.index(request.severity_floor)
    suppressed_targets = {
        item.identity.canonical_key
        for item in outcomes if item.outcome is Outcome.SUPPRESSED
    }
    for delta in diff.deltas:
        if delta.delta_class is DeltaClass.NEW_FINDING:
            if delta.candidate.severity is Severity.UNKNOWN:
                uncertain.append("NEW_FINDING_SEVERITY_UNKNOWN")
            elif SEVERITY_ORDER.index(delta.candidate.severity) >= floor:
                decisive.append(delta.delta_class.value)
        elif delta.delta_class in {
            DeltaClass.SEVERITY_INCREASED,
            DeltaClass.SCOPE_EXPANDED,
            DeltaClass.SUPPRESSION_ADDED,
        }:
            if delta.delta_class is DeltaClass.SUPPRESSION_ADDED:
                candidate = delta.candidate
                identity = (candidate.scanner, candidate.rule_id, candidate.resource_address)
                if identity in suppressed_targets:
                    continue
            decisive.append(delta.delta_class.value)
        elif delta.delta_class is DeltaClass.LOCATION_CHANGED and request.fail_on_location_change:
            decisive.append(delta.delta_class.value)
    destructive = next(
        item for item in engine_events
        if item.delta_class is DeltaClass.DESTRUCTIVE_CHANGE
    )
    target_scopes = {
        item.identity.scope for item in outcomes
        if item.outcome in {Outcome.RESOURCE_DELETED, Outcome.FILE_DELETED_OR_RENAMED}
    }
    unrelated_deleted = set(destructive.affected_resources) - target_scopes
    if unrelated_deleted:
        decisive.append(DeltaClass.DESTRUCTIVE_CHANGE.value)
    if uncertain:
        return GateResult(
            "regression", Status.INCONCLUSIVE, uncertain[0],
            ",".join(sorted(set(uncertain))),
        )
    if decisive:
        return GateResult("regression", Status.FAIL, "REGRESSION_DETECTED", ",".join(sorted(set(decisive))))
    return GateResult("regression", Status.PASS, "NO_DECISIVE_REGRESSION")


def _preflight_result(
    request: VerificationRequest, baseline: ScannerRun, candidate: ScannerRun
) -> GateResult:
    payload = {
        "baseline": [item.canonical_dict() for item in request.baseline_scan.eligible_file_evidence],
        "candidate": [item.canonical_dict() for item in request.candidate_scan.eligible_file_evidence],
        "baseline_resources": [item.canonical_dict() for item in request.baseline_scan.expected_resources],
        "candidate_resources": [item.canonical_dict() for item in request.candidate_scan.expected_resources],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    expected_inputs = (
        tuple(item.canonical_dict() for item in request.baseline_scan.eligible_file_evidence),
        tuple(item.canonical_dict() for item in request.candidate_scan.eligible_file_evidence),
    )
    actual_inputs = (
        tuple(item.canonical_dict() for item in baseline.input_files),
        tuple(item.canonical_dict() for item in candidate.input_files),
    )
    preparation_failures = {
        AdapterReason.INPUT_CHANGED_DURING_SCAN_PREPARATION.value,
        AdapterReason.SCAN_VIEW_PREPARATION_FAILED.value,
        AdapterReason.OUTPUT_DIRECTORY_INTEGRITY_FAILED.value,
    }
    failed_diagnostics = tuple(sorted(
        diagnostic for run in (baseline, candidate) for diagnostic in run.diagnostics
        if diagnostic in preparation_failures
    ))
    if actual_inputs != expected_inputs or failed_diagnostics:
        return GateResult(
            "preflight", Status.ERROR, "BOUND_INPUT_REVALIDATION_FAILED",
            ",".join(failed_diagnostics) or "adapter input evidence disagrees with plan",
        )
    return GateResult(
        "preflight", Status.PASS, "BOUND_SCAN_PLAN_VALIDATED",
        f"plan_sha256={digest};files={len(payload['baseline'])}+{len(payload['candidate'])}",
    )


def _engine_events(
    request: VerificationRequest,
    baseline: ScannerRun,
    candidate: ScannerRun,
    stable_run: bool,
) -> tuple[EngineEventEvaluation, ...]:
    baseline_resources = {
        item.canonical_key: item for item in request.baseline_scan.expected_resources
    }
    candidate_resources = {
        item.canonical_key: item for item in request.candidate_scan.expected_resources
    }
    deleted_records = tuple(
        baseline_resources[key]
        for key in sorted(set(baseline_resources) - set(candidate_resources))
    )
    deleted = tuple(sorted({item.resource_address for item in deleted_records}))
    deleted_paths = tuple(sorted({item.file_path for item in deleted_records}))
    coverage_decreased = (
        candidate.status is Status.PARTIAL
        or candidate.coverage.files_parsed < candidate.coverage.files_eligible
        or candidate.resource_coverage.resources_observed
        < candidate.resource_coverage.resources_expected
    )
    coverage_status = (
        Status.FAIL if coverage_decreased
        else Status.PASS if candidate.status is Status.PASS
        else Status.INCONCLUSIVE
    )
    added_diagnostics = tuple(sorted(set(candidate.diagnostics) - set(baseline.diagnostics)))
    policy_drift = (
        request.trusted_governed_config_sha256
        != request.candidate_governed_config_sha256
    )
    return (
        EngineEventEvaluation(
            DeltaClass.RULE_SUBSTITUTED,
            Status.PASS if stable_run else Status.INCONCLUSIVE,
            "RULE_IDENTITY_STABLE" if stable_run else "RULE_SUBSTITUTION_NOT_DECIDABLE",
        ),
        EngineEventEvaluation(
            DeltaClass.COVERAGE_DECREASED,
            coverage_status,
            "COVERAGE_COMPLETE" if coverage_status is Status.PASS else "COVERAGE_DECREASED_OR_UNCERTAIN",
        ),
        EngineEventEvaluation(
            DeltaClass.DIAGNOSTIC_ADDED,
            Status.FAIL if added_diagnostics else Status.PASS,
            "DIAGNOSTICS_ADDED" if added_diagnostics else "NO_DIAGNOSTICS_ADDED",
            detail=",".join(added_diagnostics),
        ),
        EngineEventEvaluation(
            DeltaClass.DESTRUCTIVE_CHANGE,
            Status.FAIL if deleted else Status.PASS,
            "RESOURCES_DELETED" if deleted else "NO_RESOURCES_DELETED",
            affected_resources=deleted,
            affected_paths=deleted_paths,
        ),
        EngineEventEvaluation(
            DeltaClass.POLICY_DRIFT,
            Status.FAIL if policy_drift else Status.PASS,
            "GOVERNED_CONFIG_DRIFT" if policy_drift else "GOVERNED_CONFIG_STABLE",
            detail=(
                f"trusted={request.trusted_governed_config_sha256};"
                f"candidate={request.candidate_governed_config_sha256}"
            ),
        ),
    )


def _read_bound_texts(scan: TrustedScanPlan) -> dict[str, tuple[str, ...]]:
    values = {}
    for evidence in scan.files:
        values[evidence.file_path] = tuple(
            evidence.content.decode("utf-8", errors="strict").splitlines()
        )
    return values


def _change_metrics(request: VerificationRequest) -> ChangeMetrics:
    before = _read_bound_texts(request.baseline_scan)
    after = _read_bound_texts(request.candidate_scan)
    added = removed = 0
    changed_files = 0
    for path in sorted(set(before) | set(after)):
        old = before.get(path, ())
        new = after.get(path, ())
        if old == new:
            continue
        changed_files += 1
        for line in difflib.ndiff(old, new):
            if line.startswith("+ "):
                added += 1
            elif line.startswith("- "):
                removed += 1
    before_resources = {item.canonical_key for item in request.baseline_scan.expected_resources}
    after_resources = {item.canonical_key for item in request.candidate_scan.expected_resources}
    resource_added = len(after_resources - before_resources)
    resource_deleted = len(before_resources - after_resources)
    denominator = max(sum(len(lines) for lines in before.values()), 1)
    return ChangeMetrics(
        added, removed, added + removed, float((added + removed) / denominator),
        changed_files, resource_added + resource_deleted, resource_added,
        resource_deleted, None, ("policy_files_changed",),
    )


def run_checkov_verification(
    request: VerificationRequest,
    *,
    _gate_executor: GateExecutor | None = None,
) -> VerificationResult:
    """Run both scans and derive all D5 evidence internally.

    ``_gate_executor`` is an in-process trusted dependency hook for validator/oracle
    implementations. It is deliberately absent from ``VerificationRequest`` and cannot
    be supplied through CLI/config/JSON.
    """
    require_exact_type(request, VerificationRequest, "verification request")
    adapter = CheckovAdapter()
    baseline = require_trusted_scanner_run(adapter.scan(request.baseline_scan.request))
    candidate = require_trusted_scanner_run(adapter.scan(request.candidate_scan.request))
    stable_run = (
        _execution_identity(baseline) == _execution_identity(candidate)
        and baseline.ruleset_integrity is Status.PASS
        and candidate.ruleset_integrity is Status.PASS
    )
    if stable_run:
        diff = diff_findings(baseline.findings, candidate.findings)
    else:
        diff = diff_findings((), ())
    outcomes = []
    for target in request.targets:
        observation, reason = _target_observation(target, baseline, candidate, diff, request)
        outcomes.append(
            TargetOutcomeEvidence(
                target.identity,
                classify_target(observation),
                observation,
                reason,
                _trusted_context=_TRUSTED_ENGINE_CONTEXT,
            )
        )
    candidate_root = request.candidate_scan.scan_root
    validators = _gate_results(
        request.required_gates.validator_ids, "validator", candidate_root, _gate_executor
    )
    oracles = _gate_results(
        request.required_gates.oracle_ids, "oracle", candidate_root, _gate_executor
    )
    scanner_status = (
        Status.PASS
        if baseline.status is Status.PASS and candidate.status is Status.PASS and stable_run
        else Status.INCONCLUSIVE
    )
    engine_events = _engine_events(request, baseline, candidate, stable_run)
    regression = _regression_result(request, diff, tuple(outcomes), engine_events)
    suppression_status = (
        Status.PASS if candidate.status is Status.PASS else Status.INCONCLUSIVE
    )
    return VerificationResult(
        baseline,
        candidate,
        diff,
        tuple(outcomes),
        _preflight_result(request, baseline, candidate),
        GateResult(
            "scanner_integrity", scanner_status,
            "SCANNER_EVIDENCE_RECONCILED" if scanner_status is Status.PASS
            else "SCANNER_EXECUTION_IDENTITY_DRIFT_OR_FAILURE",
        ),
        validators,
        oracles,
        regression,
        GateResult("suppression", suppression_status, "SUPPRESSION_DETECTOR_COMPLETED"),
        engine_events,
        _change_metrics(request),
        request.required_gates,
        _trusted_context=_TRUSTED_ENGINE_CONTEXT,
    )


__all__ = [
    "ChangeMetrics", "EngineEventEvaluation", "ScanPlanFile", "TargetObservation",
    "TargetOutcomeEvidence", "TrustedScanPlan", "VerificationRequest",
    "VerificationResult", "attest_checkov_scan_plan", "classify_target",
    "require_trusted_verification_result", "run_checkov_verification",
]
