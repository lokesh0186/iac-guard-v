"""Repository-wide validation-universe planning and conservative aggregation."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from ..adapters.phase_e_lock import (
    LockedContainerIdentity,
    ProtectedKubernetesSchemaIdentity,
)
from ..adapters.phase_e_runtime import TrustedContainerRuntime
from ..engine import SealedVerificationSnapshot, _filesystem_inventory
from ..enums import ScanRole, Status
from ..models import DomainError, canonical_identifier
from .base import ValidationReason, ValidatorExecutionEvidence, require_trusted_validator_evidence
from .kubeconform import create_kubeconform_validation_request
from .materialization import VALIDATION_SCOPE_CONTRACT
from .registry import production_validator_registry
from .terraform import create_terraform_validation_request
from .tflint import create_tflint_validation_request, load_protected_tflint_config


UNIVERSE_CONTRACT = "trusted-validation-universe-v2"
TF_JSON_REASON = "TF_JSON_UNSUPPORTED"
_PLAN_CONTEXT = object()
_RESULT_CONTEXT = object()
_SHA = re.compile(r"[0-9a-f]{64}")


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ValidationUniverseFile:
    file_path: str
    kind: str
    size: int
    sha256: str

    def __post_init__(self) -> None:
        from ..models import canonical_repo_path
        object.__setattr__(self, "file_path", canonical_repo_path(self.file_path))
        if self.kind != "REGULAR_FILE" or type(self.size) is not int or self.size < 0:
            raise DomainError("validation universe file must be a regular file")
        if type(self.sha256) is not str or not _SHA.fullmatch(self.sha256):
            raise DomainError("validation universe file digest is invalid")

    def canonical_dict(self) -> dict:
        return {
            "file_path": self.file_path, "kind": self.kind,
            "size": self.size, "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class ValidationUniverseModule:
    module_root: str
    files: tuple
    manifest_sha256: str

    def __post_init__(self) -> None:
        from ..models import canonical_repo_path
        if self.module_root != ".":
            object.__setattr__(self, "module_root", canonical_repo_path(self.module_root))
        if type(self.files) is not tuple or not self.files or any(
            type(item) is not ValidationUniverseFile for item in self.files
        ):
            raise DomainError("validation module universe files are invalid")
        if tuple(item.file_path for item in self.files) != tuple(sorted(
            item.file_path for item in self.files
        )):
            raise DomainError("validation module universe files must be sorted")
        if any(
            (PurePosixPath(item.file_path).parent.as_posix() or ".") != self.module_root
            for item in self.files
        ):
            raise DomainError("validation module universe crosses module roots")
        if self.manifest_sha256 != _sha([item.canonical_dict() for item in self.files]):
            raise DomainError("validation module universe manifest is not canonical")

    def canonical_dict(self) -> dict:
        return {
            "module_root": self.module_root,
            "files": [item.canonical_dict() for item in self.files],
            "manifest_sha256": self.manifest_sha256,
        }


@dataclass(frozen=True, slots=True)
class TrustedValidationUniversePlan:
    role: ScanRole
    repository_identity: str
    repository_relative_subpath: str
    sealed_snapshot_identity: str
    sealed_artifact_manifest_identity: str
    terraform_modules: tuple
    kubernetes_files: tuple
    kubernetes_resource_identities: tuple
    unsupported_tf_json: tuple
    unresolved_entries: tuple
    physical_inventory_sha256: str
    universe_sha256: str
    contract: str = UNIVERSE_CONTRACT
    _snapshot: SealedVerificationSnapshot = field(repr=False, compare=False, default=None)
    _trusted_context: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._trusted_context is not _PLAN_CONTEXT:
            raise DomainError("validation universe requires the sealed-snapshot factory")
        if type(self._snapshot) is not SealedVerificationSnapshot or not self._snapshot._trusted:
            raise DomainError("validation universe snapshot is not trusted")
        if self.role not in {ScanRole.BASELINE, ScanRole.CANDIDATE}:
            raise DomainError("validation universe role is invalid")
        if self.contract != UNIVERSE_CONTRACT:
            raise DomainError("validation universe contract is unsupported")
        for name in (
            "sealed_snapshot_identity", "sealed_artifact_manifest_identity",
            "physical_inventory_sha256", "universe_sha256",
        ):
            if type(getattr(self, name)) is not str or not _SHA.fullmatch(getattr(self, name)):
                raise DomainError(f"validation universe {name} is invalid")
        if type(self.terraform_modules) is not tuple or any(
            type(item) is not ValidationUniverseModule for item in self.terraform_modules
        ):
            raise DomainError("validation universe modules are invalid")
        roots = tuple(item.module_root for item in self.terraform_modules)
        if roots != tuple(sorted(set(roots))):
            raise DomainError("validation universe module roots must be sorted and unique")
        if type(self.kubernetes_files) is not tuple or any(
            type(item) is not ValidationUniverseFile for item in self.kubernetes_files
        ):
            raise DomainError("validation universe Kubernetes files are invalid")
        for values, label in (
            (self.kubernetes_resource_identities, "Kubernetes resources"),
            (self.unsupported_tf_json, "unsupported Terraform JSON"),
            (self.unresolved_entries, "unresolved entries"),
        ):
            if type(values) is not tuple or values != tuple(sorted(set(values))):
                raise DomainError(f"validation universe {label} must be sorted and unique")
        if self.sealed_snapshot_identity != self._snapshot.snapshot_sha256:
            raise DomainError("validation universe snapshot identity disagrees with snapshot")
        if self.repository_identity != self._snapshot.repository_identity:
            raise DomainError("validation universe repository identity disagrees with snapshot")
        if self.repository_relative_subpath != self._snapshot.repository_relative_subpath:
            raise DomainError("validation universe repository subpath disagrees with snapshot")
        if self.sealed_artifact_manifest_identity != self._snapshot.artifact_manifest_sha256:
            raise DomainError("validation universe artifact manifest disagrees with snapshot")
        if self.physical_inventory_sha256 != _physical_digest(
            self._snapshot.filesystem_entries
        ):
            raise DomainError("validation universe physical inventory disagrees with snapshot")
        expected = _derive_validation_universe(self._snapshot)
        if (
            self.terraform_modules != expected[0]
            or self.kubernetes_files != expected[1]
            or self.kubernetes_resource_identities != expected[2]
            or self.unsupported_tf_json != expected[3]
            or self.unresolved_entries != expected[4]
        ):
            raise DomainError("validation universe contents disagree with sealed snapshot")
        if self.universe_sha256 != _sha(self._identity_payload()):
            raise DomainError("validation universe identity is not canonical")

    @property
    def ready(self) -> bool:
        return not self.unsupported_tf_json and not self.unresolved_entries

    def _identity_payload(self) -> dict:
        return {
            "contract": self.contract,
            "role": self.role.value,
            "repository_identity": self.repository_identity,
            "repository_relative_subpath": self.repository_relative_subpath,
            "sealed_snapshot_identity": self.sealed_snapshot_identity,
            "sealed_artifact_manifest_identity": self.sealed_artifact_manifest_identity,
            "terraform_modules": [item.canonical_dict() for item in self.terraform_modules],
            "kubernetes_files": [item.canonical_dict() for item in self.kubernetes_files],
            "kubernetes_resource_identities": list(self.kubernetes_resource_identities),
            "unsupported_tf_json": list(self.unsupported_tf_json),
            "unresolved_entries": list(self.unresolved_entries),
            "physical_inventory_sha256": self.physical_inventory_sha256,
        }

    def canonical_dict(self) -> dict:
        return {**self._identity_payload(), "universe_sha256": self.universe_sha256}


def _physical_digest(entries: tuple) -> str:
    return _sha([item.canonical_dict() for item in entries])


def _derive_validation_universe(snapshot: SealedVerificationSnapshot) -> tuple:
    entries = snapshot.filesystem_entries
    classifications = {item.file_path: item for item in snapshot.classifications}
    modules: dict[str, list[ValidationUniverseFile]] = {}
    unsupported = []
    unresolved = []
    for entry in entries:
        lower = entry.file_path.lower()
        if lower.endswith(".tf.json"):
            unsupported.append(entry.file_path)
            continue
        if lower.endswith(".tf"):
            if entry.kind != "REGULAR_FILE" or entry.sha256 is None:
                unresolved.append(f"{entry.file_path}:{entry.kind}")
                continue
            parent = PurePosixPath(entry.file_path).parent.as_posix() or "."
            modules.setdefault(parent, []).append(ValidationUniverseFile(
                entry.file_path, entry.kind, entry.size, entry.sha256,
            ))
        if (entry.supported or entry.governed) and entry.rejection_reason:
            unresolved.append(f"{entry.file_path}:{entry.rejection_reason}")
    module_records = tuple(
        ValidationUniverseModule(
            root, tuple(sorted(module_files, key=lambda item: item.file_path)),
            _sha([
                item.canonical_dict()
                for item in sorted(module_files, key=lambda item: item.file_path)
            ]),
        )
        for root, module_files in sorted(modules.items())
    )
    kubernetes_paths = tuple(sorted(
        path for path, item in classifications.items()
        if item.classification == "KUBERNETES_RESOURCES"
    ))
    by_path = {item.file_path: item for item in entries}
    try:
        kubernetes_files = tuple(
            ValidationUniverseFile(
                path, by_path[path].kind, by_path[path].size, by_path[path].sha256,
            )
            for path in kubernetes_paths
        )
    except (KeyError, DomainError) as exc:
        raise DomainError(
            "validation universe classifications disagree with physical inventory"
        ) from exc
    resource_identities = tuple(sorted(
        f"{item.file_path}:{item.resource_address}" for item in snapshot.resources
        if item.file_path in kubernetes_paths
    ))
    return (
        module_records, kubernetes_files, resource_identities,
        tuple(sorted(unsupported)), tuple(sorted(set(unresolved))),
    )


def create_trusted_validation_universe_plan(
    snapshot: SealedVerificationSnapshot,
) -> TrustedValidationUniversePlan:
    if type(snapshot) is not SealedVerificationSnapshot or not snapshot._trusted:
        raise DomainError("validation universe requires a trusted sealed snapshot")
    (
        module_records, kubernetes_files, resource_identities,
        unsupported, unresolved,
    ) = _derive_validation_universe(snapshot)
    physical = _physical_digest(snapshot.filesystem_entries)
    values = {
        "contract": UNIVERSE_CONTRACT,
        "role": snapshot.role.value,
        "repository_identity": snapshot.repository_identity,
        "repository_relative_subpath": snapshot.repository_relative_subpath,
        "sealed_snapshot_identity": snapshot.snapshot_sha256,
        "sealed_artifact_manifest_identity": snapshot.artifact_manifest_sha256,
        "terraform_modules": [item.canonical_dict() for item in module_records],
        "kubernetes_files": [item.canonical_dict() for item in kubernetes_files],
        "kubernetes_resource_identities": list(resource_identities),
        "unsupported_tf_json": list(unsupported),
        "unresolved_entries": list(unresolved),
        "physical_inventory_sha256": physical,
    }
    return TrustedValidationUniversePlan(
        snapshot.role, snapshot.repository_identity, snapshot.repository_relative_subpath,
        snapshot.snapshot_sha256, snapshot.artifact_manifest_sha256, module_records,
        kubernetes_files, resource_identities, unsupported,
        unresolved, physical, _sha(values),
        _snapshot=snapshot, _trusted_context=_PLAN_CONTEXT,
    )


def revalidate_validation_universe_plan(
    plan: TrustedValidationUniversePlan, scan_root: Path,
) -> None:
    if type(plan) is not TrustedValidationUniversePlan or plan._trusted_context is not _PLAN_CONTEXT:
        raise DomainError("validation universe plan is not trusted")
    try:
        current = _filesystem_inventory(
            scan_root, max_files=10_000, max_file_bytes=8 * 1024 * 1024,
            max_total_bytes=64 * 1024 * 1024,
        )
    except DomainError as exc:
        raise DomainError(ValidationReason.SNAPSHOT_CHANGED_DURING_VALIDATION.value) from exc
    if [item.canonical_dict() for item in current] != [
        item.canonical_dict() for item in plan._snapshot.filesystem_entries
    ]:
        raise DomainError(ValidationReason.SNAPSHOT_CHANGED_DURING_VALIDATION.value)


def _expected_input_payload(
    record: ValidationUniverseFile, file_type: str,
) -> dict:
    return {
        "file_path": record.file_path,
        "file_type": file_type,
        "size": record.size,
        "sha256": record.sha256,
    }


def _expected_module_scope(
    plan: TrustedValidationUniversePlan, module: ValidationUniverseModule, tool: str,
) -> tuple[tuple[dict, ...], str, str]:
    inputs = tuple(
        _expected_input_payload(item, "terraform_hcl") for item in module.files
    )
    module_snapshot = _sha(list(inputs))
    scope_identity = _sha({
        "contract": VALIDATION_SCOPE_CONTRACT,
        "role": plan.role.value,
        "scope_kind": "terraform-module",
        "module_root": module.module_root,
        "files": list(inputs),
        "resource_identities": [],
    })
    return inputs, module_snapshot, scope_identity


def _expected_kubernetes_scope(
    plan: TrustedValidationUniversePlan,
) -> tuple[tuple[dict, ...], str]:
    inputs = tuple(
        _expected_input_payload(
            item,
            "kubernetes_json" if item.file_path.lower().endswith(".json")
            else "kubernetes_yaml",
        )
        for item in plan.kubernetes_files
    )
    scope_identity = _sha({
        "contract": VALIDATION_SCOPE_CONTRACT,
        "role": plan.role.value,
        "scope_kind": "kubernetes-artifact-universe",
        "module_root": ".",
        "files": list(inputs),
        "resource_identities": list(plan.kubernetes_resource_identities),
    })
    return inputs, scope_identity


def _reconcile_module_evidence(
    plan: TrustedValidationUniversePlan, validator_id: str,
    results: tuple[ValidatorExecutionEvidence, ...], advisory: bool,
) -> tuple[ValidatorExecutionEvidence, ...]:
    expected_tools = {
        "opentofu_validate": "opentofu",
        "terraform_validate": "terraform",
        "tflint_advisory": "tflint",
    }
    expected_tool = expected_tools.get(validator_id)
    if expected_tool is None or advisory is not (validator_id == "tflint_advisory"):
        raise DomainError("validator universe requested an unsupported identity")
    if len(results) != len(plan.terraform_modules):
        raise DomainError("validator evidence does not cover every repository module")
    observed = {}
    expected = {item.module_root: item for item in plan.terraform_modules}
    for result in results:
        require_trusted_validator_evidence(result)
        if (
            result.validator_id != validator_id
            or result.tool != expected_tool
            or result.advisory_only is not advisory
        ):
            raise DomainError("validator universe evidence identity is inconsistent")
        scope = dict(result.validation_scope)
        root = scope.get("module_root")
        if root in observed or root not in expected:
            raise DomainError("validator universe module evidence is duplicated or unbound")
        module = expected[root]
        expected_inputs, module_snapshot, scope_identity = _expected_module_scope(
            plan, module, expected_tool,
        )
        inputs = tuple(item.canonical_dict() for item in result.input_files)
        if inputs != expected_inputs:
            raise DomainError("validator universe module bytes disagree with sealed plan")
        expected_scope = {
            "kind": "terraform-module", "role": plan.role.value,
            "module_root": module.module_root,
            "module_snapshot_sha256": module_snapshot, "tool": expected_tool,
        }
        if expected_tool == "tflint":
            expected_scope["module_execution_complete"] = "true"
        if scope != expected_scope:
            raise DomainError("validator universe module scope contradicts sealed plan")
        if result.sealed_snapshot_identity != scope_identity:
            raise DomainError("validator universe module snapshot identity is inconsistent")
        expected_count = len(expected_inputs)
        if (
            result.files_eligible != expected_count
            or result.resources_expected != 0
            or result.resources_validated != 0
            or result.resource_identities
        ):
            raise DomainError("validator universe module coverage counters are inconsistent")
        if result.status is Status.PASS and result.files_validated != expected_count:
            raise DomainError("passing validator module evidence is incomplete")
        observed[root] = result
    return tuple(observed[root] for root in sorted(observed))


@dataclass(frozen=True, slots=True)
class ValidationUniverseResult:
    validator_id: str
    role: ScanRole
    universe_sha256: str
    status: Status
    reason: str
    advisory_only: bool
    module_results: tuple
    kubernetes_result: ValidatorExecutionEvidence | None = None
    _plan: TrustedValidationUniversePlan = field(repr=False, compare=False, default=None)
    _trusted_context: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._trusted_context is not _RESULT_CONTEXT:
            raise DomainError("validation universe result requires protected orchestration")
        object.__setattr__(
            self, "validator_id", canonical_identifier(self.validator_id, "validator id"),
        )
        if type(self.role) is not ScanRole or self.role is ScanRole.DISCOVERY:
            raise DomainError("validation universe result role is invalid")
        if not _SHA.fullmatch(self.universe_sha256):
            raise DomainError("validation universe result identity is invalid")
        if type(self.status) is not Status:
            raise DomainError("validation universe result status is invalid")
        object.__setattr__(self, "reason", canonical_identifier(self.reason, "universe reason"))
        if type(self.advisory_only) is not bool:
            raise DomainError("validation universe advisory flag is invalid")
        if (
            type(self._plan) is not TrustedValidationUniversePlan
            or self._plan._trusted_context is not _PLAN_CONTEXT
            or self.role is not self._plan.role
            or self.universe_sha256 != self._plan.universe_sha256
        ):
            raise DomainError("validation universe result is not bound to its trusted plan")
        if type(self.module_results) is not tuple or any(
            type(item) is not ValidatorExecutionEvidence for item in self.module_results
        ):
            raise DomainError("validation universe module results are invalid")
        for item in self.module_results:
            require_trusted_validator_evidence(item)
        if self.kubernetes_result is not None:
            require_trusted_validator_evidence(self.kubernetes_result)
            if (
                self.validator_id != "kubeconform_validate"
                or self.kubernetes_result.validator_id != self.validator_id
                or self.kubernetes_result.status is not self.status
            ):
                raise DomainError("Kubernetes universe result contradicts validator evidence")
            _validate_kubernetes_evidence(self._plan, self.kubernetes_result)
        if self.validator_id == "kubeconform_validate":
            if self.advisory_only or self.module_results:
                raise DomainError("Kubernetes universe result contains module evidence")
            if self.kubernetes_result is None:
                if (self.status is not Status.INCONCLUSIVE
                        or self.reason != "EMPTY_OR_UNRESOLVED_KUBERNETES_UNIVERSE"
                        or (self._plan.ready and self._plan.kubernetes_files)):
                    raise DomainError("empty Kubernetes universe result is contradictory")
            else:
                if self.status not in {Status.PASS, Status.FAIL, Status.INCONCLUSIVE}:
                    raise DomainError("Kubernetes universe aggregate status is unsupported")
                expected_reason = (
                    "COMPLETE_KUBERNETES_UNIVERSE_PASSED"
                    if self.status is Status.PASS else "KUBERNETES_UNIVERSE_NON_PASS"
                )
                if self.reason != expected_reason:
                    raise DomainError("Kubernetes universe status/reason is contradictory")
        else:
            allowed = {
                Status.PASS: {"ALL_REQUIRED_MODULES_PASSED"},
                Status.FAIL: {"MODULE_VALIDATION_FAILED"},
                Status.INCONCLUSIVE: {
                    "MODULE_VALIDATION_INCONCLUSIVE", TF_JSON_REASON,
                    "ARTIFACT_UNIVERSE_UNRESOLVED", "EMPTY_REQUIRED_MODULE_UNIVERSE",
                    "EMPTY_OR_UNRESOLVED_MODULE_UNIVERSE",
                },
            }
            if self.status not in allowed or self.reason not in allowed[self.status]:
                raise DomainError("module universe status/reason is contradictory")
            if self.kubernetes_result is not None:
                raise DomainError("module universe contains Kubernetes evidence")
            if self.status in {Status.PASS, Status.FAIL} and not self.module_results:
                raise DomainError("decided module universe requires module evidence")
            if self.module_results and self.module_results != _reconcile_module_evidence(
                self._plan, self.validator_id, self.module_results, self.advisory_only,
            ):
                raise DomainError("module universe result ordering is not canonical")
            if self.module_results:
                expected_status, expected_reason = _derived_module_aggregate(
                    self.module_results,
                )
                if self.status is not expected_status or self.reason != expected_reason:
                    raise DomainError(
                        "module universe status/reason aggregate contradicts child evidence"
                    )
            else:
                expected_reason = (
                    TF_JSON_REASON if self._plan.unsupported_tf_json
                    else "ARTIFACT_UNIVERSE_UNRESOLVED" if self._plan.unresolved_entries
                    else "EMPTY_OR_UNRESOLVED_MODULE_UNIVERSE"
                    if self.validator_id == "tflint_advisory"
                    else "EMPTY_REQUIRED_MODULE_UNIVERSE"
                )
                if self.status is not Status.INCONCLUSIVE or self.reason != expected_reason:
                    raise DomainError("empty module universe reason contradicts plan state")

    def canonical_dict(self) -> dict:
        return {
            "validator_id": self.validator_id, "role": self.role.value,
            "universe_sha256": self.universe_sha256, "status": self.status.value,
            "reason": self.reason, "advisory_only": self.advisory_only,
            "module_results": [item.canonical_dict() for item in self.module_results],
            "kubernetes_result": (
                self.kubernetes_result.canonical_dict() if self.kubernetes_result else None
            ),
        }


def _scope(record: ValidatorExecutionEvidence) -> dict[str, str]:
    return dict(record.validation_scope)


def _aggregate_module_results(
    plan: TrustedValidationUniversePlan, validator_id: str,
    results: tuple[ValidatorExecutionEvidence, ...], *, advisory: bool,
) -> ValidationUniverseResult:
    if not plan.terraform_modules:
        raise DomainError("validator evidence cannot prove an empty repository module universe")
    ordered = _reconcile_module_evidence(plan, validator_id, results, advisory)
    status, reason = _derived_module_aggregate(ordered)
    return ValidationUniverseResult(
        validator_id, plan.role, plan.universe_sha256, status, reason, advisory,
        ordered, _plan=plan, _trusted_context=_RESULT_CONTEXT,
    )


def _derived_module_aggregate(
    results: tuple[ValidatorExecutionEvidence, ...],
) -> tuple[Status, str]:
    if any(item.status is Status.FAIL for item in results):
        return Status.FAIL, "MODULE_VALIDATION_FAILED"
    if any(item.status is not Status.PASS for item in results):
        return Status.INCONCLUSIVE, "MODULE_VALIDATION_INCONCLUSIVE"
    return Status.PASS, "ALL_REQUIRED_MODULES_PASSED"


def _validate_kubernetes_evidence(
    plan: TrustedValidationUniversePlan, evidence: ValidatorExecutionEvidence,
) -> None:
    require_trusted_validator_evidence(evidence)
    if (
        evidence.validator_id != "kubeconform_validate"
        or evidence.tool != "kubeconform"
        or evidence.advisory_only
    ):
        raise DomainError("Kubernetes universe evidence identity is inconsistent")
    expected_inputs, scope_identity = _expected_kubernetes_scope(plan)
    if tuple(item.canonical_dict() for item in evidence.input_files) != expected_inputs:
        raise DomainError("Kubernetes universe files disagree with sealed plan")
    if evidence.sealed_snapshot_identity != scope_identity:
        raise DomainError("Kubernetes universe snapshot identity is inconsistent")
    expected_resources = plan.kubernetes_resource_identities
    expected_resource_digest = _sha(list(expected_resources))
    scope = _scope(evidence)
    if (
        scope.get("kind") != "kubernetes-resource-set"
        or scope.get("role") != plan.role.value
        or scope.get("expected_resources_sha256") != expected_resource_digest
        or set(scope) != {
            "kind", "role", "expected_resources_sha256", "observed_resources_sha256",
        }
    ):
        raise DomainError("Kubernetes universe validation scope is inconsistent")
    expected_files = len(expected_inputs)
    expected_resource_count = len(expected_resources)
    if (
        evidence.files_eligible != expected_files
        or evidence.resources_expected != expected_resource_count
    ):
        raise DomainError("Kubernetes universe expected coverage is inconsistent")
    if evidence.status is Status.PASS:
        if (
            evidence.files_validated != expected_files
            or evidence.resources_validated != expected_resource_count
            or evidence.resource_identities != expected_resources
            or scope["observed_resources_sha256"] != expected_resource_digest
        ):
            raise DomainError("passing Kubernetes universe evidence is incomplete")


class ValidationUniverseOrchestrator:
    """Closed execution: callers provide paths/locks, never module plans or evidence."""

    def validate_terraform(
        self, *, plan: TrustedValidationUniversePlan, workspace_root: Path,
        scan_root: Path, runtime: TrustedContainerRuntime,
        locked_identity: LockedContainerIdentity,
    ) -> ValidationUniverseResult:
        if locked_identity.tool not in {"opentofu", "terraform"}:
            raise DomainError("Terraform universe requires OpenTofu or Terraform")
        if not plan.ready:
            return ValidationUniverseResult(
                f"{locked_identity.tool}_validate", plan.role, plan.universe_sha256,
                Status.INCONCLUSIVE,
                TF_JSON_REASON if plan.unsupported_tf_json else "ARTIFACT_UNIVERSE_UNRESOLVED",
                False, (), _plan=plan, _trusted_context=_RESULT_CONTEXT,
            )
        if not plan.terraform_modules:
            return ValidationUniverseResult(
                f"{locked_identity.tool}_validate", plan.role, plan.universe_sha256,
                Status.INCONCLUSIVE, "EMPTY_REQUIRED_MODULE_UNIVERSE", False, (),
                _plan=plan, _trusted_context=_RESULT_CONTEXT,
            )
        registry = production_validator_registry()
        results = []
        revalidate_validation_universe_plan(plan, scan_root)
        for module in plan.terraform_modules:
            request = create_terraform_validation_request(
                workspace_root=workspace_root, scan_root=scan_root,
                files_eligible=tuple(item.file_path for item in module.files),
                container_runtime=runtime, locked_identity=locked_identity,
                role=plan.role,
            )
            results.append(registry.execute(f"{locked_identity.tool}_validate", request))
            revalidate_validation_universe_plan(plan, scan_root)
        return _aggregate_module_results(
            plan, f"{locked_identity.tool}_validate", tuple(results), advisory=False,
        )

    def validate_tflint(
        self, *, plan: TrustedValidationUniversePlan, workspace_root: Path,
        scan_root: Path, runtime: TrustedContainerRuntime,
        locked_identity: LockedContainerIdentity,
    ) -> ValidationUniverseResult:
        if locked_identity.tool != "tflint":
            raise DomainError("TFLint universe requires the TFLint lock")
        if not plan.ready or not plan.terraform_modules:
            return ValidationUniverseResult(
                "tflint_advisory", plan.role, plan.universe_sha256,
                Status.INCONCLUSIVE,
                TF_JSON_REASON if plan.unsupported_tf_json else "EMPTY_OR_UNRESOLVED_MODULE_UNIVERSE",
                True, (), _plan=plan, _trusted_context=_RESULT_CONTEXT,
            )
        registry = production_validator_registry()
        protected = load_protected_tflint_config()
        results = []
        revalidate_validation_universe_plan(plan, scan_root)
        for module in plan.terraform_modules:
            request = create_tflint_validation_request(
                workspace_root=workspace_root, scan_root=scan_root,
                files_eligible=tuple(item.file_path for item in module.files),
                container_runtime=runtime, locked_identity=locked_identity,
                protected_config=protected, role=plan.role,
            )
            results.append(registry.execute("tflint_advisory", request))
            revalidate_validation_universe_plan(plan, scan_root)
        return _aggregate_module_results(
            plan, "tflint_advisory", tuple(results), advisory=True,
        )

    def validate_kubernetes(
        self, *, plan: TrustedValidationUniversePlan, workspace_root: Path,
        scan_root: Path, runtime: TrustedContainerRuntime,
        locked_identity: LockedContainerIdentity,
        schema_identity: ProtectedKubernetesSchemaIdentity,
        protected_crd_schema: ProtectedKubernetesSchemaIdentity | None = None,
    ) -> ValidationUniverseResult:
        if not plan.ready or not plan.kubernetes_files:
            return ValidationUniverseResult(
                "kubeconform_validate", plan.role, plan.universe_sha256,
                Status.INCONCLUSIVE, "EMPTY_OR_UNRESOLVED_KUBERNETES_UNIVERSE",
                False, (), _plan=plan, _trusted_context=_RESULT_CONTEXT,
            )
        revalidate_validation_universe_plan(plan, scan_root)
        request = create_kubeconform_validation_request(
            workspace_root=workspace_root, scan_root=scan_root, role=plan.role,
            files_eligible=tuple(item.file_path for item in plan.kubernetes_files),
            container_runtime=runtime, locked_identity=locked_identity,
            schema_identity=schema_identity, protected_crd_schema=protected_crd_schema,
        )
        evidence = production_validator_registry().execute("kubeconform_validate", request)
        revalidate_validation_universe_plan(plan, scan_root)
        _validate_kubernetes_evidence(plan, evidence)
        return ValidationUniverseResult(
            "kubeconform_validate", plan.role, plan.universe_sha256,
            evidence.status,
            "COMPLETE_KUBERNETES_UNIVERSE_PASSED" if evidence.status is Status.PASS
            else "KUBERNETES_UNIVERSE_NON_PASS",
            False, (), evidence, _plan=plan, _trusted_context=_RESULT_CONTEXT,
        )
