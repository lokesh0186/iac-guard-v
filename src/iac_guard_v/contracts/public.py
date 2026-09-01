"""Public, offline execution boundary for declared infrastructure contracts."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

from ..helm import HelmRenderSpec, materialize_helm
from ..models import DomainError
from ..native_properties.model import NativeArtifactClass
from ..native_properties.universe import ProtectedNativeUniverse, load_protected_native_universe
from .activation import evaluate_activation, requested_activation_paths
from .evaluator import evaluate_contract
from .helm_values import bind_helm_effective_values, direct_effective_values
from .model import ContractProvenance, InfrastructureContract
from .parser import _ContractLoader, load_contract
from .planner import ContractPlan, plan_contract
from .report import ContractReportV1


@dataclass(frozen=True, slots=True)
class ContractExecutionInput:
    contract_path: Path
    project_root: Path
    protected_root: Path | None = None
    helm_spec: HelmRenderSpec | None = None
    activation_values_path: Path | None = None
    requested_provenance: ContractProvenance | None = None
    source_commit: str = "WORKTREE"
    default_namespace: str = "default"

    def __post_init__(self) -> None:
        for name in ("contract_path", "project_root"):
            if not isinstance(getattr(self, name), Path):
                raise DomainError(f"contract execution {name} must be a Path")
        if (self.protected_root is None) == (self.helm_spec is None):
            raise DomainError("contract execution requires exactly one protected input mode")
        if self.protected_root is not None and not isinstance(self.protected_root, Path):
            raise DomainError("contract protected root must be a Path")
        if self.helm_spec is not None and type(self.helm_spec) is not HelmRenderSpec:
            raise DomainError("contract Helm input must be an exact HelmRenderSpec")
        if self.activation_values_path is not None and not isinstance(self.activation_values_path, Path):
            raise DomainError("contract activation values path must be a Path")
        if self.helm_spec is not None and self.activation_values_path is not None:
            raise DomainError("Helm contract activation must use protected effective Helm values")


@dataclass(frozen=True, slots=True)
class ContractRun:
    contract: InfrastructureContract
    universe: ProtectedNativeUniverse
    plan: ContractPlan
    report: ContractReportV1


@dataclass(frozen=True, slots=True)
class PreparedContract:
    contract: InfrastructureContract
    universe: ProtectedNativeUniverse
    plan: ContractPlan


def _read_direct_values(path: Path, project_root: Path) -> tuple[dict, str]:
    root = project_root.resolve(strict=True)
    if path.is_symlink():
        raise DomainError("activation values must be a regular non-symlink file")
    candidate = path.resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise DomainError("activation values escape the protected project root") from exc
    before = candidate.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise DomainError("activation values must be a regular non-symlink file")
    descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        content = bytearray()
        while chunk := os.read(
            descriptor, min(64 * 1024, 1024 * 1024 + 1 - len(content))
        ):
            content.extend(chunk)
            if len(content) > 1024 * 1024:
                break
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = bytes(content)
    if len(raw) > 1024 * 1024:
        raise DomainError("activation values exceed the 1 MiB limit")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise DomainError("activation values changed while reading")
    try:
        value = yaml.load(raw.decode("utf-8"), Loader=_ContractLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise DomainError("activation values are not strict UTF-8 YAML") from exc
    if type(value) is not dict:
        raise DomainError("activation values must be a mapping")
    return value, hashlib.sha256(raw).hexdigest()


@contextmanager
def prepare_contract_plan(value: ContractExecutionInput) -> Iterator[PreparedContract]:
    if type(value) is not ContractExecutionInput:
        raise DomainError("contract execution input must be exact")
    contract = load_contract(
        value.contract_path,
        project_root=value.project_root,
        requested_provenance=value.requested_provenance,
        source_commit=value.source_commit,
    )
    paths = requested_activation_paths(contract.when)
    if value.helm_spec is not None:
        with tempfile.TemporaryDirectory(prefix="iacgv-contract-helm-") as temporary:
            rendered = Path(temporary) / "protected-render"
            materialization = materialize_helm(value.helm_spec, rendered)
            activation_universe = bind_helm_effective_values(
                value.helm_spec, materialization, paths
            ) if paths else None
            universe = load_protected_native_universe(
                rendered, NativeArtifactClass.KUBERNETES_RENDERED,
                default_namespace=value.default_namespace,
            )
            activation = evaluate_activation(contract.when, activation_universe)
            plan = plan_contract(contract, universe, activation)
            yield PreparedContract(contract, universe, plan)
        return
    assert value.protected_root is not None
    universe = load_protected_native_universe(
        value.protected_root, NativeArtifactClass(contract.artifact_class),
        default_namespace=value.default_namespace,
    )
    activation_universe = None
    if paths and value.activation_values_path is not None:
        direct, identity = _read_direct_values(value.activation_values_path, value.project_root)
        activation_universe = direct_effective_values(
            direct, input_identity=identity, requested_paths=paths
        )
    activation = evaluate_activation(contract.when, activation_universe)
    plan = plan_contract(contract, universe, activation)
    yield PreparedContract(contract, universe, plan)


@contextmanager
def prepare_contract_run(value: ContractExecutionInput) -> Iterator[ContractRun]:
    with prepare_contract_plan(value) as prepared:
        clauses, result, reason = evaluate_contract(
            prepared.contract, prepared.universe, prepared.plan
        )
        yield ContractRun(
            prepared.contract, prepared.universe, prepared.plan,
            ContractReportV1.build(
                prepared.contract, prepared.universe, prepared.plan,
                clauses, result, reason,
            ),
        )


def plan_payload(run: ContractRun | PreparedContract) -> str:
    payload = {
        "contract": {
            "identity": run.contract.identity,
            "name": run.contract.name,
            "source": run.contract.source.canonical_dict(),
        },
        "protected_universe_identity": run.universe.identity,
        "plan": run.plan.canonical_dict(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


__all__ = [
    "ContractExecutionInput", "ContractRun", "PreparedContract", "plan_payload",
    "prepare_contract_plan", "prepare_contract_run",
]
