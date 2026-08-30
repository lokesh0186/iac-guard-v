"""A8 scanner-neutral protected-universe conformance and adversarial tests."""
from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from iac_guard_v.enums import ArtifactKind
from iac_guard_v.models import BoundInputFile, DomainError, ExpectedResource
from iac_guard_v.scanner_core import (
    NativePropertyIdentity,
    NormalizedPropertyIdentity,
    PropertyCapability,
    ProtectedScanArtifact,
    ProtectedScanPlan,
    ProtectedPropertyTarget,
    RawPropertyObservation,
    RawScannerExecution,
    ScannerCapabilities,
    ScannerDescriptor,
    ScannerObservationResult,
    build_protected_scan_plan,
    execute_protected_scan,
    legacy_report_v1_property_capability,
    protect_scan_artifact,
)


SHA = "a" * 64


def _bound(root: Path, relative: str) -> BoundInputFile:
    path = root / relative
    metadata = path.stat()
    return BoundInputFile(
        relative, "regular_file", metadata.st_size,
        hashlib.sha256(path.read_bytes()).hexdigest(), metadata.st_dev, metadata.st_ino,
    )


def _fixture(tmp_path: Path, *, relationship: bool = False, advisory: bool = False):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "one.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: one}\n", encoding="utf-8"
    )
    (root / "two.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: two}\n", encoding="utf-8"
    )
    resources = (
        ExpectedResource(
            "one.yaml", "v1/ConfigMap/default/one", ArtifactKind.KUBERNETES_YAML,
            "ConfigMap.default.one",
        ),
        ExpectedResource(
            "two.yaml", "v1/ConfigMap/default/two", ArtifactKind.KUBERNETES_YAML,
            "ConfigMap.default.two",
        ),
    )
    artifact = protect_scan_artifact(
        root, "kubernetes_rendered_yaml",
        (_bound(root, "one.yaml"), _bound(root, "two.yaml")), resources,
    )
    capability = PropertyCapability.RELATIONSHIP if relationship else PropertyCapability.ATTRIBUTE
    descriptor = ScannerDescriptor(
        "synthetic", "1.0.0", "1" * 64, "2" * 64, "3" * 64,
        ScannerCapabilities(
            ("kubernetes_rendered_yaml",), (capability,), not advisory, advisory,
        ),
    )
    native = NativePropertyIdentity("synthetic", "SYNTH-1", "1.0.0", "3" * 64)
    target = ProtectedPropertyTarget(
        native, resources[0].resource_address, "one.yaml",
        resources[0].scanner_native_lookup, capability,
    )
    plan = build_protected_scan_plan(descriptor, artifact, (target,))
    return root, resources, descriptor, target, plan


class SyntheticAdapter:
    def __init__(self, descriptor: ScannerDescriptor, raw: RawScannerExecution):
        self._descriptor = descriptor
        self.raw = raw

    @property
    def descriptor(self) -> ScannerDescriptor:
        return self._descriptor

    def scan(self, plan):
        return self.raw


def _raw(plan, resources, target, *, result=ScannerObservationResult.PASS,
         evidence="4" * 64, relationship=""):
    observation = RawPropertyObservation(
        target.property_identity, target.protected_resource_identity, target.file_path,
        target.scanner_native_target_identity, result, evidence, relationship,
    )
    return RawScannerExecution(
        plan.descriptor.identity, plan.artifact.artifact_identity,
        tuple(item.file_path for item in plan.artifact.input_files),
        tuple(sorted(item.resource_address for item in resources)),
        (observation,), "5" * 64,
    )


def test_affirmative_exact_target_pass_is_accepted(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path)
    evidence = execute_protected_scan(
        plan, SyntheticAdapter(descriptor, _raw(plan, resources, target))
    )
    assert evidence.observations[0].result is ScannerObservationResult.PASS
    assert evidence.scanner_input_artifact_identity == plan.artifact.artifact_identity


def test_scanner_cannot_prune_protected_files(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path)
    raw = replace(_raw(plan, resources, target), consumed_input_paths=("one.yaml",))
    with pytest.raises(DomainError, match="complete protected file universe"):
        execute_protected_scan(plan, SyntheticAdapter(descriptor, raw))


def test_scanner_cannot_omit_protected_resource_coverage(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path)
    raw = replace(
        _raw(plan, resources, target),
        observed_resource_identities=(resources[0].resource_address,),
    )
    with pytest.raises(DomainError, match="complete protected resource coverage"):
        execute_protected_scan(plan, SyntheticAdapter(descriptor, raw))


def test_nondecisive_error_can_report_incomplete_observed_coverage(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path)
    raw = replace(
        _raw(
            plan, resources, target,
            result=ScannerObservationResult.ERROR, evidence="",
        ),
        observed_resource_identities=(),
    )
    evidence = execute_protected_scan(plan, SyntheticAdapter(descriptor, raw))
    assert evidence.observations[0].result is ScannerObservationResult.ERROR


def test_scanner_cannot_redefine_protected_target(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path)
    wrong = RawPropertyObservation(
        target.property_identity, resources[1].resource_address, "two.yaml",
        resources[1].scanner_native_lookup, ScannerObservationResult.FAIL, "4" * 64,
    )
    raw = replace(_raw(plan, resources, target), observations=(wrong,))
    with pytest.raises(DomainError, match="redefines"):
        execute_protected_scan(plan, SyntheticAdapter(descriptor, raw))


def test_scanner_cannot_invent_pass_from_absence(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path)
    raw = _raw(plan, resources, target, evidence="")
    with pytest.raises(DomainError, match="affirmative evidence"):
        execute_protected_scan(plan, SyntheticAdapter(descriptor, raw))


def test_scanner_cannot_supply_another_property_namespace(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path)
    foreign = NativePropertyIdentity("other", "SYNTH-1", "1.0.0", "3" * 64)
    wrong = RawPropertyObservation(
        foreign, target.protected_resource_identity, target.file_path,
        target.scanner_native_target_identity, ScannerObservationResult.FAIL, "4" * 64,
    )
    raw = replace(_raw(plan, resources, target), observations=(wrong,))
    with pytest.raises(DomainError, match="redefines"):
        execute_protected_scan(plan, SyntheticAdapter(descriptor, raw))


def test_relationship_requires_relationship_evidence(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path, relationship=True)
    with pytest.raises(DomainError, match="relationship evidence"):
        execute_protected_scan(
            plan, SyntheticAdapter(descriptor, _raw(plan, resources, target))
        )
    accepted = execute_protected_scan(
        plan, SyntheticAdapter(
            descriptor, _raw(plan, resources, target, relationship="6" * 64)
        ),
    )
    assert accepted.observations[0].relationship_evidence_digest == "6" * 64


def test_advisory_adapter_cannot_produce_authoritative_pass(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path, advisory=True)
    with pytest.raises(DomainError, match="advisory scanner"):
        execute_protected_scan(
            plan, SyntheticAdapter(descriptor, _raw(plan, resources, target))
        )


def test_not_evaluated_remains_typed_uncertainty(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path)
    evidence = execute_protected_scan(
        plan, SyntheticAdapter(descriptor, _raw(
            plan, resources, target, result=ScannerObservationResult.NOT_EVALUATED,
            evidence="",
        )),
    )
    assert evidence.observations[0].result is ScannerObservationResult.NOT_EVALUATED


def test_scanner_cannot_mutate_materialized_bytes(tmp_path: Path) -> None:
    root, resources, descriptor, target, plan = _fixture(tmp_path)

    class MutatingAdapter(SyntheticAdapter):
        def scan(self, plan):
            (root / "one.yaml").write_text("changed\n", encoding="utf-8")
            return self.raw

    with pytest.raises(DomainError, match="changed"):
        execute_protected_scan(
            plan, MutatingAdapter(descriptor, _raw(plan, resources, target))
        )


def test_property_identity_and_legacy_capability_are_explicit() -> None:
    normalized = NormalizedPropertyIdentity("iacgv", "container-hardening", "v1", SHA)
    assert normalized.canonical_dict()["mapping_digest"] == SHA
    native = NativePropertyIdentity("checkov", "CKV_K8S_20", "3.3.0", SHA)
    assert native.opaque_id == "checkov:CKV_K8S_20"
    assert legacy_report_v1_property_capability(
        "checkov", "CKV2_K8S_6"
    ) is PropertyCapability.RELATIONSHIP
    assert legacy_report_v1_property_capability(
        "other", "CKV2_K8S_6"
    ) is PropertyCapability.ATTRIBUTE


@pytest.mark.parametrize(
    "arguments",
    (
        ([], (PropertyCapability.ATTRIBUTE,), True, False),
        (("kubernetes", "kubernetes"), (PropertyCapability.ATTRIBUTE,), True, False),
        (("kubernetes",), [PropertyCapability.ATTRIBUTE], True, False),
        (("kubernetes",), ("ATTRIBUTE",), True, False),
        (("kubernetes",), (PropertyCapability.ATTRIBUTE,) * 2, True, False),
        (("kubernetes",), (PropertyCapability.ATTRIBUTE,), 1, False),
        (("kubernetes",), (PropertyCapability.ATTRIBUTE,), True, True),
    ),
)
def test_scanner_capability_shape_is_closed(arguments: tuple) -> None:
    with pytest.raises(DomainError):
        ScannerCapabilities(*arguments)


def test_protected_artifact_and_plan_reject_forged_shapes(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path)
    artifact = plan.artifact
    with pytest.raises(DomainError, match="pathlib"):
        replace(artifact, root="not-a-path")
    with pytest.raises(DomainError, match="input files"):
        replace(artifact, input_files=[])
    with pytest.raises(DomainError, match="cannot be empty"):
        replace(artifact, input_files=())
    with pytest.raises(DomainError, match="resources"):
        replace(artifact, expected_resources=[])
    with pytest.raises(DomainError, match="paths must be unique"):
        replace(artifact, input_files=(artifact.input_files[0],) * 2)
    with pytest.raises(DomainError, match="resources must be unique"):
        replace(artifact, expected_resources=(resources[0], resources[0]))
    with pytest.raises(DomainError, match="input manifest"):
        replace(artifact, input_manifest_digest=SHA)
    with pytest.raises(DomainError, match="resource inventory"):
        replace(artifact, resource_inventory_digest=SHA)
    with pytest.raises(DomainError, match="artifact identity"):
        replace(artifact, artifact_identity=SHA)

    with pytest.raises(DomainError, match="nonempty exact tuple"):
        replace(plan, targets=())
    with pytest.raises(DomainError, match="unique"):
        replace(plan, targets=(target, target))
    with pytest.raises(DomainError, match="plan identity"):
        replace(plan, plan_identity=SHA)
    unsupported = ScannerDescriptor(
        "synthetic", "1.0.0", "1" * 64, "2" * 64, "3" * 64,
        ScannerCapabilities(("terraform_source_hcl",),
                            (PropertyCapability.ATTRIBUTE,), True, False),
    )
    with pytest.raises(DomainError, match="artifact class"):
        ProtectedScanPlan(unsupported, artifact, (target,), SHA)
    foreign = replace(
        target,
        property_identity=NativePropertyIdentity(
            "other", "SYNTH-1", "1.0.0", "3" * 64
        ),
    )
    with pytest.raises(DomainError, match="disagrees"):
        build_protected_scan_plan(descriptor, artifact, (foreign,))
    container = replace(target, capability=PropertyCapability.CONTAINER)
    with pytest.raises(DomainError, match="required property capability"):
        build_protected_scan_plan(descriptor, artifact, (container,))


def test_raw_execution_and_adapter_protocol_are_closed(tmp_path: Path) -> None:
    _root, resources, descriptor, target, plan = _fixture(tmp_path)
    raw = _raw(plan, resources, target)
    observation = raw.observations[0]
    with pytest.raises(DomainError, match="result"):
        replace(observation, result="PASS")
    with pytest.raises(DomainError, match="native scanner reason"):
        replace(observation, native_reason=1)
    with pytest.raises(DomainError, match="paths must be an exact tuple"):
        replace(raw, consumed_input_paths=[])
    with pytest.raises(DomainError, match="paths must be unique"):
        replace(raw, consumed_input_paths=("one.yaml", "one.yaml"))
    with pytest.raises(DomainError, match="identities must be an exact tuple"):
        replace(raw, observed_resource_identities=[])
    with pytest.raises(DomainError, match="identities must be unique"):
        replace(raw, observed_resource_identities=(
            resources[0].resource_address, resources[0].resource_address,
        ))
    with pytest.raises(DomainError, match="raw observations"):
        replace(raw, observations=[])
    with pytest.raises(DomainError, match="diagnostics"):
        replace(raw, scanner_diagnostics=["bad"])
    with pytest.raises(DomainError, match="neutral protocol"):
        execute_protected_scan(plan, object())

    class WrongDescriptorAdapter:
        descriptor = object()

        def scan(self, _plan):
            return raw

    with pytest.raises(DomainError, match="descriptor must be exact"):
        execute_protected_scan(plan, WrongDescriptorAdapter())
    other_descriptor = replace(descriptor, scanner_configuration_digest="9" * 64)
    with pytest.raises(DomainError, match="disagrees with protected plan"):
        execute_protected_scan(
            plan, SyntheticAdapter(other_descriptor, raw)
        )
    with pytest.raises(DomainError, match="another descriptor"):
        execute_protected_scan(
            plan, SyntheticAdapter(descriptor, replace(raw, descriptor_identity=SHA))
        )
    with pytest.raises(DomainError, match="another protected artifact"):
        execute_protected_scan(
            plan, SyntheticAdapter(
                descriptor, replace(raw, scanner_input_artifact_identity=SHA)
            )
        )
    with pytest.raises(DomainError, match="outside the protected universe"):
        execute_protected_scan(
            plan, SyntheticAdapter(descriptor, replace(
                _raw(
                    plan, resources, target,
                    result=ScannerObservationResult.ERROR, evidence="",
                ),
                observed_resource_identities=("v1/ConfigMap/default/outside",),
            ))
        )
    with pytest.raises(DomainError, match="exactly one observation"):
        execute_protected_scan(
            plan, SyntheticAdapter(descriptor, replace(raw, observations=()))
        )
    assert execute_protected_scan(
        plan, SyntheticAdapter(descriptor, raw)
    ).canonical_dict()["descriptor"]["scanner_name"] == "synthetic"
