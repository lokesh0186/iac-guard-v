"""Candidate-acceptance evidence universes and scanner addressability.

The ordinary scanner run remains immutable evidence.  This module may explain a
resource-level PARTIAL result only when a protected check contract proves that every
missing standalone resource is not a primary scanner address and cannot affect any
selected property.  Files, bytes and every rendered resource remain governed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import InitVar, dataclass, field
from pathlib import Path

from .config import PublicAcceptanceProperty
from .engine import TrustedScanPlan
from .enums import ArtifactKind, Status
from .graph_evidence import (
    _selector_matches,
    _workload_labels,
    build_graph_evidence_context,
)
from .models import (
    CheckEvaluation,
    DomainError,
    ExpectedResource,
    GraphParticipant,
    ScannerRun,
    canonical_identifier,
    require_trusted_scanner_run,
)


EVIDENCE_UNIVERSES_CONTRACT = "candidate-evidence-universes-v1"
_TRUSTED_UNIVERSE_CONTEXT = object()
_RESOURCE_CLASSIFICATIONS = frozenset({
    "SCANNER_PRIMARY_ADDRESSABLE",
    "TARGET_RELEVANT_GRAPH_PARTICIPANT",
    "GOVERNED_NON_TARGET_SCANNER_UNADDRESSED",
    "CONSERVATIVE_SCANNER_ADDRESSABLE",
})


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


def _property_selector(property_: PublicAcceptanceProperty) -> dict:
    return {
        "rule_id": property_.rule_id,
        "resource_address": property_.resource_address,
        "file_path": property_.file_path,
        "artifact_kind": property_.artifact_kind.value,
    }


def _resource_for_property(
    plan: TrustedScanPlan, property_: PublicAcceptanceProperty
) -> ExpectedResource | None:
    resources = tuple(
        item for item in plan.resources
        if item.resource_address == property_.resource_address
        and (not property_.file_path or item.file_path == property_.file_path)
        and (
            property_.artifact_kind is ArtifactKind.UNKNOWN
            or item.artifact_kind is property_.artifact_kind
        )
    )
    return resources[0] if len(resources) == 1 else None


@dataclass(frozen=True, slots=True)
class ResourceAddressabilityEvidence:
    resource: ExpectedResource
    classification: str
    reason_code: str
    rule_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.resource) is not ExpectedResource:
            raise DomainError("addressability resource must be independently governed")
        if self.classification not in _RESOURCE_CLASSIFICATIONS:
            raise DomainError("resource addressability classification is unsupported")
        object.__setattr__(
            self, "reason_code",
            canonical_identifier(self.reason_code, "addressability reason code"),
        )
        if type(self.rule_ids) is not tuple or not self.rule_ids:
            raise DomainError("addressability evidence requires selected rule ids")
        rules = tuple(sorted(canonical_identifier(item, "rule id") for item in self.rule_ids))
        if len(rules) != len(set(rules)):
            raise DomainError("addressability evidence contains duplicate rules")
        object.__setattr__(self, "rule_ids", rules)

    def canonical_dict(self) -> dict:
        return {
            "resource": self.resource.canonical_dict(),
            "classification": self.classification,
            "reason_code": self.reason_code,
            "rule_ids": list(self.rule_ids),
        }


@dataclass(frozen=True, slots=True)
class StructuralIrrelevanceEvidence:
    target: ExpectedResource
    resource: ExpectedResource
    reason_code: str
    selector_sha256: str
    target_labels_sha256: str

    def __post_init__(self) -> None:
        if type(self.target) is not ExpectedResource or type(self.resource) is not ExpectedResource:
            raise DomainError("irrelevance evidence must bind governed resources")
        if self.reason_code not in {"NAMESPACE_DISJOINT", "SELECTOR_DISJOINT"}:
            raise DomainError("structural irrelevance reason is unsupported")
        for name in ("selector_sha256", "target_labels_sha256"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(
                char not in "0123456789abcdef" for char in value
            ):
                raise DomainError(f"{name} must be a lowercase SHA-256")

    def canonical_dict(self) -> dict:
        return {
            "target": self.target.canonical_dict(),
            "resource": self.resource.canonical_dict(),
            "reason_code": self.reason_code,
            "selector_sha256": self.selector_sha256,
            "target_labels_sha256": self.target_labels_sha256,
        }


@dataclass(frozen=True, slots=True)
class TargetRelevantEvidenceUniverse:
    selector: dict
    primary: ExpectedResource | None
    participants: tuple[ExpectedResource, ...]
    irrelevant_relationship_resources: tuple[StructuralIrrelevanceEvidence, ...]
    relationship_resource_count: int
    unresolved_relationship_resource_count: int
    policy_definition_sha256: str
    query_identity_sha256: str
    status: Status
    reason_code: str

    def __post_init__(self) -> None:
        if type(self.selector) is not dict or set(self.selector) != {
            "rule_id", "resource_address", "file_path", "artifact_kind"
        }:
            raise DomainError("target-relevant universe selector is invalid")
        object.__setattr__(self, "selector", dict(self.selector))
        if self.primary is not None and type(self.primary) is not ExpectedResource:
            raise DomainError("target-relevant primary must be governed")
        if type(self.participants) is not tuple or any(
            type(item) is not ExpectedResource for item in self.participants
        ):
            raise DomainError("target-relevant participants must be governed")
        participant_keys = [item.canonical_key for item in self.participants]
        if len(participant_keys) != len(set(participant_keys)):
            raise DomainError("target-relevant participants are duplicated")
        object.__setattr__(
            self, "participants", tuple(sorted(self.participants, key=lambda item: item.canonical_key))
        )
        if type(self.irrelevant_relationship_resources) is not tuple or any(
            type(item) is not StructuralIrrelevanceEvidence
            for item in self.irrelevant_relationship_resources
        ):
            raise DomainError("target irrelevance evidence must be exact records")
        irrelevant_keys = [
            item.resource.canonical_key for item in self.irrelevant_relationship_resources
        ]
        if len(irrelevant_keys) != len(set(irrelevant_keys)):
            raise DomainError("target irrelevance evidence is duplicated")
        object.__setattr__(
            self,
            "irrelevant_relationship_resources",
            tuple(sorted(
                self.irrelevant_relationship_resources,
                key=lambda item: item.resource.canonical_key,
            )),
        )
        if type(self.relationship_resource_count) is not int or self.relationship_resource_count < 0:
            raise DomainError("relationship resource count must be nonnegative")
        if (
            type(self.unresolved_relationship_resource_count) is not int
            or self.unresolved_relationship_resource_count < 0
        ):
            raise DomainError("unresolved relationship resource count must be nonnegative")
        if self.relationship_resource_count != (
            len(self.participants)
            + len(self.irrelevant_relationship_resources)
            + self.unresolved_relationship_resource_count
        ):
            raise DomainError("target relationship accounting is incomplete")
        for name in ("policy_definition_sha256", "query_identity_sha256"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(
                char not in "0123456789abcdef" for char in value
            ):
                raise DomainError(f"{name} must be a lowercase SHA-256")
        if type(self.status) is not Status:
            raise DomainError("target-relevant universe status must be closed")
        object.__setattr__(
            self, "reason_code", canonical_identifier(self.reason_code, "target universe reason"),
        )

    def canonical_dict(self) -> dict:
        return {
            "selector": dict(self.selector),
            "primary": None if self.primary is None else self.primary.canonical_dict(),
            "participants": [item.canonical_dict() for item in self.participants],
            "irrelevant_relationship_resources": [
                item.canonical_dict() for item in self.irrelevant_relationship_resources
            ],
            "relationship_resource_count": self.relationship_resource_count,
            "unresolved_relationship_resource_count": (
                self.unresolved_relationship_resource_count
            ),
            "policy_definition_sha256": self.policy_definition_sha256,
            "query_identity_sha256": self.query_identity_sha256,
            "status": self.status.value,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class CandidateEvidenceUniverses:
    governed_resources: tuple[ExpectedResource, ...]
    addressability: tuple[ResourceAddressabilityEvidence, ...]
    targets: tuple[TargetRelevantEvidenceUniverse, ...]
    missing_standalone_evaluations: tuple[ExpectedResource, ...]
    status: Status
    reason_code: str
    raw_scanner_status_accepted: bool
    _trusted_context: InitVar[object] = None
    _trusted: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self, _trusted_context: object) -> None:
        if type(self.governed_resources) is not tuple or any(
            type(item) is not ExpectedResource for item in self.governed_resources
        ):
            raise DomainError("governed resource universe must be exact")
        governed_keys = [item.canonical_key for item in self.governed_resources]
        if len(governed_keys) != len(set(governed_keys)):
            raise DomainError("governed resource universe is duplicated")
        object.__setattr__(
            self, "governed_resources",
            tuple(sorted(self.governed_resources, key=lambda item: item.canonical_key)),
        )
        if type(self.addressability) is not tuple or any(
            type(item) is not ResourceAddressabilityEvidence for item in self.addressability
        ):
            raise DomainError("scanner-addressable universe must be exact")
        if {item.resource.canonical_key for item in self.addressability} != set(governed_keys):
            raise DomainError("scanner-addressable universe must classify every governed resource")
        object.__setattr__(
            self, "addressability",
            tuple(sorted(self.addressability, key=lambda item: item.resource.canonical_key)),
        )
        if type(self.targets) is not tuple or not self.targets or any(
            type(item) is not TargetRelevantEvidenceUniverse for item in self.targets
        ):
            raise DomainError("target-relevant evidence universe must be nonempty")
        if type(self.missing_standalone_evaluations) is not tuple or any(
            type(item) is not ExpectedResource for item in self.missing_standalone_evaluations
        ):
            raise DomainError("missing standalone evaluations must bind governed resources")
        missing_keys = [item.canonical_key for item in self.missing_standalone_evaluations]
        if len(missing_keys) != len(set(missing_keys)) or not set(missing_keys) <= set(governed_keys):
            raise DomainError("missing standalone evaluation identity is invalid")
        object.__setattr__(
            self, "missing_standalone_evaluations",
            tuple(sorted(
                self.missing_standalone_evaluations, key=lambda item: item.canonical_key
            )),
        )
        if type(self.status) is not Status:
            raise DomainError("candidate evidence universe status must be closed")
        object.__setattr__(
            self, "reason_code", canonical_identifier(self.reason_code, "universe reason code"),
        )
        if type(self.raw_scanner_status_accepted) is not bool:
            raise DomainError("raw scanner status acceptance must be Boolean")
        if self.status is Status.PASS and any(item.status is not Status.PASS for item in self.targets):
            raise DomainError("complete candidate evidence cannot contain an incomplete target")
        if _trusted_context is not _TRUSTED_UNIVERSE_CONTEXT:
            raise DomainError("candidate evidence universes require protected derivation")
        object.__setattr__(self, "_trusted", True)

    def target_for(self, property_: PublicAcceptanceProperty) -> TargetRelevantEvidenceUniverse:
        selector = _property_selector(property_)
        matches = tuple(item for item in self.targets if item.selector == selector)
        if len(matches) != 1:
            raise DomainError("candidate property has no unique target-relevant universe")
        return matches[0]

    def canonical_dict(self) -> dict:
        governed = [item.canonical_dict() for item in self.governed_resources]
        accounting = [item.canonical_dict() for item in self.addressability]
        missing = [item.canonical_dict() for item in self.missing_standalone_evaluations]
        primary = [
            item["resource"] for item in accounting
            if item["classification"] in {
                "SCANNER_PRIMARY_ADDRESSABLE", "CONSERVATIVE_SCANNER_ADDRESSABLE"
            }
        ]
        relationship = [
            item["resource"] for item in accounting
            if item["classification"] == "TARGET_RELEVANT_GRAPH_PARTICIPANT"
        ]
        unaddressed = [
            item["resource"] for item in accounting
            if item["classification"] == "GOVERNED_NON_TARGET_SCANNER_UNADDRESSED"
        ]
        return {
            "contract": EVIDENCE_UNIVERSES_CONTRACT,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "raw_scanner_status_accepted": self.raw_scanner_status_accepted,
            "governed_resource_universe": {
                "count": len(governed), "sha256": _digest(governed), "resources": governed,
            },
            "scanner_addressable_universe": {
                "resource_accounting": accounting,
                "primary_count": len(primary),
                "primary_sha256": _digest(primary),
                "relationship_participant_count": len(relationship),
                "relationship_participant_sha256": _digest(relationship),
                "governed_unaddressed_count": len(unaddressed),
                "governed_unaddressed_sha256": _digest(unaddressed),
                "missing_standalone_evaluation_count": len(missing),
                "missing_standalone_evaluations": missing,
                "missing_standalone_evaluations_sha256": _digest(missing),
            },
            "target_relevant_evidence_universe": [
                item.canonical_dict() for item in self.targets
            ],
        }


def _base_file_health(plan: TrustedScanPlan, run: ScannerRun) -> bool:
    coverage = run.coverage
    return (
        run.ruleset_integrity is Status.PASS
        and coverage.files_eligible == len(plan.files)
        and coverage.files_discovered == len(plan.files)
        and coverage.files_parsed == len(plan.files)
        and coverage.files_failed == 0
        and coverage.checks_failed_to_execute == 0
        and coverage.parse_errors == 0
        and run.resource_coverage.resources_expected == len(plan.resources)
        and run.resource_coverage.unexpected_resources_observed == 0
        and {item.file_path for item in run.input_files}
        == {item.file_path for item in plan.files}
    )


def _conservative_complete(plan: TrustedScanPlan, run: ScannerRun) -> bool:
    return (
        _base_file_health(plan, run)
        and run.status is Status.PASS
        and run.resource_coverage.expected_resources_missing == 0
    )


def build_conservative_evidence_universes(
    plan: TrustedScanPlan,
    run: ScannerRun,
    properties: tuple[PublicAcceptanceProperty, ...],
) -> CandidateEvidenceUniverses:
    """Preserve pre-a5 full-resource coverage for unsupported check contracts."""
    require_trusted_scanner_run(run)
    rules = tuple(sorted({item.rule_id for item in properties}))
    complete = _conservative_complete(plan, run)
    targets = tuple(
        TargetRelevantEvidenceUniverse(
            _property_selector(item),
            _resource_for_property(plan, item),
            (),
            (),
            0,
            0,
            "0" * 64,
            "0" * 64,
            Status.PASS if complete and _resource_for_property(plan, item) is not None
            else Status.INCONCLUSIVE,
            "CONSERVATIVE_COMPLETE_RESOURCE_EVIDENCE" if complete
            else "CONSERVATIVE_RESOURCE_EVIDENCE_INCOMPLETE",
        )
        for item in properties
    )
    complete = complete and all(item.status is Status.PASS for item in targets)
    return CandidateEvidenceUniverses(
        tuple(plan.resources),
        tuple(
            ResourceAddressabilityEvidence(
                item,
                "CONSERVATIVE_SCANNER_ADDRESSABLE",
                "UNMODELED_CHECK_RETAINS_FULL_COVERAGE",
                rules,
            )
            for item in plan.resources
        ),
        targets,
        (),
        Status.PASS if complete else Status.INCONCLUSIVE,
        "CONSERVATIVE_SCANNER_EVIDENCE_COMPLETE" if complete
        else "CONSERVATIVE_SCANNER_EVIDENCE_INCOMPLETE",
        False,
        _TRUSTED_UNIVERSE_CONTEXT,
    )


def _evaluation_for(
    run: ScannerRun, rule_id: str, resource: ExpectedResource
) -> tuple[CheckEvaluation, ...]:
    return tuple(
        item for item in run.evaluations
        if item.rule_id == rule_id
        and item.file_path == resource.file_path
        and item.resource_address in {
            resource.resource_address, resource.scanner_native_lookup,
        }
    )


def _observed_by_scanner(run: ScannerRun, resource: ExpectedResource) -> bool:
    if any(
        item.file_path == resource.file_path
        and item.resource_address in {
            resource.resource_address, resource.scanner_native_lookup,
        }
        for item in run.evaluations
    ):
        return True
    return any(
        participant.file_path == resource.file_path
        and participant.resource_address == resource.resource_address
        for evaluation in run.evaluations
        if evaluation.graph_evidence is not None
        for participant in evaluation.graph_evidence.participants
    )


def build_candidate_evidence_universes(
    *,
    plan: TrustedScanPlan,
    run: ScannerRun,
    properties: tuple[PublicAcceptanceProperty, ...],
    executable: Path,
) -> CandidateEvidenceUniverses:
    """Derive acceptance completeness from the selected protected check contract."""
    require_trusted_scanner_run(run)
    if type(properties) is not tuple or not properties:
        raise DomainError("candidate evidence requires selected properties")
    if {item.rule_id for item in properties} != {"CKV2_K8S_6"} or set(
        plan.request.frameworks
    ) != {"kubernetes"}:
        return build_conservative_evidence_universes(plan, run, properties)

    try:
        context = build_graph_evidence_context(
            executable=executable,
            scan_root=plan.request.scan_root,
            frameworks=plan.request.frameworks,
            expected_resources=plan.resources,
            input_files=plan.request.eligible_file_evidence,
            source_snapshot_sha256=plan.request.source_snapshot_sha256,
            policy_inventory_sha256=run.policy_inventory_digest,
        )
    except (DomainError, OSError):
        return build_conservative_evidence_universes(plan, run, properties)
    query_matches = tuple(
        query for framework, rule, query in context.queries
        if framework == "kubernetes" and rule == "CKV2_K8S_6"
    )
    if len(query_matches) != 1 or query_matches[0] is None:
        return build_conservative_evidence_universes(plan, run, properties)
    query = query_matches[0]
    if (
        query.primary_types != ("Pod",)
        or query.connected_types != ("NetworkPolicy",)
        or query.attribute_requirements
    ):
        return build_conservative_evidence_universes(plan, run, properties)

    resources_by_key = {
        (item.file_path, item.resource_address): item for item in plan.resources
    }
    primary_nodes = tuple(
        item for item in context.nodes if set(item.graph_types) & set(query.primary_types)
    )
    relationship_nodes = tuple(
        item for item in context.nodes if set(item.graph_types) & set(query.connected_types)
    )
    try:
        primary_resources = {
            resources_by_key[(item.participant.file_path, item.participant.resource_address)]
            for item in primary_nodes
        }
        relationship_resources = {
            resources_by_key[(item.participant.file_path, item.participant.resource_address)]
            for item in relationship_nodes
        }
    except KeyError:
        return build_conservative_evidence_universes(plan, run, properties)

    target_universes = []
    globally_relevant: set[ExpectedResource] = set()
    globally_unresolved: set[ExpectedResource] = set()
    all_targets_complete = True
    edges = {item.canonical_key: item for item in context.edges}
    ambiguous = set(context.ambiguous_relations)
    for property_ in properties:
        selector = _property_selector(property_)
        target = _resource_for_property(plan, property_)
        target_nodes = tuple(
            item for item in primary_nodes
            if target is not None
            and item.participant.file_path == target.file_path
            and item.participant.resource_address == target.resource_address
        )
        if target is None or len(target_nodes) != 1:
            all_targets_complete = False
            globally_unresolved.update(relationship_resources)
            target_universes.append(TargetRelevantEvidenceUniverse(
                selector, target, (), (), len(relationship_nodes), len(relationship_nodes),
                query.policy_definition_sha256, query.query_identity_sha256,
                Status.INCONCLUSIVE, "TARGET_GRAPH_IDENTITY_INCOMPLETE",
            ))
            continue
        target_node = target_nodes[0]
        target_labels = _workload_labels(
            target_node.attributes, target_node.participant.resource_type
        )
        target_label_digest = _digest(target_labels)
        target_namespace = target_node.attributes.get("metadata", {}).get(
            "namespace", "default"
        ) or "default"
        participants = []
        proofs = []
        target_complete = True
        expected_edges = []
        for policy_node in relationship_nodes:
            policy_resource = resources_by_key[
                (policy_node.participant.file_path, policy_node.participant.resource_address)
            ]
            relation_pair = (
                target_node.participant.resource_address,
                policy_node.participant.resource_address,
            )
            reverse_pair = tuple(reversed(relation_pair))
            if relation_pair in ambiguous or reverse_pair in ambiguous:
                target_complete = False
                globally_unresolved.add(policy_resource)
                continue
            matching_edges = tuple(
                edge for edge in edges.values()
                if {
                    edge.source.canonical_key, edge.target.canonical_key
                } == {
                    target_node.participant.canonical_key,
                    policy_node.participant.canonical_key,
                }
            )
            if matching_edges:
                participants.append(policy_resource)
                globally_relevant.add(policy_resource)
                expected_edges.extend(matching_edges)
                continue
            metadata = policy_node.attributes.get("metadata", {})
            policy_namespace = metadata.get("namespace", "default") or "default"
            selector_value = policy_node.attributes.get("spec", {}).get("podSelector")
            selector_digest = _digest(selector_value)
            if policy_namespace != target_namespace:
                reason = "NAMESPACE_DISJOINT"
            else:
                matches = _selector_matches(selector_value, target_labels)
                if matches is None or matches:
                    target_complete = False
                    globally_unresolved.add(policy_resource)
                    continue
                reason = "SELECTOR_DISJOINT"
            proofs.append(StructuralIrrelevanceEvidence(
                target, policy_resource, reason, selector_digest, target_label_digest
            ))

        evaluations = _evaluation_for(run, property_.rule_id, target)
        if len(evaluations) != 1 or evaluations[0].graph_evidence is None:
            target_complete = False
        else:
            graph = evaluations[0].graph_evidence
            expected_participants = {
                (target.file_path, target.resource_address),
                *((item.file_path, item.resource_address) for item in participants),
            }
            actual_participants = {
                (item.file_path, item.resource_address) for item in graph.participants
            }
            if (
                graph.status is not Status.PASS
                or graph.policy_definition_sha256 != query.policy_definition_sha256
                or graph.query_identity_sha256 != query.query_identity_sha256
                or actual_participants != expected_participants
                or {item.canonical_key for item in graph.edges}
                != {item.canonical_key for item in expected_edges}
            ):
                target_complete = False
        all_targets_complete = all_targets_complete and target_complete
        unresolved_count = len(relationship_nodes) - len(participants) - len(proofs)
        target_universes.append(TargetRelevantEvidenceUniverse(
            selector,
            target,
            tuple(participants),
            tuple(proofs),
            len(relationship_nodes),
            unresolved_count,
            query.policy_definition_sha256,
            query.query_identity_sha256,
            Status.PASS if target_complete else Status.INCONCLUSIVE,
            "TARGET_RELEVANT_GRAPH_EVIDENCE_COMPLETE" if target_complete
            else "TARGET_RELEVANT_GRAPH_EVIDENCE_INCOMPLETE",
        ))

    classifications = []
    rules = ("CKV2_K8S_6",)
    for resource in plan.resources:
        if resource in primary_resources:
            classification = "SCANNER_PRIMARY_ADDRESSABLE"
            reason = "CHECK_PRIMARY_RESOURCE_TYPE"
        elif resource in globally_relevant or resource in globally_unresolved:
            classification = "TARGET_RELEVANT_GRAPH_PARTICIPANT"
            reason = (
                "SELECTED_GRAPH_RELATIONSHIP_PARTICIPANT"
                if resource in globally_relevant
                else "GRAPH_RELATIONSHIP_RELEVANCE_UNRESOLVED"
            )
        else:
            classification = "GOVERNED_NON_TARGET_SCANNER_UNADDRESSED"
            reason = (
                "STRUCTURALLY_IRRELEVANT_TO_SELECTED_TARGETS"
                if resource in relationship_resources
                else "CHECK_SEMANTICS_EXCLUDES_RESOURCE_TYPE"
            )
        classifications.append(ResourceAddressabilityEvidence(
            resource, classification, reason, rules
        ))

    missing = tuple(
        item for item in plan.resources if not _observed_by_scanner(run, item)
    )
    by_resource = {item.resource.canonical_key: item for item in classifications}
    allowed_missing = all(
        by_resource[item.canonical_key].classification
        == "GOVERNED_NON_TARGET_SCANNER_UNADDRESSED"
        for item in missing
    )
    primary_complete = all(
        len(_evaluation_for(run, "CKV2_K8S_6", item)) == 1
        for item in primary_resources
    )
    missing_count_agrees = (
        len(missing) == run.resource_coverage.expected_resources_missing
    )
    expected_diagnostics = {
        "COVERAGE_MISMATCH",
        *(f"missing evaluation resource: {item.file_path}@{item.resource_address}" for item in missing),
    }
    raw_status_accepted = (
        run.status is Status.PASS and not missing
    ) or (
        run.status is Status.PARTIAL
        and bool(missing)
        and set(run.diagnostics) == expected_diagnostics
    )
    complete = (
        _base_file_health(plan, run)
        and raw_status_accepted
        and allowed_missing
        and missing_count_agrees
        and primary_complete
        and all_targets_complete
    )
    return CandidateEvidenceUniverses(
        tuple(plan.resources),
        tuple(classifications),
        tuple(target_universes),
        missing,
        Status.PASS if complete else Status.INCONCLUSIVE,
        "TARGET_RELEVANT_SCANNER_EVIDENCE_COMPLETE" if complete
        else "TARGET_RELEVANT_SCANNER_EVIDENCE_INCOMPLETE",
        run.status is Status.PARTIAL and complete,
        _TRUSTED_UNIVERSE_CONTEXT,
    )


__all__ = [
    "CandidateEvidenceUniverses",
    "EVIDENCE_UNIVERSES_CONTRACT",
    "ResourceAddressabilityEvidence",
    "StructuralIrrelevanceEvidence",
    "TargetRelevantEvidenceUniverse",
    "build_candidate_evidence_universes",
    "build_conservative_evidence_universes",
]
