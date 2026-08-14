"""Canonical report-v1 and projections derived only from canonical evidence."""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

import jsonschema

from .diffing import diff_findings
from .enums import (
    ArtifactKind, DeltaClass, SEVERITY_ORDER, Severity, Status, Verdict,
)
from .engine import VerificationResult, require_trusted_verification_result
from .models import DomainError, Finding, FindingLocation, TargetIdentity
from .policy import PolicyResult, require_trusted_policy_result


@dataclass(frozen=True, slots=True)
class ExecutionIsolationEvidence:
    mode: str
    hostile_input_support: bool
    network_isolation_state: str
    filesystem_isolation_state: str
    scanner_environment_integrity_state: str

    def __post_init__(self) -> None:
        if self.mode not in {"hardened-container", "reduced-isolation"}:
            raise DomainError("execution isolation mode is unsupported")
        if type(self.hostile_input_support) is not bool:
            raise DomainError("hostile_input_support must be an exact bool")
        for name in (
            "network_isolation_state", "filesystem_isolation_state",
            "scanner_environment_integrity_state",
        ):
            if getattr(self, name) not in {"PASS", "FAIL", "INCONCLUSIVE", "UNSUPPORTED"}:
                raise DomainError(f"execution isolation {name} is unsupported")
        if self.mode == "reduced-isolation" and self.hostile_input_support:
            raise DomainError("reduced-isolation cannot claim hostile-input support")

    @classmethod
    def reduced_verified(cls) -> "ExecutionIsolationEvidence":
        return cls("reduced-isolation", False, "UNSUPPORTED", "UNSUPPORTED", "PASS")

    def canonical_dict(self) -> dict:
        return {
            "mode": self.mode,
            "hostile_input_support": self.hostile_input_support,
            "network_isolation_state": self.network_isolation_state,
            "filesystem_isolation_state": self.filesystem_isolation_state,
            "scanner_environment_integrity_state": self.scanner_environment_integrity_state,
        }


def _schema() -> dict:
    path = files("iac_guard_v").joinpath("schemas/report-v1.schema.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_report_payload(payload: dict, *, allow_private_test_registry: bool) -> None:
    try:
        jsonschema.Draft202012Validator(_schema(), format_checker=jsonschema.FormatChecker()).validate(payload)
    except jsonschema.ValidationError as exc:
        raise DomainError(f"report-v1 contract violation: {exc.message}") from exc
    if payload["result_kind"] == "verification":
        policy = payload["policy"]
        if (payload["verdict"], payload["exit_code"]) != (
            policy["verdict"], policy["exit_code"]
        ):
            raise DomainError("report-v1 top-level and policy verdict/exit disagree")
        _validate_verification_semantics(
            payload, allow_private_test_registry=allow_private_test_registry
        )


def validate_report_payload(payload: dict) -> None:
    """Validate public report-v1 evidence; private test registries are forbidden."""
    _validate_report_payload(payload, allow_private_test_registry=False)


def _validate_test_report_payload(payload: dict) -> None:
    """Private unit-test validator for factory-proven synthetic gate evidence."""
    _validate_report_payload(payload, allow_private_test_registry=True)


_UNCERTAIN_STATUSES = frozenset({
    "ERROR", "TIMEOUT", "UNSUPPORTED", "SKIPPED", "PARTIAL", "INCONCLUSIVE",
})
_INCONCLUSIVE_OUTCOMES = frozenset({
    "OUT_OF_SCOPE", "RULE_OR_SCANNER_DRIFT", "SCANNER_ERROR", "INCONCLUSIVE",
})
_ENGINE_EVENT_CLASSES = frozenset({
    "RULE_SUBSTITUTED", "COVERAGE_DECREASED", "DIAGNOSTIC_ADDED",
    "DESTRUCTIVE_CHANGE", "POLICY_DRIFT",
})
_EXCEPTION_ELIGIBLE_OUTCOMES = frozenset({
    "SUPPRESSED", "RESOURCE_DELETED", "FILE_DELETED_OR_RENAMED",
})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PASS_BUCKETS = {
    "passed_checks": "PASSED",
    "failed_checks": "FAILED",
    "skipped_checks": "SKIPPED",
}
_SCANNER_FAILURE_REASONS = frozenset({
    "PROCESS_ERROR", "EMPTY_OUTPUT", "MALFORMED_JSON", "TRUNCATED_OUTPUT",
    "UNEXPECTED_TOP_LEVEL", "EXIT_CODE_OUTSIDE_CONTRACT", "DEADLINE_EXCEEDED",
    "KILLED_PROCESS", "PARTIAL_SCAN", "ZERO_FILES_DISCOVERED",
    "UNSUPPORTED_VERSION", "VERSION_MISMATCH", "VERSION_PROBE_FAILED",
    "NO_RESULTS_STRUCTURE", "INVALID_RESULTS_STRUCTURE", "COVERAGE_MISMATCH",
    "FRAMEWORK_MISMATCH", "MISSING_RESOURCE_IDENTITY", "RAW_OUTPUT_MISSING",
    "OUTPUT_CLEANUP_FAILED", "INPUT_CHANGED_DURING_SCAN_PREPARATION",
    "SCAN_VIEW_PREPARATION_FAILED", "OUTPUT_DIRECTORY_INTEGRITY_FAILED",
    "UNKNOWN_RESULT_BUCKET", "AGGREGATE_ONLY_EVIDENCE",
    "SCANNER_ENVIRONMENT_MISMATCH", "POLICY_INVENTORY_MISMATCH",
    "RESOURCE_INVENTORY_MISSING", "RESOURCE_COUNT_MISMATCH",
    "CONTRADICTORY_EVALUATION_EVIDENCE", "EMPTY_ELIGIBLE_SCOPE",
    "INPUT_FILE_COUNT_LIMIT_EXCEEDED", "INPUT_FILE_SIZE_LIMIT_EXCEEDED",
    "INPUT_TOTAL_SIZE_LIMIT_EXCEEDED", "JSON_DEPTH_EXCEEDED",
})
_SUPPORTED_SUFFIXES = frozenset({".tf", ".yaml", ".yml", ".json"})
_GOVERNED_FILE_NAMES = frozenset({
    ".iac-guard.yml", ".iac-guard.yaml", ".iac-guard.json",
    ".checkov.yml", ".checkov.yaml", ".checkovignore",
    ".trivyignore", ".trivy.yaml", ".trivy.yml", "trivy.yaml", "trivy.yml",
    ".tflint.hcl", ".tflint.json", ".kics.yaml", ".kics.yml", ".kics-config",
    ".terraformrc", "terraform.rc", ".terraform.lock.hcl",
    "iac-guard.lock.yml", "exceptions.json", "control-catalog.json",
    "oracle-policy.json", "severity-policy.json", "gate-policy.json",
})
_GOVERNED_DIRECTORY_NAMES = frozenset({
    ".iac-guard", ".checkov", "checkov_custom_checks", "custom_checks",
    "oracle-policy", "control-catalog",
})


def _semantic_error(detail: str) -> None:
    raise DomainError(f"report-v1 semantic violation: {detail}")


def _binding_key(value: dict | None) -> str:
    if type(value) is not dict:
        return ""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _canonical_json_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


def _unique(items: list, key, label: str) -> dict:
    keys = [key(item) for item in items]
    duplicates = sorted(
        (value for value, count in Counter(keys).items() if count > 1),
        key=str,
    )
    if duplicates:
        _semantic_error(f"duplicate authoritative {label}: {duplicates}")
    return dict(zip(keys, items, strict=True))


def _require_sha(value: object, label: str, *, allow_empty: bool = False) -> None:
    if allow_empty and value == "":
        return
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _semantic_error(f"{label} is not a canonical SHA-256")


def _validate_config_identity(config: dict) -> None:
    payload = {
        name: config[name]
        for name in (
            "role_snapshots", "role_subpaths", "role_repository_identities",
            "frameworks", "scanner_identity", "required_gates",
            "severity_floor", "fail_on_location_change", "invocation_settings",
            "governed_config", "source_identity", "source_provenance",
            "policy_source_authorization", "gate_registry_identity",
            "gate_implementations",
        )
    }
    if _canonical_json_digest(payload) != config["config_sha256"]:
        _semantic_error("protected configuration identity is not canonical")
    scanner = config["scanner_identity"]
    for name in (
        "launcher_digest", "scanner_environment_digest", "policy_inventory_digest",
    ):
        _require_sha(scanner[name], f"protected scanner {name}")
    authorization = config["policy_source_authorization"]
    expected_repository = (
        authorization["repository_identity"] or "operator_content_repository_v1"
    )
    if set(config["role_repository_identities"].values()) != {expected_repository}:
        _semantic_error(
            "role repository identities disagree with protected source authorization"
        )


def _validate_target_identity(value: dict, label: str) -> tuple[str, str, str]:
    try:
        rebuilt = TargetIdentity(value["scanner"], value["rule_id"], value["scope"])
    except (KeyError, DomainError) as exc:
        _semantic_error(f"{label} is not a canonical target identity: {exc}")
    if value != rebuilt.canonical_dict():
        _semantic_error(f"{label} derived identity forms are not canonical")
    return rebuilt.canonical_key


def _validate_gate_graph(verification: dict, *, allow_private_test_registry: bool) -> None:
    config = verification["verification_config"]
    required = config["required_gates"]
    validator_ids = required["validator_ids"]
    oracle_ids = required["oracle_ids"]
    _unique(validator_ids, lambda item: item, "required validator id")
    _unique(oracle_ids, lambda item: item, "required oracle id")
    if set(validator_ids) & set(oracle_ids):
        _semantic_error("a gate id cannot be both a required validator and oracle")

    validators = verification["validators"]
    oracles = verification["oracles"]
    _unique(validators, lambda item: item["gate_id"], "observed validator id")
    _unique(oracles, lambda item: item["gate_id"], "observed oracle id")
    if [item["gate_id"] for item in validators] != validator_ids:
        _semantic_error("validator evidence does not exactly cover required validators")
    if [item["gate_id"] for item in oracles] != oracle_ids:
        _semantic_error("oracle evidence does not exactly cover required oracles")

    top = verification["gate_implementations"]
    configured = config["gate_implementations"]
    if top != configured:
        _semantic_error("top-level gate implementations disagree with protected config")
    implementations = _unique(
        top, lambda item: item["gate_id"], "gate implementation id"
    )
    if set(implementations) != set(validator_ids) | set(oracle_ids):
        _semantic_error("gate implementations do not exactly cover required gates")
    for gate_id, implementation in implementations.items():
        expected_kind = "validator" if gate_id in validator_ids else "oracle"
        if implementation["kind"] != expected_kind:
            _semantic_error(f"gate implementation {gate_id!r} has the wrong kind")
        for name in (
            "code_sha256", "dependency_identity", "product_build_digest",
            "parser_dependency_digest", "schema_loader_contract_digest",
        ):
            _require_sha(implementation[name], f"gate {gate_id} {name}")
    allowed_registries = {
        "iac_guard_v_phase_d_registry_v4", "iac_guard_v_private_test_registry_v1",
    }
    if config["gate_registry_identity"] not in allowed_registries:
        _semantic_error("gate registry identity is not a closed packaged registry")
    if not allow_private_test_registry:
        if (
            config["source_provenance"] == "private_test"
            or config["gate_registry_identity"] == "iac_guard_v_private_test_registry_v1"
        ):
            _semantic_error(
                "private test gate registry or provenance is forbidden in public reports"
            )
        for implementation in implementations.values():
            if (
                implementation["version"] == "test"
                or implementation["contract_version"] == "test"
                or not implementation["artifact_kinds"]
                or implementation["code_sha256"] == "f" * 64
                or implementation["product_build_digest"] == "f" * 64
            ):
                _semantic_error("private synthetic gate evidence is forbidden publicly")
            if (
                implementation["code_sha256"]
                != implementation["product_build_digest"]
                or implementation["dependency_identity"]
                != implementation["parser_dependency_digest"]
                or implementation["version"]
                != implementation["contract_version"]
            ):
                _semantic_error("gate implementation aliases are inconsistent")


def _derived_entry_scope(path: str) -> tuple[bool, bool]:
    candidate = Path(path)
    supported = candidate.suffix.lower() in _SUPPORTED_SUFFIXES
    governed = (
        candidate.name in _GOVERNED_FILE_NAMES
        or any(part in _GOVERNED_DIRECTORY_NAMES for part in candidate.parts)
    )
    return supported, governed


def _validate_snapshot(snapshot: dict, config: dict, role: str) -> tuple[dict[str, dict], bool]:
    if snapshot["role"] != role:
        _semantic_error(f"{role} snapshot carries the wrong role")
    if snapshot["snapshot_sha256"] != config["role_snapshots"][role]:
        _semantic_error(f"{role} snapshot identity disagrees with protected config")
    if snapshot["config_sha256"] != config["config_sha256"]:
        _semantic_error(f"{role} snapshot belongs to a different protected config")
    if snapshot["repository_relative_subpath"] != config["role_subpaths"][role]:
        _semantic_error(f"{role} snapshot subpath disagrees with protected config")
    if snapshot["repository_identity"] != config["role_repository_identities"][role]:
        _semantic_error(f"{role} snapshot repository identity disagrees with protected config")

    files = _unique(snapshot["files"], lambda item: item["file_path"],
                    f"{role} snapshot file path")
    classifications = _unique(
        snapshot["classifications"], lambda item: item["file_path"],
        f"{role} artifact classification path",
    )
    entries = _unique(
        snapshot["filesystem_entries"], lambda item: item["file_path"],
        f"{role} filesystem entry path",
    )
    resources = _unique(
        snapshot["resources"],
        lambda item: (
            item["file_path"], item["resource_address"], item["artifact_kind"],
            item["scanner_native_lookup"],
        ),
        f"{role} resource identity",
    )
    governed = _unique(snapshot["governed_paths"], lambda item: item["file_path"],
                       f"{role} governed path")

    eligible_classifications = {
        path: item for path, item in classifications.items()
        if item["classification"] in {"TERRAFORM_RESOURCES", "KUBERNETES_RESOURCES"}
    }
    if set(files) != set(eligible_classifications):
        _semantic_error(f"{role} eligible files disagree with artifact classifications")
    classified_resources = []
    rejected = False
    for path, entry in entries.items():
        derived_supported, derived_governed = _derived_entry_scope(path)
        if (entry["supported"], entry["governed"]) != (
            derived_supported, derived_governed,
        ):
            _semantic_error(f"{role} filesystem scope flags are not derived from catalog")
        if derived_supported and path not in classifications:
            _semantic_error(f"{role} supported entry lacks artifact classification")
        if derived_governed and path not in governed:
            _semantic_error(f"{role} governed entry lacks governed-path evidence")
        if entry["rejection_reason"]:
            rejected = True
            classification = classifications.get(path)
            if (
                classification is None
                or classification["classification"] != "REJECTED_ARTIFACT_ENTRY"
                or classification["reason"] != entry["rejection_reason"]
            ):
                _semantic_error(f"{role} rejected artifact lacks typed classification")

    for path, classification in classifications.items():
        _require_sha(classification["sha256"], f"{role} classification digest")
        entry = entries.get(path)
        if entry is None:
            _semantic_error(f"{role} classified file lacks a filesystem entry")
        if classification["classification"] == "REJECTED_ARTIFACT_ENTRY":
            if entry["kind"] == "REGULAR_FILE" or not entry["rejection_reason"]:
                _semantic_error(f"{role} rejected classification lacks unsafe path evidence")
            expected = _canonical_json_digest(entry)
            if classification["sha256"] != expected or classification["size"] != entry["size"]:
                _semantic_error(f"{role} rejected classification is not entry-bound")
            continue
        if entry["kind"] != "REGULAR_FILE":
            _semantic_error(f"{role} classified file lacks a regular filesystem entry")
        if (classification["size"], classification["sha256"]) != (
            entry["size"], entry["sha256"],
        ):
            _semantic_error(f"{role} classification bytes disagree with filesystem entry")
        classified_resources.extend(classification["resources"])
    for path, bound in files.items():
        classification = eligible_classifications[path]
        if (bound["size"], bound["sha256"]) != (
            classification["size"], classification["sha256"],
        ):
            _semantic_error(f"{role} bound file bytes disagree with classification")
        _require_sha(bound["sha256"], f"{role} bound file digest")
    if sorted(classified_resources, key=_binding_key) != sorted(
        snapshot["resources"], key=_binding_key
    ):
        _semantic_error(f"{role} resource inventory disagrees with classifications")

    inventory_payload = {
        "resources": snapshot["resources"],
        "classifications": snapshot["classifications"],
    }
    if _canonical_json_digest(inventory_payload) != snapshot["resource_inventory_sha256"]:
        _semantic_error(f"{role} resource inventory digest is not canonical")
    artifact_payload = {
        "root_files": snapshot["classifications"],
        "eligible_files": snapshot["files"],
        "filesystem_entries": snapshot["filesystem_entries"],
    }
    if _canonical_json_digest(artifact_payload) != snapshot["artifact_manifest_sha256"]:
        _semantic_error(f"{role} artifact manifest digest is not canonical")
    source_records = sorted(snapshot["filesystem_entries"], key=lambda item: item["file_path"])
    if _canonical_json_digest(source_records) != snapshot["snapshot_sha256"]:
        _semantic_error(f"{role} source snapshot digest is not canonical")
    return files, rejected


def _finding_identity(item: dict) -> tuple:
    location = item["location"]
    return (
        item["scanner"], item["scanner_version"], item["artifact_kind"],
        item["rule_id"], item["resource_address"], item["native_fingerprint"],
        location["file_path"], location["start_line"], location["end_line"],
    )


def _evaluation_identity(item: dict) -> tuple:
    return (
        item["scanner"], item["scanner_version"], item["rule_id"],
        item["file_path"], item["resource_address"],
        tuple(item["evaluated_keys"]), item["occurrence_token"],
    )


def _validate_scanner_run(
    run: dict, snapshot: dict, role: str, *, allow_private_test_registry: bool,
) -> None:
    for name in (
        "stdout_sha256", "stderr_sha256", "raw_output_sha256", "launcher_digest",
        "scanner_environment_digest", "policy_inventory_digest",
        "invocation_config_digest", "installed_distribution_digest",
        "dependency_lock_digest", "custom_check_digest",
    ):
        _require_sha(run[name], f"{role} scanner {name}", allow_empty=True)
    components = run["environment_components"]
    if components is None:
        if not allow_private_test_registry:
            _semantic_error(f"{role} public scanner environment lacks component evidence")
    else:
        for name in (
            "non_policy_package_digest", "installed_distribution_digest",
            "dependency_closure_digest", "custom_check_digest",
            "policy_inventory_digest", "runtime_interpreter_digest",
        ):
            _require_sha(components[name], f"{role} scanner component {name}")
        if components["contract"] != "checkov-native-environment-v1":
            _semantic_error(f"{role} scanner environment contract is unsupported")
        if (
            _canonical_json_digest(components) != run["scanner_environment_digest"]
            or components["installed_distribution_digest"]
            != run["installed_distribution_digest"]
            or components["dependency_closure_digest"] != run["dependency_lock_digest"]
            or components["custom_check_digest"] != run["custom_check_digest"]
            or components["policy_inventory_digest"] != run["policy_inventory_digest"]
        ):
            _semantic_error(
                f"{role} scanner environment digest is not derived from its components"
            )
    if run["status"] == "PASS" and run["exit_code"] not in {0, 1}:
        _semantic_error(f"{role} PASS scanner run has a non-success exit code")
    diagnostics = run["diagnostics"]
    if run["status"] == "PASS":
        if diagnostics != ["COMPLETED"]:
            _semantic_error(f"{role} PASS scanner run contains adverse diagnostics")
        if run["ruleset_integrity"] != "PASS":
            _semantic_error(f"{role} PASS scanner run lacks ruleset integrity")
    elif not diagnostics or diagnostics[0] not in _SCANNER_FAILURE_REASONS:
        _semantic_error(f"{role} scanner failure lacks a closed typed diagnostic")
    if diagnostics:
        reason = diagnostics[0]
        expected_ruleset = (
            "FAIL" if reason in {
                "POLICY_INVENTORY_MISMATCH", "SCANNER_ENVIRONMENT_MISMATCH",
            }
            else "INCONCLUSIVE" if reason in {
                "UNSUPPORTED_VERSION", "VERSION_MISMATCH", "VERSION_PROBE_FAILED",
            }
            else None
        )
        if expected_ruleset is not None and run["ruleset_integrity"] != expected_ruleset:
            _semantic_error(f"{role} scanner ruleset integrity contradicts its reason")

    coverage = run["coverage"]
    if not (
        coverage["files_parsed"] <= coverage["files_discovered"]
        <= coverage["files_eligible"]
    ):
        _semantic_error(f"{role} scanner file coverage counters are inconsistent")
    if coverage["files_parsed"] + coverage["files_failed"] > coverage["files_discovered"]:
        _semantic_error(f"{role} parsed/failed file counts exceed discovery")
    if coverage["parse_errors"] > coverage["files_failed"]:
        _semantic_error(f"{role} parse errors exceed failed files")
    if coverage["evaluations_reported"] != len(run["evaluations"]):
        _semantic_error(f"{role} retained evaluations disagree with reported evaluations")

    resource = run["resource_coverage"]
    if resource["resources_expected"] != (
        resource["expected_resources_observed"] + resource["expected_resources_missing"]
    ) or resource["resources_observed"] != (
        resource["expected_resources_observed"] + resource["unexpected_resources_observed"]
    ):
        _semantic_error(f"{role} scanner resource counters are inconsistent")
    if run["status"] == "PASS" and (
        resource["expected_resources_missing"]
        or resource["unexpected_resources_observed"]
        or resource["resources_expected"] != len(snapshot["resources"])
        or resource["summary_resources_reported"] != resource["resources_observed"]
    ):
        _semantic_error(f"{role} PASS scanner run lacks complete resource coverage")

    findings = _unique(run["findings"], _finding_identity, f"{role} scanner finding identity")
    evaluations = _unique(
        run["evaluations"], _evaluation_identity, f"{role} scanner evaluation identity"
    )
    inputs = _unique(run["input_files"], lambda item: item["file_path"],
                     f"{role} scanner input path")
    snapshot_files = {item["file_path"]: item for item in snapshot["files"]}
    if run["status"] == "PASS" and set(inputs) != set(snapshot_files):
        _semantic_error(f"{role} PASS scanner inputs do not exactly cover sealed files")
    for path, item in inputs.items():
        bound = snapshot_files.get(path)
        if bound is None or item != bound:
            _semantic_error(f"{role} scanner input is not bound by its sealed snapshot")
    if coverage["files_eligible"] != len(inputs):
        _semantic_error(f"{role} scanner eligible count disagrees with input evidence")

    for item in (*findings.values(), *evaluations.values()):
        if (item["scanner"], item["scanner_version"]) != (
            run["scanner"], run["scanner_version"],
        ):
            _semantic_error(f"{role} scanner evidence belongs to another scanner domain")
        path = item["location"]["file_path"] if "location" in item else item["file_path"]
        if path not in inputs:
            _semantic_error(f"{role} scanner evidence refers to an unbound input")
    for item in evaluations.values():
        expected = _PASS_BUCKETS.get(item["source_bucket"])
        if expected is not None and item["native_result"] != expected:
            _semantic_error(f"{role} scanner evaluation bucket contradicts native result")
    observed_resource_keys = {
        (item["location"]["file_path"], item["resource_address"])
        for item in findings.values()
    } | {
        (item["file_path"], item["resource_address"])
        for item in evaluations.values()
    }
    expected_resource_keys = {
        (item["file_path"], item["resource_address"])
        for item in snapshot["resources"]
    }
    if run["status"] == "PASS" and expected_resource_keys != observed_resource_keys:
        _semantic_error(f"{role} PASS scanner resource evidence is incomplete or unexpected")
    if run["status"] == "PASS" and any((
        coverage["files_failed"], coverage["checks_failed_to_execute"],
        coverage["parse_errors"],
    )):
        _semantic_error(f"{role} PASS scanner run contains failure counters")


def _rebuild_finding(value: dict) -> Finding:
    location = value["location"]
    return Finding(
        scanner=value["scanner"],
        scanner_version=value["scanner_version"],
        rule_id=value["rule_id"],
        resource_address=value["resource_address"],
        location=FindingLocation(
            location["file_path"], location["start_line"], location["end_line"]
        ),
        severity=Severity(value["severity"]),
        occurrence_index=value["occurrence_index"],
        rule_name=value["rule_name"],
        message=value["message"],
        native_fingerprint=value["native_fingerprint"],
        iacgv_fingerprint=value["iacgv_fingerprint"],
        artifact_kind=ArtifactKind(value["artifact_kind"]),
        suppressed=value["suppressed"],
    )


def _validate_finding_graph(verification: dict, events: dict) -> None:
    baseline_run = verification["baseline_run"]
    candidate_run = verification["candidate_run"]
    identity_fields = (
        "scanner", "scanner_version", "launcher_digest",
        "scanner_environment_digest", "policy_inventory_digest",
        "invocation_config_digest", "installed_distribution_digest",
        "dependency_lock_digest", "custom_check_digest",
    )
    stable = (
        all(baseline_run[name] == candidate_run[name] for name in identity_fields)
        and baseline_run["ruleset_integrity"]
        == candidate_run["ruleset_integrity"] == "PASS"
    )
    try:
        baseline = tuple(
            _rebuild_finding(item) for item in baseline_run["findings"]
        )
        candidate = tuple(
            _rebuild_finding(item) for item in candidate_run["findings"]
        )
        derived = (
            diff_findings(baseline, candidate).canonical_dict()
            if stable else {"deltas": [], "ambiguities": []}
        )
    except (DomainError, KeyError, ValueError) as exc:
        _semantic_error(f"scanner findings cannot be canonically reconstructed: {exc}")
    if derived != verification["finding_diff"]:
        _semantic_error("finding diff is not derived from scanner finding multisets")

    deltas = verification["finding_diff"]["deltas"]
    uncertain = []
    decisive = []
    floor = SEVERITY_ORDER.index(Severity(
        verification["verification_config"]["severity_floor"]
    ))
    suppressed_targets = {
        (
            item["identity"]["scanner"], item["identity"]["rule_id"],
            item["identity"]["scope"], item["binding"]["file_path"],
            item["binding"]["artifact_kind"],
        )
        for item in verification["targets"] if item["outcome"] == "SUPPRESSED"
    }
    if verification["finding_diff"]["ambiguities"]:
        expected = {
            "gate_id": "regression", "status": "INCONCLUSIVE",
            "reason_code": "MATCHING_INCONCLUSIVE",
            "detail": (
                f"ambiguous_groups={len(verification['finding_diff']['ambiguities'])}"
            ),
        }
        if verification["regression"] != expected:
            _semantic_error("regression does not preserve matching ambiguity")
        return
    for delta in deltas:
        kind = delta["delta_class"]
        if kind == "NEW_FINDING":
            severity = Severity(delta["candidate"]["severity"])
            if severity is Severity.UNKNOWN:
                uncertain.append("NEW_FINDING_SEVERITY_UNKNOWN")
            elif SEVERITY_ORDER.index(severity) >= floor:
                decisive.append(kind)
        elif kind in {"SEVERITY_INCREASED", "SCOPE_EXPANDED", "SUPPRESSION_ADDED"}:
            if kind == "SUPPRESSION_ADDED":
                candidate = delta["candidate"]
                identity = (
                    candidate["scanner"], candidate["rule_id"],
                    candidate["resource_address"],
                    candidate["location"]["file_path"], candidate["artifact_kind"],
                )
                if identity in suppressed_targets:
                    continue
            decisive.append(kind)
        elif (kind == "LOCATION_CHANGED"
              and verification["verification_config"]["fail_on_location_change"]):
            decisive.append(kind)
    destructive = events["DESTRUCTIVE_CHANGE"]
    target_deletions = {
        (
            item["binding"]["file_path"], item["identity"]["scope"],
            item["binding"]["artifact_kind"],
            item["binding"]["scanner_native_lookup"],
        )
        for item in verification["targets"]
        if item["outcome"] in {"RESOURCE_DELETED", "FILE_DELETED_OR_RENAMED"}
    }
    unrelated = {
        (
            item["file_path"], item["resource_address"], item["artifact_kind"],
            item["scanner_native_lookup"],
        )
        for item in destructive["affected_resource_records"]
    } - target_deletions
    if unrelated:
        decisive.append("DESTRUCTIVE_CHANGE")
    if uncertain:
        expected = {
            "gate_id": "regression", "status": "INCONCLUSIVE",
            "reason_code": uncertain[0],
            "detail": ",".join(sorted(set(uncertain))),
        }
    elif decisive:
        expected = {
            "gate_id": "regression", "status": "FAIL",
            "reason_code": "REGRESSION_DETECTED",
            "detail": ",".join(sorted(set(decisive))),
        }
    else:
        expected = {
            "gate_id": "regression", "status": "PASS",
            "reason_code": "NO_DECISIVE_REGRESSION", "detail": "",
        }
    if verification["regression"] != expected:
        _semantic_error("regression is not derived from finding and resource evidence")


def _governed_comparison(baseline: dict, candidate: dict) -> list[dict]:
    before = {item["file_path"]: item for item in baseline["governed_paths"]}
    after = {item["file_path"]: item for item in candidate["governed_paths"]}
    result = []
    for path in sorted(set(before) | set(after)):
        old = before.get(path)
        new = after.get(path)
        old_kind = "ABSENT" if old is None else old["kind"]
        new_kind = "ABSENT" if new is None else new["kind"]
        old_sha = None if old is None else old["sha256"]
        new_sha = None if new is None else new["sha256"]
        state = (
            "added" if old is None else "removed" if new is None
            else "type_changed" if old_kind != new_kind
            else "stable" if (
                old_kind in {"REGULAR_FILE", "REAL_DIRECTORY"}
                and old_sha == new_sha
            ) else "changed"
        )
        result.append({
            "file_path": path,
            "trusted_sha256": old_sha,
            "candidate_sha256": new_sha,
            "state": state,
            "trusted_kind": old_kind,
            "candidate_kind": new_kind,
            "trusted_size": 0 if old is None else old["size"],
            "candidate_size": 0 if new is None else new["size"],
        })
    return result


def _validate_governed_graph(verification: dict, policy_evidence: dict, events: dict) -> None:
    derived = _governed_comparison(
        verification["baseline_snapshot"], verification["candidate_snapshot"]
    )
    config = verification["verification_config"]
    if config["governed_config"] != derived:
        _semantic_error("protected governed configuration disagrees with snapshots")
    if policy_evidence["governed_config_evidence"] != derived:
        _semantic_error("policy governed configuration disagrees with snapshots")
    differing = [item["file_path"] for item in derived if item["state"] != "stable"]
    if policy_evidence["differing_governed_paths"] != differing:
        _semantic_error("policy differing governed paths are not canonical")
    policy_event = events["POLICY_DRIFT"]
    expected_status = "FAIL" if differing else "PASS"
    expected_reason = "GOVERNED_CONFIG_DRIFT" if differing else "GOVERNED_CONFIG_STABLE"
    if (
        policy_event["status"] != expected_status
        or policy_event["reason_code"] != expected_reason
        or policy_event["affected_paths"] != differing
        or policy_event["affected_resources"]
        or policy_event["affected_resource_records"]
        or policy_event["detail"] != f"config={config['config_sha256']}"
    ):
        _semantic_error("POLICY_DRIFT event contradicts governed configuration")


def _validate_engine_events(verification: dict, events: dict) -> None:
    baseline = verification["baseline_run"]
    candidate = verification["candidate_run"]
    identity_fields = (
        "scanner", "scanner_version", "launcher_digest",
        "scanner_environment_digest", "policy_inventory_digest",
        "invocation_config_digest", "installed_distribution_digest",
        "dependency_lock_digest", "custom_check_digest",
    )
    stable = (
        all(baseline[name] == candidate[name] for name in identity_fields)
        and baseline["ruleset_integrity"] == candidate["ruleset_integrity"] == "PASS"
    )
    rule = events["RULE_SUBSTITUTED"]
    if rule != {
        "delta_class": "RULE_SUBSTITUTED",
        "status": "PASS" if stable else "INCONCLUSIVE",
        "reason_code": (
            "RULE_IDENTITY_STABLE" if stable else "RULE_SUBSTITUTION_NOT_DECIDABLE"
        ),
        "affected_resource_records": [], "affected_resources": [],
        "affected_paths": [], "detail": "",
    }:
        _semantic_error("RULE_SUBSTITUTED event is not derived from scanner identity")

    coverage_decreased = (
        candidate["status"] == "PARTIAL"
        or candidate["coverage"]["files_parsed"]
        < candidate["coverage"]["files_eligible"]
        or candidate["resource_coverage"]["resources_observed"]
        < candidate["resource_coverage"]["resources_expected"]
    )
    coverage_status = (
        "FAIL" if coverage_decreased else "PASS"
        if candidate["status"] == "PASS" else "INCONCLUSIVE"
    )
    coverage = events["COVERAGE_DECREASED"]
    if coverage != {
        "delta_class": "COVERAGE_DECREASED", "status": coverage_status,
        "reason_code": (
            "COVERAGE_COMPLETE" if coverage_status == "PASS"
            else "COVERAGE_DECREASED_OR_UNCERTAIN"
        ),
        "affected_resource_records": [], "affected_resources": [],
        "affected_paths": [], "detail": "",
    }:
        _semantic_error("COVERAGE_DECREASED event contradicts scanner coverage")

    added_diagnostics = sorted(set(candidate["diagnostics"]) - set(baseline["diagnostics"]))
    diagnostic = events["DIAGNOSTIC_ADDED"]
    if diagnostic != {
        "delta_class": "DIAGNOSTIC_ADDED",
        "status": "FAIL" if added_diagnostics else "PASS",
        "reason_code": "DIAGNOSTICS_ADDED" if added_diagnostics else "NO_DIAGNOSTICS_ADDED",
        "affected_resource_records": [], "affected_resources": [],
        "affected_paths": [], "detail": ",".join(added_diagnostics),
    }:
        _semantic_error("DIAGNOSTIC_ADDED event contradicts scanner diagnostics")

    before = {
        _binding_key(item): item for item in verification["baseline_snapshot"]["resources"]
    }
    after = {
        _binding_key(item): item for item in verification["candidate_snapshot"]["resources"]
    }
    deleted_records = [before[key] for key in sorted(set(before) - set(after))]
    deleted_resources = sorted({item["resource_address"] for item in deleted_records})
    deleted_paths = sorted({item["file_path"] for item in deleted_records})
    destructive = events["DESTRUCTIVE_CHANGE"]
    if destructive != {
        "delta_class": "DESTRUCTIVE_CHANGE",
        "status": "FAIL" if deleted_records else "PASS",
        "reason_code": "RESOURCES_DELETED" if deleted_records else "NO_RESOURCES_DELETED",
        "affected_resource_records": deleted_records,
        "affected_resources": deleted_resources,
        "affected_paths": deleted_paths,
        "detail": "",
    }:
        _semantic_error("DESTRUCTIVE_CHANGE event contradicts sealed resource inventories")


def _validate_change_metrics(verification: dict, events: dict) -> None:
    metrics = verification["change_metrics"]
    before_resources = {
        _binding_key(item) for item in verification["baseline_snapshot"]["resources"]
    }
    after_resources = {
        _binding_key(item) for item in verification["candidate_snapshot"]["resources"]
    }
    added = len(after_resources - before_resources)
    deleted = len(before_resources - after_resources)
    if (
        metrics["resources_added"] != added
        or metrics["resources_deleted"] != deleted
        or metrics["resources_changed"] != added + deleted
    ):
        _semantic_error("change metrics contradict sealed resource inventories")
    drift_count = len(events["POLICY_DRIFT"]["affected_paths"])
    if metrics["policy_files_changed"] != drift_count:
        _semantic_error("policy change metric contradicts governed drift")
    if metrics["lines_changed"] != metrics["lines_added"] + metrics["lines_removed"]:
        _semantic_error("line change metrics are internally inconsistent")
    unavailable = metrics["unavailable_metrics"]
    if len(unavailable) != len(set(unavailable)):
        _semantic_error("unavailable change metrics contain duplicates")


def _target_finding(item: dict, target: dict) -> bool:
    binding = target["binding"]
    return (
        item["scanner"] == target["identity"]["scanner"]
        and item["rule_id"] == target["identity"]["rule_id"]
        and item["resource_address"] == target["identity"]["scope"]
        and item["location"]["file_path"] == binding["file_path"]
        and item["artifact_kind"] == binding["artifact_kind"]
    )


def _target_evaluation(item: dict, target: dict, run: dict) -> bool:
    binding = target["binding"]
    return (
        item["scanner"] == target["identity"]["scanner"] == run["scanner"]
        and item["scanner_version"] == run["scanner_version"]
        and item["rule_id"] == target["identity"]["rule_id"]
        and item["resource_address"] == target["identity"]["scope"]
        and item["file_path"] == binding["file_path"]
    )


def _resource_key(item: dict) -> tuple:
    return (
        item["file_path"], item["resource_address"], item["artifact_kind"],
        item["scanner_native_lookup"],
    )


def _derive_target_outcome(verification: dict, target: dict) -> tuple[str, int, int]:
    baseline = verification["baseline_run"]
    candidate = verification["candidate_run"]
    binding = target["binding"]
    baseline_findings = [
        item for item in baseline["findings"] if _target_finding(item, target)
    ]
    candidate_findings = [
        item for item in candidate["findings"]
        if _target_finding(item, target) and not item["suppressed"]
    ]
    baseline_count = len(baseline_findings)
    candidate_count = len(candidate_findings)
    if baseline_count != binding["baseline_occurrences"]:
        return "INCONCLUSIVE", baseline_count, candidate_count
    if baseline["status"] != "PASS" or candidate["status"] != "PASS":
        return "SCANNER_ERROR", baseline_count, candidate_count

    identity_fields = (
        "scanner", "scanner_version", "launcher_digest",
        "scanner_environment_digest", "policy_inventory_digest",
        "invocation_config_digest", "installed_distribution_digest",
        "dependency_lock_digest", "custom_check_digest", "environment_components",
    )
    stable = (
        all(baseline[name] == candidate[name] for name in identity_fields)
        and baseline["ruleset_integrity"] == candidate["ruleset_integrity"] == "PASS"
    )
    if not stable:
        if "INCONCLUSIVE" in {baseline["ruleset_integrity"], candidate["ruleset_integrity"]}:
            return "INCONCLUSIVE", baseline_count, candidate_count
        return "RULE_OR_SCANNER_DRIFT", baseline_count, candidate_count

    baseline_resources = {_resource_key(item) for item in verification["baseline_snapshot"]["resources"]}
    candidate_resources = {_resource_key(item) for item in verification["candidate_snapshot"]["resources"]}
    exact_resource = (
        binding["file_path"], target["identity"]["scope"], binding["artifact_kind"],
        binding["scanner_native_lookup"],
    )
    if exact_resource not in baseline_resources:
        return "INCONCLUSIVE", baseline_count, candidate_count

    candidate_entries = {
        item["file_path"]: item
        for item in verification["candidate_snapshot"]["filesystem_entries"]
    }
    original = candidate_entries.get(binding["file_path"])
    if original is None or original["kind"] != "REGULAR_FILE":
        return "FILE_DELETED_OR_RENAMED", baseline_count, candidate_count

    classifications = {
        item["file_path"]: item
        for item in verification["candidate_snapshot"]["classifications"]
    }
    classification = classifications.get(binding["file_path"])
    eligible = (
        classification is not None
        and classification["classification"]
        in {"TERRAFORM_RESOURCES", "KUBERNETES_RESOURCES"}
    )
    if not eligible:
        return "OUT_OF_SCOPE", baseline_count, candidate_count
    if exact_resource not in candidate_resources:
        residual = any(_target_finding(item, target) for item in candidate["findings"]) or any(
            _target_evaluation(item, target, candidate) for item in candidate["evaluations"]
        )
        return (
            "INCONCLUSIVE" if residual else "RESOURCE_DELETED",
            baseline_count, candidate_count,
        )

    evaluations = [
        item for item in candidate["evaluations"]
        if _target_evaluation(item, target, candidate)
    ]
    skipped = [item for item in evaluations if item["native_result"] == "SKIPPED"]
    passed = [item for item in evaluations if item["native_result"] == "PASSED"]
    suppressed_findings = [
        item for item in candidate["findings"]
        if _target_finding(item, target) and item["suppressed"]
    ]
    if skipped or suppressed_findings:
        if passed or not skipped:
            return "INCONCLUSIVE", baseline_count, candidate_count
        return "SUPPRESSED", baseline_count, candidate_count

    ambiguities = verification["finding_diff"]["ambiguities"]
    if ambiguities:
        return "INCONCLUSIVE", baseline_count, candidate_count
    if binding["baseline_occurrences"] > 1 and 0 < candidate_count < baseline_count:
        return "PARTIALLY_FIXED", baseline_count, candidate_count
    if candidate_count >= baseline_count:
        return "STILL_PRESENT", baseline_count, candidate_count
    if candidate_count:
        return "INCONCLUSIVE", baseline_count, candidate_count
    if passed:
        if binding["baseline_occurrences"] > 1:
            baseline_tokens = {
                item["native_fingerprint"] for item in baseline_findings
                if item["native_fingerprint"]
            }
            passed_tokens = {
                item["occurrence_token"] for item in passed if item["occurrence_token"]
            }
            if (
                len(baseline_tokens) != binding["baseline_occurrences"]
                or not baseline_tokens <= passed_tokens
            ):
                return "INCONCLUSIVE", baseline_count, candidate_count
        return "FIXED", baseline_count, candidate_count
    return "INCONCLUSIVE", baseline_count, candidate_count


def _validate_target_and_policy_graph(
    verification: dict, policy: dict, *, allow_private_test_registry: bool,
) -> tuple[dict, dict]:
    targets = _unique(
        verification["targets"], lambda item: _binding_key(item["binding"]),
        "target resolved binding",
    )
    decisions = _unique(
        policy["decisions"], lambda item: _binding_key(item["resolved_target"]),
        "policy decision resolved binding",
    )
    if "" in decisions or set(targets) != set(decisions):
        _semantic_error("policy decisions do not exactly cover resolved targets")

    baseline = verification["baseline_run"]
    candidate = verification["candidate_run"]
    candidate_snapshot = verification["candidate_snapshot"]
    for key, target in targets.items():
        target_identity = _validate_target_identity(target["identity"], "target identity")
        binding_identity = _validate_target_identity(
            target["binding"]["identity"], "target binding identity"
        )
        if target_identity != binding_identity:
            _semantic_error("target identity disagrees with resolved binding identity")
        decision = decisions[key]
        decision_identity = _validate_target_identity(
            decision["identity"], "policy decision identity"
        )
        resolved_identity = _validate_target_identity(
            decision["resolved_target"]["identity"], "policy resolved target identity"
        )
        if decision["resolved_target"] != target["binding"]:
            _semantic_error("policy resolved target differs from target binding")
        if len({target_identity, decision_identity, resolved_identity}) != 1:
            _semantic_error("target and policy decision identities disagree")
        if decision["outcome"] != target["outcome"]:
            _semantic_error("policy decision outcome disagrees with target evidence")

        if not allow_private_test_registry:
            derived, baseline_count, candidate_count = _derive_target_outcome(
                verification, target
            )
            if target["outcome"] != derived or target["counts"] != {
                "baseline": baseline_count, "candidate": candidate_count,
            }:
                if target["outcome"] == "FIXED" and derived != "FIXED":
                    _semantic_error(
                        "FIXED target lacks affirmative exact-domain PASS evidence"
                    )
                _semantic_error(
                    "target outcome is not derived from scanner and sealed snapshot evidence"
                )
            closed_reasons = {
                "AFFIRMATIVE_TARGET_PASS", "TARGET_FAILED", "TARGET_SUPPRESSED",
                "TARGET_EVALUATION_UNKNOWN", "TARGET_NOT_EVALUATED",
                "RESOURCE_NOT_OBSERVED", "RULE_NOT_OBSERVED",
                "AGGREGATE_ONLY_EVIDENCE", "SCANNER_RUN_NOT_PASS",
                "OCCURRENCE_PASS_COVERAGE_INCOMPLETE",
            }
            if target["target_reason"] not in closed_reasons:
                _semantic_error("target reason is outside the closed evidence contract")

        if target["outcome"] == "FIXED":
            if target["target_reason"] != "AFFIRMATIVE_TARGET_PASS":
                _semantic_error("FIXED target lacks the affirmative target reason")
            if (decision["policy_permitted"] or decision["exception_id"]
                    or decision["rejection_reason"]):
                _semantic_error("FIXED target cannot carry exception policy evidence")
            binding = target["binding"]
            baseline_findings = [item for item in baseline["findings"] if _target_finding(item, target)]
            candidate_findings = [item for item in candidate["findings"] if _target_finding(item, target)]
            if target["counts"] != {
                "baseline": len(baseline_findings), "candidate": len(candidate_findings),
            } or target["counts"]["candidate"] != 0:
                _semantic_error("FIXED target finding counts disagree with scanner evidence")
            positive = [
                item for item in candidate["evaluations"]
                if item["native_result"] == "PASSED"
                and item["scanner"] == target["identity"]["scanner"]
                and item["rule_id"] == target["identity"]["rule_id"]
                and item["resource_address"] == target["identity"]["scope"]
                and item["file_path"] == binding["file_path"]
            ]
            resource_key = (
                binding["file_path"], target["identity"]["scope"],
                binding["artifact_kind"], binding["scanner_native_lookup"],
            )
            snapshot_keys = {
                (item["file_path"], item["resource_address"], item["artifact_kind"],
                 item["scanner_native_lookup"])
                for item in candidate_snapshot["resources"]
            }
            if not positive or resource_key not in snapshot_keys:
                _semantic_error("FIXED target lacks affirmative exact-domain PASS evidence")
            if binding["baseline_occurrences"] > 1:
                baseline_tokens = {
                    item["native_fingerprint"] for item in baseline_findings
                    if item["native_fingerprint"]
                }
                positive_tokens = {
                    item["occurrence_token"] for item in positive
                    if item["occurrence_token"]
                }
                if (len(baseline_tokens) != binding["baseline_occurrences"]
                        or not baseline_tokens <= positive_tokens):
                    _semantic_error("FIXED target occurrence-token coverage is incomplete")
        elif decision["policy_permitted"]:
            if target["outcome"] not in _EXCEPTION_ELIGIBLE_OUTCOMES:
                _semantic_error("policy exception permits an ineligible target outcome")
            if not decision["exception_id"]:
                _semantic_error("permitted non-fix target lacks an exception id")
            if decision["rejection_reason"]:
                _semantic_error("permitted target cannot also carry a rejection reason")
        elif decision["exception_id"]:
            _semantic_error("unpermitted policy decision cannot claim an exception id")
    return targets, decisions


def _validate_exception_graph(policy: dict, decisions: dict) -> None:
    evidence = policy["policy_evidence"]
    allowed_origins = {"operator", "trusted_base", "protected_policy_repo"}
    if evidence["source_origin"] not in allowed_origins:
        _semantic_error("policy evidence is not from an allowed trusted source")
    records = _unique(
        evidence["exception_records"], lambda item: item["exception_id"],
        "policy exception id",
    )
    sources = _unique(
        evidence["applied_exception_sources"], lambda item: item["exception_id"],
        "applied exception source id",
    )
    expected_applied = {
        decision["exception_id"] for decision in decisions.values()
        if decision["policy_permitted"]
    }
    if set(sources) != expected_applied:
        _semantic_error("applied exception sources do not exactly cover permitted decisions")
    for decision in decisions.values():
        if not decision["policy_permitted"]:
            continue
        exception_id = decision["exception_id"]
        record = records.get(exception_id)
        source = sources.get(exception_id)
        if record is None or source is None:
            _semantic_error("permitted decision lacks its exact exception evidence")
        if (
            record["origin"] != evidence["source_origin"]
            or source["source_origin"] != evidence["source_origin"]
            or source["source_origin"] not in allowed_origins
            or source["source_identity"] != evidence["source_identity"]
            or decision["outcome"] not in record["permitted_outcomes"]
            or record["resolved_target"] != decision["resolved_target"]
            or record["target"] != decision["identity"]
        ):
            _semantic_error("permitted decision exception source or binding is inconsistent")
        evaluation_date = policy["evaluation_date"]
        if not (record["created"] <= evaluation_date <= record["expires"]):
            _semantic_error("permitted decision exception is not active at evaluation time")


def _validate_artifact_failure_semantics(payload: dict) -> None:
    verification = payload["verification"]
    policy = payload["policy"]
    if (payload["verdict"], payload["exit_code"]) != ("FAILED", 1):
        _semantic_error("definite candidate artifact failure must be FAILED/1")
    if verification["preflight"]["status"] != "PASS":
        _semantic_error("candidate artifact failure requires a completed preflight")
    validators = verification["validators"]
    if len(validators) != 1 or validators[0]["status"] != "FAIL":
        _semantic_error("candidate artifact failure requires exactly one failed validator")
    if validators[0]["gate_id"] != verification["validator_gate_id"]:
        _semantic_error("candidate artifact failure substituted its validator gate")
    if validators[0]["reason_code"] != verification["failure_reason"]:
        _semantic_error("candidate artifact failure reason disagrees with its validator")
    if policy["verdict"] != "FAILED" or policy["exit_code"] != 1:
        _semantic_error("candidate artifact failure policy must be FAILED/1")


def _validate_full_semantics(
    payload: dict, *, allow_private_test_registry: bool,
) -> None:
    verification = payload["verification"]
    policy = payload["policy"]
    verdict = payload["verdict"]
    config = verification["verification_config"]
    _require_sha(config["config_sha256"], "verification config identity")
    _validate_config_identity(config)
    _validate_gate_graph(
        verification, allow_private_test_registry=allow_private_test_registry
    )
    _baseline_files, baseline_rejected = _validate_snapshot(
        verification["baseline_snapshot"], config, "baseline"
    )
    _candidate_files, candidate_rejected = _validate_snapshot(
        verification["candidate_snapshot"], config, "candidate"
    )
    if (
        verification["baseline_snapshot"]["snapshot_sha256"]
        == verification["candidate_snapshot"]["snapshot_sha256"]
    ):
        _semantic_error("differential verification requires distinct role snapshots")
    if (baseline_rejected or candidate_rejected) and verification["preflight"]["status"] == "PASS":
        _semantic_error("PASS preflight contains rejected artifact or filesystem evidence")
    _validate_scanner_run(
        verification["baseline_run"], verification["baseline_snapshot"], "baseline",
        allow_private_test_registry=allow_private_test_registry,
    )
    _validate_scanner_run(
        verification["candidate_run"], verification["candidate_snapshot"], "candidate",
        allow_private_test_registry=allow_private_test_registry,
    )
    baseline_run = verification["baseline_run"]
    candidate_run = verification["candidate_run"]
    scanner_config = config["scanner_identity"]
    invocation = config["invocation_settings"]
    invocation_digest = _canonical_json_digest({
        "adapter": "checkov-adapter-contract-v3",
        "compact": True,
        "download_external_modules": False,
        "frameworks": config["frameworks"],
        "output": "json",
        "quiet": False,
        "skip_download": True,
        "skip_results_upload": True,
        "max_eligible_files": invocation["max_eligible_files"],
        "max_file_bytes": invocation["max_file_bytes"],
        "max_total_eligible_bytes": invocation["max_total_eligible_bytes"],
    })
    for role, run in (("baseline", baseline_run), ("candidate", candidate_run)):
        if (
            run["scanner"] != scanner_config["scanner"]
            or run["scanner_version"] != scanner_config["version"]
            or run["launcher_digest"] != scanner_config["launcher_digest"]
            or run["scanner_environment_digest"]
            != scanner_config["scanner_environment_digest"]
            or run["policy_inventory_digest"]
            != scanner_config["policy_inventory_digest"]
            or run["invocation_config_digest"] != invocation_digest
        ):
            _semantic_error(f"{role} scanner evidence disagrees with protected identity")
    if (baseline_run["scanner"], baseline_run["scanner_version"]) != (
        candidate_run["scanner"], candidate_run["scanner_version"],
    ):
        _semantic_error("baseline and candidate scanner domains differ")
    execution_identity_fields = (
        "launcher_digest", "scanner_environment_digest", "policy_inventory_digest",
        "invocation_config_digest", "installed_distribution_digest",
        "dependency_lock_digest", "custom_check_digest",
    )
    if verification["scanner_integrity"]["status"] == "PASS" and any(
        baseline_run[name] != candidate_run[name] for name in execution_identity_fields
    ):
        _semantic_error("PASS scanner integrity contains execution-identity drift")

    events = _unique(
        verification["engine_events"], lambda item: item["delta_class"],
        "engine-event delta class",
    )
    if set(events) != _ENGINE_EVENT_CLASSES:
        _semantic_error("engine events do not contain the complete five-class set")
    _validate_engine_events(verification, events)
    _validate_finding_graph(verification, events)

    validators = verification["validators"]
    oracles = verification["oracles"]
    targets, decisions = _validate_target_and_policy_graph(
        verification, policy,
        allow_private_test_registry=allow_private_test_registry,
    )
    policy_evidence = policy["policy_evidence"]
    if policy_evidence["verification_config_sha256"] != config["config_sha256"]:
        _semantic_error("policy evidence belongs to a different verification config")
    if policy_evidence["candidate_snapshot_sha256"] != (
        verification["candidate_snapshot"]["snapshot_sha256"]
    ):
        _semantic_error("policy evidence belongs to a different candidate snapshot")
    if policy["evaluation_date"] != policy_evidence["evaluation_date"]:
        _semantic_error("policy evaluation dates disagree")
    authorization = config["policy_source_authorization"]
    if (
        policy_evidence["execution_mode"] != authorization["mode"]
        or policy_evidence["execution_context_identity"]
        != authorization["context_identity"]
        or policy_evidence["candidate_root_identity"]
        != authorization["candidate_identity"]
        or (
            authorization["repository_identity"]
            and policy_evidence["source_repository"]
            != authorization["repository_identity"]
        )
        or (
            authorization["commit_sha"]
            and policy_evidence["source_commit"] != authorization["commit_sha"]
        )
    ):
        _semantic_error("policy provenance disagrees with protected source authorization")
    _validate_governed_graph(verification, policy_evidence, events)
    _validate_exception_graph(policy, decisions)
    _validate_change_metrics(verification, events)
    if (
        not allow_private_test_registry
        and config["gate_registry_identity"] == "iac_guard_v_private_test_registry_v1"
    ):
        _semantic_error("private test gate registry is forbidden in public reports")

    isolation = payload["execution_isolation"]
    if isolation["mode"] == "reduced-isolation":
        if isolation["hostile_input_support"] is not False:
            _semantic_error("reduced-isolation cannot claim hostile-input support")
    elif verdict == "VERIFIED" and (
        isolation["hostile_input_support"] is not True
        or isolation["network_isolation_state"] != "PASS"
        or isolation["filesystem_isolation_state"] != "PASS"
        or isolation["scanner_environment_integrity_state"] != "PASS"
    ):
        _semantic_error("VERIFIED hardened-container lacks complete isolation evidence")

    preflight_pass = verification["preflight"]["status"] == "PASS"
    scanner_pass = verification["scanner_integrity"]["status"] == "PASS"
    run_integrity_pass = all(
        verification[name]["status"] == "PASS"
        and verification[name]["ruleset_integrity"] == "PASS"
        for name in ("baseline_run", "candidate_run")
    )
    required_gates_pass = all(
        item["status"] == "PASS" for item in validators + oracles
    )
    policy_gates_pass = all(
        verification[name]["status"] == "PASS"
        for name in ("regression", "suppression")
    )
    events_pass = all(item["status"] == "PASS" for item in events.values())
    no_ambiguity = not verification["finding_diff"]["ambiguities"]
    target_uncertainty = any(
        item["outcome"] in _INCONCLUSIVE_OUTCOMES for item in verification["targets"]
    )
    unpermitted_nonfix = any(
        target["outcome"] != "FIXED"
        and target["outcome"] not in _INCONCLUSIVE_OUTCOMES
        and not decisions[key]["policy_permitted"]
        for key, target in targets.items()
    )

    if verdict == "VERIFIED":
        if not all((
            preflight_pass, scanner_pass, run_integrity_pass, required_gates_pass,
            policy_gates_pass, events_pass, no_ambiguity,
        )):
            _semantic_error("VERIFIED requires every integrity and required gate to pass")
        if target_uncertainty or unpermitted_nonfix:
            _semantic_error("VERIFIED contains unresolved or unpermitted target evidence")
        if policy["verdict"] != "VERIFIED" or policy["exit_code"] != 0:
            _semantic_error("VERIFIED requires VERIFIED/0 policy evidence")
        return

    uncertain = (
        not preflight_pass
        or not scanner_pass
        or not run_integrity_pass
        or any(item["status"] in _UNCERTAIN_STATUSES for item in validators + oracles)
        or verification["regression"]["status"] in _UNCERTAIN_STATUSES
        or verification["suppression"]["status"] in _UNCERTAIN_STATUSES
        or any(item["status"] in _UNCERTAIN_STATUSES for item in events.values())
        or target_uncertainty
        or not no_ambiguity
    )
    decisive_failure = (
        any(item["status"] == "FAIL" for item in validators + oracles)
        or verification["regression"]["status"] == "FAIL"
        or verification["suppression"]["status"] == "FAIL"
        or any(item["status"] == "FAIL" for item in events.values())
        or unpermitted_nonfix
    )
    if verdict == "FAILED":
        if uncertain or not decisive_failure:
            _semantic_error("FAILED requires decisive negative evidence without uncertainty")
        if policy["verdict"] != "FAILED" or policy["exit_code"] != 1:
            _semantic_error("FAILED requires FAILED/1 policy evidence")
    elif verdict == "INCONCLUSIVE":
        if not uncertain:
            _semantic_error("INCONCLUSIVE requires typed uncertainty evidence")
        if policy["verdict"] != "INCONCLUSIVE" or policy["exit_code"] != 3:
            _semantic_error("INCONCLUSIVE requires INCONCLUSIVE/3 policy evidence")


def _validate_verification_semantics(
    payload: dict, *, allow_private_test_registry: bool,
) -> None:
    verification = payload["verification"]
    if "failure_stage" in verification:
        _validate_artifact_failure_semantics(payload)
    else:
        _validate_full_semantics(
            payload, allow_private_test_registry=allow_private_test_registry
        )


@dataclass(frozen=True, slots=True)
class VerificationReportV1:
    verification: VerificationResult
    policy_result: PolicyResult
    execution_isolation: ExecutionIsolationEvidence = field(
        default_factory=ExecutionIsolationEvidence.reduced_verified
    )

    def __post_init__(self) -> None:
        require_trusted_verification_result(self.verification)
        require_trusted_policy_result(self.policy_result)
        if type(self.execution_isolation) is not ExecutionIsolationEvidence:
            raise DomainError("verification report requires typed execution isolation evidence")
        bundle = self.policy_result.policy_evidence.bundle
        if (
            bundle.verification_config_sha256
            != self.verification.verification_config.config_sha256
            or bundle.candidate_snapshot_sha256
            != self.verification.candidate_snapshot.snapshot_sha256
        ):
            raise DomainError("report policy and verification evidence do not share a snapshot")
        outcome_keys = {item.binding.canonical_key for item in self.verification.target_outcomes}
        decision_keys = {
            item.resolved_target.canonical_key
            for item in self.policy_result.decisions
            if item.resolved_target is not None
        }
        if outcome_keys != decision_keys:
            raise DomainError("report policy decisions do not cover verification targets")

    @property
    def verdict(self) -> Verdict:
        return self.policy_result.verdict

    @property
    def exit_code(self) -> int:
        return self.policy_result.exit_code

    def canonical_dict(self) -> dict:
        result = {
            "schema_version": "report-v1",
            "result_kind": "verification",
            "verdict": self.verdict.value,
            "exit_code": self.exit_code,
            "execution_isolation": self.execution_isolation.canonical_dict(),
            "verification": self.verification.canonical_dict(),
            "policy": self.policy_result.canonical_dict(),
        }
        registry = self.verification.verification_config.gate_registry.identity
        if registry == "iac_guard_v_private_test_registry_v1":
            _validate_test_report_payload(result)
        else:
            validate_report_payload(result)
        return result

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ) + "\n"

    @property
    def report_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class OperationalReportV1:
    reason_code: str
    detail: str
    remediation: str

    def __post_init__(self) -> None:
        for name in ("reason_code", "detail", "remediation"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip() or any(
                ord(char) < 32 and char not in "\t" for char in value
            ):
                raise DomainError(f"operational report {name} must be safe nonblank text")

    @property
    def verdict(self) -> Verdict:
        return Verdict.INCONCLUSIVE

    @property
    def exit_code(self) -> int:
        return 3

    def canonical_dict(self) -> dict:
        result = {
            "schema_version": "report-v1",
            "result_kind": "operational_uncertainty",
            "verdict": "INCONCLUSIVE",
            "exit_code": 3,
            "diagnostic": {
                "reason_code": self.reason_code,
                "detail": self.detail,
                "remediation": self.remediation,
            },
        }
        validate_report_payload(result)
        return result

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ) + "\n"


@dataclass(frozen=True, slots=True)
class CandidateArtifactFailureReportV1:
    artifact_kind: ArtifactKind
    validator_gate_id: str
    reason_code: str
    detail: str
    execution_isolation: ExecutionIsolationEvidence

    def __post_init__(self) -> None:
        if type(self.artifact_kind) is not ArtifactKind or self.artifact_kind is ArtifactKind.UNKNOWN:
            raise DomainError("candidate artifact failure requires a concrete artifact kind")
        for name in ("validator_gate_id", "reason_code", "detail"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip() or any(ord(char) < 32 for char in value):
                raise DomainError(f"candidate artifact failure {name} must be safe nonblank text")
        if type(self.execution_isolation) is not ExecutionIsolationEvidence:
            raise DomainError("candidate artifact failure requires isolation evidence")

    @property
    def verdict(self) -> Verdict:
        return Verdict.FAILED

    @property
    def exit_code(self) -> int:
        return 1

    def canonical_dict(self) -> dict:
        result = {
            "schema_version": "report-v1",
            "result_kind": "verification",
            "verdict": "FAILED",
            "exit_code": 1,
            "execution_isolation": self.execution_isolation.canonical_dict(),
            "verification": {
                "failure_stage": "V1",
                "artifact_kind": self.artifact_kind.value,
                "validator_gate_id": self.validator_gate_id,
                "failure_reason": self.reason_code,
                "preflight": {
                    "gate_id": "preflight", "status": "PASS",
                    "reason_code": "PUBLIC_REQUEST_BOUND", "detail": "",
                },
                "validators": [{
                    "gate_id": self.validator_gate_id, "status": "FAIL",
                    "reason_code": self.reason_code, "detail": self.detail,
                }],
            },
            "policy": {
                "verdict": "FAILED", "exit_code": 1, "decisions": [],
                "policy_evidence": {
                    "source_origin": "operator",
                    "reason_code": "CANDIDATE_ARTIFACT_INVALID",
                },
            },
        }
        validate_report_payload(result)
        return result

    def canonical_json(self) -> str:
        return json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")) + "\n"

def render_console(report: VerificationReportV1 | OperationalReportV1 | CandidateArtifactFailureReportV1) -> str:
    """Human projection of report-v1; it introduces no new evidence."""
    value = report.canonical_dict()
    lines = [
        f"IaC-Guard-V: {value['verdict']}",
        f"exit_code: {value['exit_code']}",
    ]
    if value["result_kind"] == "operational_uncertainty":
        diagnostic = value["diagnostic"]
        lines.extend((
            f"reason: {diagnostic['reason_code']}",
            f"detail: {diagnostic['detail']}",
            f"remediation: {diagnostic['remediation']}",
        ))
    else:
        verification = value["verification"]
        targets = verification.get("targets", [])
        lines.append("targets:")
        for target in targets:
            identity = target["binding"]["identity"]
            lines.append(
                f"  {identity['rule_id']} {identity['scope']}: {target['outcome']}"
            )
        if "failure_stage" in verification:
            lines.extend((
                "scanner integrity: not executed",
                "regressions: not evaluated",
            ))
        else:
            lines.append(
                f"scanner integrity: {verification['scanner_integrity']['status']}"
            )
            regression = verification["regression"]["status"]
            lines.append(
                "regressions: none" if regression == "PASS"
                else f"regressions: {regression}"
            )
        lines.append(f"policy: {value['policy']['verdict']}")
    return "\n".join(lines) + "\n"


__all__ = [
    "CandidateArtifactFailureReportV1", "ExecutionIsolationEvidence",
    "OperationalReportV1", "VerificationReportV1", "render_console",
    "validate_report_payload",
]
