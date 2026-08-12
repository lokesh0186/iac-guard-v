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

from .enums import ArtifactKind, Verdict
from .engine import VerificationResult, require_trusted_verification_result
from .models import DomainError, TargetIdentity
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


def validate_report_payload(payload: dict) -> None:
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
        _validate_verification_semantics(payload)


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


def _validate_target_identity(value: dict, label: str) -> tuple[str, str, str]:
    try:
        rebuilt = TargetIdentity(value["scanner"], value["rule_id"], value["scope"])
    except (KeyError, DomainError) as exc:
        _semantic_error(f"{label} is not a canonical target identity: {exc}")
    if value != rebuilt.canonical_dict():
        _semantic_error(f"{label} derived identity forms are not canonical")
    return rebuilt.canonical_key


def _validate_gate_graph(verification: dict) -> None:
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
    if config["gate_registry_identity"] not in {
        "iac_guard_v_phase_d_registry_v4",
        "iac_guard_v_private_test_registry_v1",
    }:
        _semantic_error("gate registry identity is not a closed packaged registry")


def _validate_snapshot(snapshot: dict, config: dict, role: str) -> dict[str, dict]:
    if snapshot["role"] != role:
        _semantic_error(f"{role} snapshot carries the wrong role")
    if snapshot["snapshot_sha256"] != config["role_snapshots"][role]:
        _semantic_error(f"{role} snapshot identity disagrees with protected config")
    if snapshot["config_sha256"] != config["config_sha256"]:
        _semantic_error(f"{role} snapshot belongs to a different protected config")
    if snapshot["repository_relative_subpath"] != config["role_subpaths"][role]:
        _semantic_error(f"{role} snapshot subpath disagrees with protected config")

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
    _unique(snapshot["governed_paths"], lambda item: item["file_path"],
            f"{role} governed path")

    eligible_classifications = {
        path: item for path, item in classifications.items()
        if item["classification"] in {"TERRAFORM_RESOURCES", "KUBERNETES_RESOURCES"}
    }
    if set(files) != set(eligible_classifications):
        _semantic_error(f"{role} eligible files disagree with artifact classifications")
    classified_resources = []
    for path, classification in classifications.items():
        _require_sha(classification["sha256"], f"{role} classification digest")
        entry = entries.get(path)
        if entry is None or entry["kind"] != "REGULAR_FILE":
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
    return files


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


def _validate_scanner_run(run: dict, snapshot: dict, role: str) -> None:
    for name in (
        "stdout_sha256", "stderr_sha256", "raw_output_sha256", "launcher_digest",
        "scanner_environment_digest", "policy_inventory_digest",
        "invocation_config_digest", "installed_distribution_digest",
        "dependency_lock_digest", "custom_check_digest",
    ):
        _require_sha(run[name], f"{role} scanner {name}", allow_empty=True)
    if run["status"] == "PASS" and run["exit_code"] != 0:
        _semantic_error(f"{role} PASS scanner run has a non-success exit code")

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
    if coverage["evaluations_reported"] < len(run["evaluations"]):
        _semantic_error(f"{role} retained evaluations exceed reported evaluations")

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
    if run["ruleset_integrity"] == "PASS" and any(
        "MISMATCH" in diagnostic for diagnostic in run["diagnostics"]
    ):
        _semantic_error(f"{role} ruleset integrity contradicts its diagnostics")


def _validate_target_and_policy_graph(verification: dict, policy: dict) -> tuple[dict, dict]:
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

        if target["outcome"] == "FIXED":
            if target["target_reason"] != "AFFIRMATIVE_TARGET_PASS":
                _semantic_error("FIXED target lacks the affirmative target reason")
            if (decision["policy_permitted"] or decision["exception_id"]
                    or decision["rejection_reason"]):
                _semantic_error("FIXED target cannot carry exception policy evidence")
            binding = target["binding"]
            def matching_finding(item: dict) -> bool:
                return (
                    item["scanner"] == target["identity"]["scanner"]
                    and item["rule_id"] == target["identity"]["rule_id"]
                    and item["resource_address"] == target["identity"]["scope"]
                    and item["location"]["file_path"] == binding["file_path"]
                    and item["artifact_kind"] == binding["artifact_kind"]
                )
            baseline_findings = [item for item in baseline["findings"] if matching_finding(item)]
            candidate_findings = [item for item in candidate["findings"] if matching_finding(item)]
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


def _validate_full_semantics(payload: dict) -> None:
    verification = payload["verification"]
    policy = payload["policy"]
    verdict = payload["verdict"]
    config = verification["verification_config"]
    _require_sha(config["config_sha256"], "verification config identity")
    _validate_gate_graph(verification)
    _validate_snapshot(verification["baseline_snapshot"], config, "baseline")
    _validate_snapshot(verification["candidate_snapshot"], config, "candidate")
    _validate_scanner_run(
        verification["baseline_run"], verification["baseline_snapshot"], "baseline"
    )
    _validate_scanner_run(
        verification["candidate_run"], verification["candidate_snapshot"], "candidate"
    )
    baseline_run = verification["baseline_run"]
    candidate_run = verification["candidate_run"]
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

    validators = verification["validators"]
    oracles = verification["oracles"]
    targets, decisions = _validate_target_and_policy_graph(verification, policy)
    policy_evidence = policy["policy_evidence"]
    if policy_evidence["verification_config_sha256"] != config["config_sha256"]:
        _semantic_error("policy evidence belongs to a different verification config")
    if policy_evidence["candidate_snapshot_sha256"] != (
        verification["candidate_snapshot"]["snapshot_sha256"]
    ):
        _semantic_error("policy evidence belongs to a different candidate snapshot")
    if policy["evaluation_date"] != policy_evidence["evaluation_date"]:
        _semantic_error("policy evaluation dates disagree")

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


def _validate_verification_semantics(payload: dict) -> None:
    verification = payload["verification"]
    if "failure_stage" in verification:
        _validate_artifact_failure_semantics(payload)
    else:
        _validate_full_semantics(payload)


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
        targets = value["verification"].get("targets", [])
        lines.append("targets:")
        for target in targets:
            identity = target["binding"]["identity"]
            lines.append(
                f"  {identity['rule_id']} {identity['scope']}: {target['outcome']}"
            )
        if hasattr(report, "report_sha256"):
            lines.append(f"report_sha256: {report.report_sha256}")
    return "\n".join(lines) + "\n"


__all__ = [
    "CandidateArtifactFailureReportV1", "ExecutionIsolationEvidence",
    "OperationalReportV1", "VerificationReportV1", "render_console",
    "validate_report_payload",
]
