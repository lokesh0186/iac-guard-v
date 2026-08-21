#!/usr/bin/env python3
"""Validate source and locked-runtime evidence for the advisory E4 catalog."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import re
import subprocess
import urllib.request
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CLASSES = {"EXACT", "RELATED", "OVERLAPPING", "NOT_COMPARABLE", "UNKNOWN"}
SHA40 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
SCANNERS = ("checkov", "kics", "trivy")
FIXTURES = ("boundary", "negative", "positive")
APPROVED_LOCKS = {
    "checkov": {
        "version": "3.3.0", "release_tag": "3.3.0",
        "source_repository": "https://github.com/bridgecrewio/checkov",
        "source_commit": "5b5ce3e65339c78ca9977e06beb504240db95fdc",
    },
    "kics": {
        "version": "2.1.20", "release_tag": "v2.1.20",
        "source_repository": "https://github.com/Checkmarx/kics",
        "source_commit": "e1f23cad9640f55b963f22a116b04906b8c16ac6",
    },
    "trivy": {
        "version": "0.73.0", "release_tag": "v2.2.0",
        "source_repository": "https://github.com/aquasecurity/trivy-checks",
        "source_commit": "d7c9302130a9b7e614a5c5d32854f6a08b4bc52e",
    },
}
APPROVED_SOURCE_HASHES = {
    ("checkov", "checkov/kubernetes/checks/resource/k8s/PrivilegedContainers.py"): "8db4658cd3cd3a8016f40b669b59320d3337f1b677a6a79adf13a2d8cf28281b",
    ("checkov", "checkov/kubernetes/checks/resource/k8s/AllowPrivilegeEscalation.py"): "8b4c6a608aa3755c2267e236d35626b4b4b49b31971fd7a142aa046b434a2317",
    ("kics", "assets/queries/k8s/container_is_privileged/query.rego"): "9a0e7c27fadf3edf05546abf395385f7675a0b091a4f7750912207116200b57d",
    ("kics", "assets/queries/k8s/privilege_escalation_allowed/query.rego"): "d38f32e8d3bc6a8f76dcb74e137cbdf4130d8be736547402822085887882a624",
    ("trivy", "checks/kubernetes/privileged.rego"): "98af8ef6e31b069b4f39e399f50bcb42b2d08b183d96cec451ae52887ba99174",
    ("trivy", "checks/kubernetes/can_elevate_its_own_privileges.rego"): "175b99a61e8c5b8af01c018bb0d870e3713610847d9abdfa5f9290a36bebc3e1",
}
SOURCE_FIELDS = {
    "repository", "commit", "relative_path", "url", "sha256",
    "source_attestation_identity",
}
REQUIRED_RELATIONSHIP = {
    "relationship_id", "classification", "checkov_rule_id", "kics_query_id",
    "trivy_check_id", "semantics", "authoritative_sources", "fixtures",
    "expected_locked_observations", "variable_default_behavior",
    "resource_type_scope", "known_semantic_differences", "exact_blockers",
    "independent_reviewer_signoff", "validated_screening_status",
    "validated_screening_blockers",
}
RUNTIME_FIELDS = {
    "relationship_id", "fixture_kind", "fixture_sha256", "scanner",
    "scanner_version", "policy_identity", "invocation_identity",
    "environment_identity", "execution_status", "exit_code", "diagnostics",
    "command_argv", "command_argv_sha256", "stdout_sha256", "stderr_sha256",
    "duration_ms", "native_result",
    "normalized_result", "raw_output_sha256", "canonical_output_sha256",
    "expected_relationship_observation",
}
RUNTIME_TOP_FIELDS = {
    "contract", "architecture", "protected_evidence_identity", "records",
    "execution_attestation", "evidence_root_sha256",
}
ATTESTATION_FIELDS = {
    "contract", "status", "creation_timestamp", "architecture",
    "protected_evidence_identity", "protected_cache_manifest_root",
    "cache_attestation_identity", "cache_attestation_record_sha256",
    "cache_attestation_signature_sha256", "cache_attestation_public_key_sha256",
    "runtime_identity", "runtime_executable_sha256", "runtime_client_version",
    "runtime_server_version", "runtime_context_identity", "runtime_daemon_identity",
    "runner_implementation_sha256", "record_root_sha256", "attestation_identity",
}
APPROVED_ARCHITECTURE = "linux/arm64"
APPROVED_PROTECTED_EVIDENCE_IDENTITY = (
    "fb99f10ef065becb441436f44c4ebb5dbb7631a602438ffaaeeb0ea9e1a97784"
)
# Updated only by a reviewed locked execution. Re-sealing JSON is insufficient.
APPROVED_EXECUTION_ATTESTATION_IDENTITY = (
    "07c4dabccdf26b0f057195dea683b05f4e7cb3bdac9b1c5aeeeace8cdee70277"
)
EXECUTION_STATUSES = {"PASS", "PARTIAL", "ERROR", "INCONCLUSIVE", "TIMEOUT"}
NORMALIZED_RESULTS = {"FINDING", "NO_FINDING", "SUPPRESSED", "ERROR", "INCONCLUSIVE"}
NATIVE_RESULTS = {
    "FAILED", "PASSED", "SKIPPED", "ABSENT", "INVALID_RESULTS_STRUCTURE",
    "COVERAGE_MISMATCH", "PROCESS_ERROR", "TIMEOUT", "EXIT_CODE_OUTSIDE_CONTRACT",
    "EXIT_RESULT_MISMATCH", "SCANNER_ERROR", "PARTIAL_SCAN",
}
SCREENING_STATUSES = {
    "READY_FOR_VALIDATED_SCREENING",
    "NOT_READY_FOR_VALIDATED_SCREENING",
}


class UniqueLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader: UniqueLoader, node: yaml.MappingNode, deep: bool = False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate catalog key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()


def _safe_file(relative: str) -> Path:
    unresolved = ROOT / relative
    candidate = unresolved.resolve()
    try:
        candidate.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError("catalog evidence path escapes repository") from exc
    cursor = ROOT
    has_symlink = False
    for part in Path(relative).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            has_symlink = True
            break
    if not candidate.is_file() or has_symlink:
        raise ValueError(f"catalog evidence is unavailable or unsafe: {relative}")
    return candidate


def _validate_locks(locks: object) -> None:
    if type(locks) is not dict or set(locks) != set(SCANNERS):
        raise ValueError("catalog requires exactly three scanner locks")
    for scanner, approved in APPROVED_LOCKS.items():
        lock = locks[scanner]
        required = {
            "version", "source_repository", "release_tag", "tag_ref_commit",
            "source_commit", "policy_identity", "runtime_policy_digest",
            "runtime_environment_digest",
        }
        if type(lock) is not dict or set(lock) != required:
            raise ValueError(f"{scanner} lock fields are incomplete")
        for name, expected in approved.items():
            if lock[name] != expected:
                raise ValueError(f"{scanner} {name} is not the reviewed lock")
        if lock["tag_ref_commit"] != lock["source_commit"]:
            raise ValueError(f"{scanner} tag relation does not bind the selected commit")
        if not SHA40.fullmatch(lock["source_commit"]):
            raise ValueError(f"{scanner} source commit is not immutable")
        if type(lock["policy_identity"]) is not str or not lock["policy_identity"]:
            raise ValueError(f"{scanner} policy identity is missing")
        if not SHA256.fullmatch(lock["runtime_policy_digest"]) or not SHA256.fullmatch(
            lock["runtime_environment_digest"]
        ):
            raise ValueError(f"{scanner} runtime identity is invalid")


def _validate_source(scanner: str, source: object, lock: dict) -> None:
    if type(source) is not dict or set(source) != SOURCE_FIELDS:
        raise ValueError(f"{scanner} source evidence is incomplete")
    if source["repository"] != lock["source_repository"]:
        raise ValueError(f"{scanner} source repository is not approved")
    if source["commit"] != lock["source_commit"]:
        raise ValueError(f"{scanner} source commit is not the release commit")
    path = source["relative_path"]
    if type(path) is not str or not path or path.startswith("/") or ".." in Path(path).parts:
        raise ValueError(f"{scanner} source path is unsafe")
    owner_repo = lock["source_repository"].removeprefix("https://github.com/")
    expected_url = f"https://raw.githubusercontent.com/{owner_repo}/{lock['source_commit']}/{path}"
    if source["url"] != expected_url:
        raise ValueError(f"{scanner} source URL is not commit-pinned")
    if source["sha256"] != APPROVED_SOURCE_HASHES.get((scanner, path)):
        raise ValueError(f"{scanner} source file digest is not the reviewed source")
    children = {name: source[name] for name in SOURCE_FIELDS - {"source_attestation_identity"}}
    if source["source_attestation_identity"] != _canonical_sha(children):
        raise ValueError(f"{scanner} source attestation identity is not canonical")


def _validate_runtime(data: dict, relationships: list, locks: dict, reference: dict) -> dict:
    path = _safe_file(reference["path"])
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise ValueError("catalog runtime-evidence file digest does not match")
    try:
        runtime = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("catalog runtime evidence is malformed") from exc
    if type(runtime) is not dict or set(runtime) != RUNTIME_TOP_FIELDS:
        raise ValueError("catalog runtime top-level fields are invalid")
    if runtime.get("contract") != "phase-e-control-fixture-runtime-evidence-v2":
        raise ValueError("catalog runtime evidence contract is unsupported")
    if runtime["architecture"] != APPROVED_ARCHITECTURE:
        raise ValueError("catalog runtime architecture is not reviewed")
    if runtime["protected_evidence_identity"] != APPROVED_PROTECTED_EVIDENCE_IDENTITY:
        raise ValueError("catalog runtime protected-evidence identity is not reviewed")
    root = runtime.pop("evidence_root_sha256", None)
    if root != _canonical_sha(runtime):
        raise ValueError("catalog runtime evidence root is not canonical")
    records = runtime.get("records")
    if type(records) is not list:
        raise ValueError("catalog runtime records are malformed")
    expected = {}
    for relationship in relationships:
        for fixture_kind in FIXTURES:
            fixture = _safe_file(relationship["fixtures"][fixture_kind])
            fixture_sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
            for scanner in SCANNERS:
                expected[(relationship["relationship_id"], fixture_kind, scanner)] = (
                    fixture_sha,
                    relationship["expected_locked_observations"][fixture_kind][scanner],
                )
    observed = {}
    for record in records:
        if type(record) is not dict or set(record) != RUNTIME_FIELDS:
            raise ValueError("catalog runtime record fields are invalid")
        key = (record["relationship_id"], record["fixture_kind"], record["scanner"])
        if key in observed or key not in expected:
            raise ValueError("catalog runtime record is duplicate or unbound")
        observed[key] = record
        fixture_sha, expected_result = expected[key]
        if record["fixture_sha256"] != fixture_sha:
            raise ValueError("catalog runtime fixture digest does not match")
        if record["scanner_version"] != locks[key[2]]["version"]:
            raise ValueError("catalog runtime scanner version does not match lock")
        if record["policy_identity"] != locks[key[2]]["runtime_policy_digest"]:
            raise ValueError("catalog runtime policy identity does not match lock")
        if record["environment_identity"] != locks[key[2]]["runtime_environment_digest"]:
            raise ValueError("catalog runtime environment identity does not match lock")
        if record["expected_relationship_observation"] != expected_result:
            raise ValueError("catalog runtime expectation does not match catalog")
        if record["normalized_result"] != expected_result:
            raise ValueError("locked scanner output contradicts catalog observation")
        if record["execution_status"] not in EXECUTION_STATUSES:
            raise ValueError("catalog runtime execution status is invalid")
        if record["native_result"] not in NATIVE_RESULTS:
            raise ValueError("catalog runtime native result is invalid")
        if record["normalized_result"] not in NORMALIZED_RESULTS:
            raise ValueError("catalog runtime normalized result is invalid")
        expected_normalized = (
            {"FINDING", "NO_FINDING", "SUPPRESSED"}
            if record["execution_status"] == "PASS" else
            {"ERROR"} if record["execution_status"] == "ERROR" else {"INCONCLUSIVE"}
        )
        if record["normalized_result"] not in expected_normalized:
            raise ValueError("catalog runtime execution status contradicts normalized result")
        if type(record["exit_code"]) is not int or not -1 <= record["exit_code"] <= 255:
            raise ValueError("catalog runtime exit code is invalid")
        diagnostics = record["diagnostics"]
        if (type(diagnostics) is not list or not diagnostics
                or any(type(item) is not str or not item or len(item) > 160 for item in diagnostics)
                or len(set(diagnostics)) != len(diagnostics)):
            raise ValueError("catalog runtime diagnostics are invalid")
        if record["execution_status"] == "PASS" and diagnostics != ["COMPLETED"]:
            raise ValueError("catalog runtime PASS diagnostics are contradictory")
        if record["execution_status"] != "PASS" and record["native_result"] not in diagnostics:
            raise ValueError("catalog runtime native result is not retained in diagnostics")
        commands = record["command_argv"]
        if (type(commands) is not list or not commands
                or any(type(command) is not list or not command
                       or any(type(arg) is not str for arg in command)
                       for command in commands)):
            raise ValueError("catalog runtime command argv is invalid")
        _validate_locked_argv(record["scanner"], commands)
        if record["command_argv_sha256"] != _canonical_sha(commands):
            raise ValueError("catalog runtime command argv digest is inconsistent")
        if type(record["duration_ms"]) is not int or record["duration_ms"] < 0:
            raise ValueError("catalog runtime duration is invalid")
        for digest in (
            "invocation_identity", "environment_identity", "raw_output_sha256",
            "canonical_output_sha256", "command_argv_sha256", "stdout_sha256",
            "stderr_sha256",
        ):
            if not SHA256.fullmatch(str(record[digest])):
                raise ValueError(f"catalog runtime {digest} is invalid")
        if type(record["policy_identity"]) is not str or not record["policy_identity"]:
            raise ValueError("catalog runtime policy identity is missing")
    if set(observed) != set(expected):
        raise ValueError("catalog runtime evidence does not cover every scanner/fixture pair")
    _validate_execution_attestation(runtime)
    return observed


def _validate_exact_signoff(signoff: object) -> None:
    required = {
        "verification_status", "verification_record_path",
        "verification_record_sha256", "signature_path", "signature_sha256",
        "public_key_path", "public_key_sha256", "signer_identity",
    }
    if type(signoff) is not dict or set(signoff) != required:
        raise ValueError(
            "EXACT mapping requires mechanically verified sign-off: complete signed record"
        )
    if signoff["verification_status"] != "VERIFIED":
        raise ValueError("EXACT mapping sign-off is not verified")
    record = _safe_file(signoff["verification_record_path"])
    signature = _safe_file(signoff["signature_path"])
    public_key = _safe_file(signoff["public_key_path"])
    for path, field in (
        (record, "verification_record_sha256"),
        (signature, "signature_sha256"), (public_key, "public_key_sha256"),
    ):
        if hashlib.sha256(path.read_bytes()).hexdigest() != signoff[field]:
            raise ValueError("EXACT mapping sign-off bytes do not match")
    expected_signer = f"ed25519:{signoff['public_key_sha256']}"
    if signoff["signer_identity"] != expected_signer:
        raise ValueError("EXACT mapping signer identity is invalid")
    result = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
         "-sigfile", str(signature), "-rawin", "-in", str(record)],
        capture_output=True,
    )
    if result.returncode != 0:
        raise ValueError("EXACT mapping sign-off signature is invalid")


def _validate_locked_argv(scanner: str, commands: list[list[str]]) -> None:
    if scanner == "checkov":
        if (len(commands) != 2
                or any(command[0] != "<checkov-executable>" for command in commands)
                or "--version" not in commands[0] or "--output" not in commands[1]):
            raise ValueError("Checkov invocation is not the locked adapter command")
        return
    if len(commands) != 1:
        raise ValueError(f"{scanner} invocation is not the locked adapter command")
    argv = commands[0]
    required = {
        "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "--memory", "--cpus",
    }
    if argv[0] != "<trusted-container-runtime>" or not required.issubset(set(argv)):
        raise ValueError(f"{scanner} invocation is not the locked adapter command")
    if not any("@sha256:" in value for value in argv):
        raise ValueError(f"{scanner} invocation does not use an immutable image")
    required_mounts = (
        {"<materialized-input>:/iacgv-input:ro", "<bounded-output>:/iacgv-output:rw"}
        if scanner == "kics" else
        {"<materialized-input>:/work:ro", "<bounded-output>:/out:rw",
         "<protected-cache>:/cache:rw"}
    )
    if not required_mounts.issubset(set(argv)):
        raise ValueError(f"{scanner} invocation mount contract is incomplete")


def _validate_execution_attestation(runtime: dict) -> None:
    item = runtime["execution_attestation"]
    if type(item) is not dict or set(item) != ATTESTATION_FIELDS:
        raise ValueError("catalog execution attestation fields are invalid")
    if item["contract"] != "phase-e-control-fixture-execution-attestation-v1":
        raise ValueError("catalog execution attestation contract is unsupported")
    if item["status"] != "PROTECTED_LOCAL_EXECUTION":
        raise ValueError("catalog execution attestation status is invalid")
    try:
        datetime.fromisoformat(item["creation_timestamp"].replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("catalog execution timestamp is invalid") from exc
    if item["architecture"] != runtime["architecture"]:
        raise ValueError("catalog execution architecture is inconsistent")
    if item["protected_evidence_identity"] != runtime["protected_evidence_identity"]:
        raise ValueError("catalog execution protected evidence is inconsistent")
    expected_record_root = _canonical_sha(runtime["records"])
    if item["record_root_sha256"] != expected_record_root:
        raise ValueError("catalog execution record root is inconsistent")
    children = dict(item)
    identity = children.pop("attestation_identity")
    if identity != _canonical_sha(children):
        raise ValueError("catalog execution attestation identity is not canonical")
    if identity != APPROVED_EXECUTION_ATTESTATION_IDENTITY:
        raise ValueError("catalog execution attestation is not the reviewed execution")
    for field in ATTESTATION_FIELDS - {
        "contract", "status", "creation_timestamp", "architecture",
        "runtime_client_version", "runtime_server_version", "cache_attestation_identity",
    }:
        if not SHA256.fullmatch(str(item[field])):
            raise ValueError(f"catalog execution {field} is invalid")
    if item["cache_attestation_identity"] != (
        f"e02-local-acquisition-ed25519:{item['cache_attestation_public_key_sha256']}"
    ):
        raise ValueError("catalog cache attestation signer identity is invalid")
    if item["runner_implementation_sha256"] != hashlib.sha256(
        (ROOT / "tools/generate_catalog_runtime_evidence.py").read_bytes()
    ).hexdigest():
        raise ValueError("catalog execution runner implementation is not current")


def validate_catalog(path: Path) -> dict:
    data = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)
    if type(data) is not dict or data.get("contract") != "iac-guard-v-control-relationship-catalog-v3":
        raise ValueError("catalog contract is unsupported")
    if data.get("catalog_status") != "ADVISORY_ONLY":
        raise ValueError("scanner relationship catalog must remain advisory")
    _validate_locks(data.get("scanner_locks"))
    relationships = data.get("relationships")
    if type(relationships) is not list:
        raise ValueError("relationships must be a list")
    ids = set()
    exact_count = 0
    scanner_ids = {name: set() for name in SCANNERS}
    for item in relationships:
        if type(item) is not dict or set(item) != REQUIRED_RELATIONSHIP:
            raise ValueError("relationship fields do not match catalog-v2")
        relationship_id = item["relationship_id"]
        if type(relationship_id) is not str or not relationship_id or relationship_id in ids:
            raise ValueError("relationship ids must be nonempty and unique")
        ids.add(relationship_id)
        if item["classification"] not in CLASSES:
            raise ValueError("relationship classification is not closed")
        for scanner, field in zip(SCANNERS, ("checkov_rule_id", "kics_query_id", "trivy_check_id")):
            native_id = item[field]
            if type(native_id) is not str or not native_id or native_id in scanner_ids[scanner]:
                raise ValueError(f"{scanner} relationship id is missing or duplicated")
            scanner_ids[scanner].add(native_id)
            _validate_source(scanner, item["authoritative_sources"].get(scanner), data["scanner_locks"][scanner])
        if set(item["semantics"]) != set(SCANNERS):
            raise ValueError("every scanner requires documented semantics")
        if set(item["authoritative_sources"]) != set(SCANNERS):
            raise ValueError("every scanner requires source evidence")
        if set(item["fixtures"]) != set(FIXTURES):
            raise ValueError("relationship requires positive, negative, and boundary fixtures")
        for fixture in item["fixtures"].values():
            _safe_file(fixture)
        observations = item["expected_locked_observations"]
        if type(observations) is not dict or set(observations) != set(FIXTURES) or any(
            type(value) is not dict or set(value) != set(SCANNERS)
            or any(result not in {"FINDING", "NO_FINDING", "SUPPRESSED", "ERROR", "INCONCLUSIVE"} for result in value.values())
            for value in observations.values()
        ):
            raise ValueError("locked fixture observations are incomplete")
        if not item["resource_type_scope"]:
            raise ValueError("resource type scope cannot be empty")
        screening_status = item["validated_screening_status"]
        screening_blockers = item["validated_screening_blockers"]
        if screening_status not in SCREENING_STATUSES:
            raise ValueError("validated screening status is not closed")
        if (
            type(screening_blockers) is not list
            or any(type(value) is not str or not value for value in screening_blockers)
            or screening_blockers != sorted(set(screening_blockers))
        ):
            raise ValueError("validated screening blockers are invalid")
        if screening_status == "NOT_READY_FOR_VALIDATED_SCREENING" and not screening_blockers:
            raise ValueError("validated screening non-readiness requires blockers")
        if screening_status == "READY_FOR_VALIDATED_SCREENING" and screening_blockers:
            raise ValueError("validated screening readiness contradicts blockers")
        if item["classification"] == "EXACT":
            exact_count += 1
            if item["exact_blockers"]:
                raise ValueError("EXACT mapping cannot retain semantic blockers")
            _validate_exact_signoff(item["independent_reviewer_signoff"])
        elif not item["exact_blockers"]:
            raise ValueError("non-EXACT relationship must explain exact blockers")
    if exact_count > 5 or data.get("exact_mapping_count") != exact_count:
        raise ValueError("EXACT mapping count is invalid")
    reference = data.get("runtime_evidence")
    if type(reference) is not dict or set(reference) != {"path", "sha256"} or not SHA256.fullmatch(str(reference["sha256"])):
        raise ValueError("catalog runtime evidence reference is invalid")
    runtime_records = _validate_runtime(
        data, relationships, data["scanner_locks"], reference,
    )
    for item in relationships:
        records = tuple(
            value for key, value in runtime_records.items()
            if key[0] == item["relationship_id"]
        )
        definitive = len(records) == 9 and not any(
            value["execution_status"] != "PASS"
            or value["normalized_result"] not in {"FINDING", "NO_FINDING", "SUPPRESSED"}
            for value in records
        )
        if (
            not definitive
            and item["validated_screening_status"]
            != "NOT_READY_FOR_VALIDATED_SCREENING"
        ):
            raise ValueError(
                "incomplete locked execution is not ready for validated screening"
            )
        if (
            item["validated_screening_status"] == "READY_FOR_VALIDATED_SCREENING"
            and not definitive
        ):
            raise ValueError("validated screening requires definitive locked results")
        if item["classification"] == "EXACT" and (
            not definitive
            or item["validated_screening_status"] != "READY_FOR_VALIDATED_SCREENING"
        ):
            raise ValueError("EXACT mapping requires definitive locked scanner results")
    return data


def verify_sources(data: dict) -> None:
    for scanner, lock in data["scanner_locks"].items():
        ref = f"refs/tags/{lock['release_tag']}"
        command = ["git", "ls-remote", f"{lock['source_repository']}.git", ref]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        lines = [line.split() for line in result.stdout.splitlines() if line.strip()]
        if lines != [[lock["source_commit"], ref]]:
            raise ValueError(f"{scanner} release tag does not resolve to the reviewed commit")
    for relationship in data["relationships"]:
        for scanner, source in relationship["authoritative_sources"].items():
            with urllib.request.urlopen(source["url"], timeout=30) as response:
                raw = response.read()
            if hashlib.sha256(raw).hexdigest() != source["sha256"]:
                raise ValueError(f"{scanner} authoritative source bytes do not match")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("catalog", nargs="?", type=Path, default=ROOT / "controls/catalog-v1.yml")
    parser.add_argument("--verify-sources", action="store_true")
    args = parser.parse_args()
    data = validate_catalog(args.catalog)
    if args.verify_sources:
        verify_sources(data)
    print(f"CONTROL_CATALOG: PASS ({len(data['relationships'])} relationships, "
          f"{data['exact_mapping_count']} EXACT; sources="
          f"{'VERIFIED' if args.verify_sources else 'PINNED'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
