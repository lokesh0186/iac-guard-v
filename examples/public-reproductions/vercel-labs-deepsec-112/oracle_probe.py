from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from importlib.metadata import version
from pathlib import Path

from iac_guard_v.api import _untrusted_scan_request
from iac_guard_v.engine import attest_checkov_scan_plan, load_operator_verification_config
from iac_guard_v.enums import ScanRole
from iac_guard_v.models import RequiredGates
from iac_guard_v.oracles import ProtectedOracleRegistry, create_protected_oracle_request


CASES = (
    (
        "inline_privileged",
        "inline-privileged.yaml",
        "v1/Pod/default/inline-demo",
        "kubernetes_no_privileged_containers_v1",
    ),
    (
        "list_privileged",
        "list-privileged.yaml",
        "v1/Pod/default/list-demo",
        "kubernetes_no_privileged_containers_v1",
    ),
    (
        "windows_hostprocess",
        "windows-hostprocess.yaml",
        "v1/Pod/default/windows-demo",
        "kubernetes_no_windows_hostprocess_v1",
    ),
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkov-executable", type=Path, required=True)
    args = parser.parse_args()
    evidence_root = Path(__file__).resolve().parent
    fixture_root = evidence_root / "fixtures"

    with tempfile.TemporaryDirectory(prefix="iacgv-deepsec-112-") as temporary:
        workspace = Path(temporary)
        baseline = workspace / "baseline"
        candidate = workspace / "candidate"
        baseline.mkdir()
        candidate.mkdir()

        for source in sorted(fixture_root.glob("*.yaml")):
            text = source.read_text(encoding="utf-8")
            (baseline / source.name).write_text(
                f"{text.rstrip()}\n# reproduction-role: baseline\n",
                encoding="utf-8",
            )
            shutil.copyfile(source, candidate / source.name)

        baseline_discovery = attest_checkov_scan_plan(
            _untrusted_scan_request(
                baseline, baseline, args.checkov_executable, ("kubernetes",)
            )
        )
        candidate_discovery = attest_checkov_scan_plan(
            _untrusted_scan_request(
                candidate, candidate, args.checkov_executable, ("kubernetes",)
            )
        )
        required = RequiredGates(
            ("kubernetes_yaml_parse",),
            (
                "kubernetes_no_privileged_containers_v1",
                "kubernetes_no_windows_hostprocess_v1",
            ),
        )
        config = load_operator_verification_config(
            baseline_discovery.request,
            candidate_discovery.request,
            required_gates=required,
            frameworks=("kubernetes",),
        )
        candidate_plan = attest_checkov_scan_plan(
            candidate_discovery.request, config, ScanRole.CANDIDATE
        )
        snapshot = candidate_plan.sealed_snapshot
        if snapshot is None:
            raise RuntimeError("candidate snapshot was not sealed")
        resources = {
            resource.resource_address: resource for resource in snapshot.resources
        }

        registry = ProtectedOracleRegistry()
        results = []
        for case_id, file_name, resource_identity, oracle_id in CASES:
            source = fixture_root / file_name
            resource = resources[resource_identity]
            oracle_result = registry.execute(
                create_protected_oracle_request(
                    oracle_id=oracle_id,
                    snapshot=snapshot,
                    file_path=file_name,
                    artifact_kind=resource.artifact_kind,
                    resource_identity=resource_identity,
                )
            )
            results.append(
                {
                    "id": case_id,
                    "fixture": f"fixtures/{file_name}",
                    "fixture_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "oracle_result_projection": {
                        "oracle_id": oracle_result.oracle_id,
                        "contract_version": oracle_result.contract_version,
                        "protected_policy_sha256": oracle_result.protected_policy_sha256,
                        "role": oracle_result.role.value,
                        "file_path": oracle_result.file_path,
                        "artifact_kind": oracle_result.artifact_kind.value,
                        "resource_identity": oracle_result.resource_identity,
                        "status": oracle_result.status.value,
                        "reason": oracle_result.reason,
                        "observations": [
                            item.canonical_dict() for item in oracle_result.observations
                        ],
                        "execution_controls": list(oracle_result.execution_controls),
                        "authoritative_reference": oracle_result.authoritative_reference,
                    },
                }
            )

    print(
        json.dumps(
            {
                "iac_guard_v_version": version("iac-guard-v"),
                "checkov_version": "3.3.0",
                "result_kind": "protected-oracle-semantic-projection-v1",
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
