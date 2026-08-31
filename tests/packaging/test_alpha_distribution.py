"""Public 0.1.0a9 distribution and clean-install boundary."""
from __future__ import annotations

import email
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet


ROOT = Path(__file__).parents[2]
VERSION = "0.1.0a9"
FORBIDDEN_DISTRIBUTION_PARTS = {
    "benchmark",
    "runs",
    "results",
    "prompts",
    "scanners",
    "scripts",
    "research",
    "tests",
    "tools",
    "controls",
    "paper.pdf",
}
SENSITIVE_DISTRIBUTION_PARTS = {
    "A8_NEXT_TIER_A_EVIDENCE",
    "A9_NATIVE_PROPERTY_DESIGN",
    "a8-implementation",
    "a9-implementation",
    "a9-product-value-audit",
    "a9-release",
    "external-impact-evidence",
    "paperoutreachstrat",
    "private-screening",
    "private-research",
    "implementation-evidence",
    "release-working-evidence",
    "tmp",
}
ALLOWED_SDIST_ROOT_FILES = {
    ".gitignore",
    "CHANGELOG.md",
    "CITATION.cff",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "PKG-INFO",
    "README.md",
    "RESEARCH_SNAPSHOT.md",
    "ROADMAP.md",
    "SECURITY.md",
    "pyproject.toml",
}
ALLOWED_SDIST_EXACT_FILES = {
    "packaging/iac_guard_v_no_bytecode.pth",
    "docs/ADVANCED_INSTALLATION.md",
    "docs/ALPHA_RELEASE_CHECKLIST.md",
    "docs/CANDIDATE_ACCEPTANCE.md",
    "docs/HELM_MATERIALIZATION.md",
    "docs/KUSTOMIZE_MATERIALIZATION.md",
    "docs/NAMESPACE_PROVENANCE.md",
    "docs/NATIVE_PROPERTIES.md",
    "docs/RELEASE_NOTES_0.1.0a9.md",
    "docs/SECURITY_MODEL.md",
    "docs/SUPPORTED_SCOPE.md",
    "docs/spec/THREAT_MODEL.md",
}
ALLOWED_SDIST_PREFIXES = (
    "src/iac_guard_v/",
    "examples/checkov-before-after/",
)
TEST_CAPABILITY_MARKERS = (
    b"phase_e_test_support",
    b"make_test_container_runtime",
    b"execute_tflint_fixture",
    b"_normalize_for_test",
    b"_create_test_protected_checks_cache_identity",
    b"def create_oracle_result",
)
REQUIRED_WHEEL_FILES = {
    "iac_guard_v/workflow.py",
    "iac_guard_v/reporters/sarif.py",
    "iac_guard_v/reporters/markdown.py",
    "iac_guard_v/reporters/junit.py",
    "iac_guard_v/schemas/report-v1.schema.json",
    "iac_guard_v/schemas/config-v1.schema.json",
    "iac_guard_v/schemas/helm-acceptance-v1.schema.json",
    "iac_guard_v/oracles/policies.json",
    "iac_guard_v/graph_evidence.py",
    "iac_guard_v/helm.py",
    "iac_guard_v/kustomize.py",
    "iac_guard_v/kustomize-engine-v5.7.1.json",
    "iac_guard_v/scanner_core.py",
    "iac_guard_v/terraform_parser.py",
    "iac_guard_v/native_properties/__init__.py",
    "iac_guard_v/native_properties/__main__.py",
    "iac_guard_v/native_properties/engine.py",
    "iac_guard_v/native_properties/evidence.py",
    "iac_guard_v/native_properties/model.py",
    "iac_guard_v/native_properties/network_policy.py",
    "iac_guard_v/native_properties/prometheus_operator.py",
    "iac_guard_v/native_properties/public.py",
    "iac_guard_v/native_properties/rbac.py",
    "iac_guard_v/native_properties/registry.py",
    "iac_guard_v/native_properties/report.py",
    "iac_guard_v/native_properties/selectors.py",
    "iac_guard_v/native_properties/services.py",
    "iac_guard_v/native_properties/terraform.py",
    "iac_guard_v/native_properties/universe.py",
    "iac_guard_v/native_properties/contracts/prometheus-operator-v1.json",
    "iac_guard_v/schemas/native-property-request-v1.schema.json",
    "iac_guard_v/schemas/native-property-report-v1.schema.json",
    "iac_guard_v/examples/checkov-before-after/before.tf",
    "iac_guard_v/examples/checkov-before-after/after.tf",
    "iac_guard_v_no_bytecode.pth",
}


@pytest.fixture(scope="module")
def alpha_artifacts(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    output = tmp_path_factory.mktemp("alpha-dist")
    assert tuple(output.iterdir()) == ()
    completed = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    wheel = next(output.glob(f"iac_guard_v-{VERSION}-py3-none-any.whl"))
    sdist = next(output.glob(f"iac_guard_v-{VERSION}.tar.gz"))
    assert set(output.iterdir()) == {wheel, sdist}
    assert output != ROOT / "dist"
    return wheel, sdist


def _forbidden_path(name: str) -> bool:
    parts = Path(name).parts
    # sdists have one versioned root directory; wheels do not.
    relative = parts[1:] if parts and parts[0].startswith("iac_guard_v-") else parts
    return bool(relative and relative[0] in FORBIDDEN_DISTRIBUTION_PARTS)


def _sdist_relative(name: str) -> str:
    parts = Path(name).parts
    if parts and parts[0].startswith("iac_guard_v-"):
        parts = parts[1:]
    return "/".join(parts)


def _approved_sdist_file(name: str) -> bool:
    relative = _sdist_relative(name)
    return (
        relative in ALLOWED_SDIST_ROOT_FILES
        or relative in ALLOWED_SDIST_EXACT_FILES
        or relative.startswith(ALLOWED_SDIST_PREFIXES)
    )


def test_alpha_metadata_and_version_are_consistent(alpha_artifacts) -> None:
    wheel, _sdist = alpha_artifacts
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = email.message_from_bytes(archive.read(metadata_name))
    assert metadata["Name"] == "iac-guard-v"
    assert metadata["Version"] == VERSION
    assert SpecifierSet(metadata["Requires-Python"]) == SpecifierSet(">=3.10,<3.14")
    assert "Development Status :: 3 - Alpha" in metadata.get_all("Classifier")
    assert f'__version__ = "{VERSION}"' in (
        ROOT / "src/iac_guard_v/__init__.py"
    ).read_text(encoding="utf-8")


def test_wheel_and_sdist_are_public_product_only(alpha_artifacts) -> None:
    wheel, sdist = alpha_artifacts
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = tuple(archive.namelist())
        assert archive.read("iac_guard_v_no_bytecode.pth") == (
            b"import sys; sys.dont_write_bytecode = True\n"
        )
        product_python = b"\n".join(
            archive.read(name) for name in wheel_names if name.endswith(".py")
        )
    with tarfile.open(sdist, "r:gz") as archive:
        members = tuple(archive.getmembers())
        sdist_names = tuple(member.name for member in members)
        sdist_files = tuple(member.name for member in members if member.isfile())
        product_python += b"\n".join(
            archive.extractfile(member).read()
            for member in members
            if member.isfile() and member.name.endswith(".py")
        )

    assert not any(_forbidden_path(name) for name in (*wheel_names, *sdist_names))
    assert not any(
        set(Path(_sdist_relative(name)).parts) & SENSITIVE_DISTRIBUTION_PARTS
        for name in sdist_files
    )
    assert all(_approved_sdist_file(name) for name in sdist_files)
    assert not any(marker in product_python for marker in TEST_CAPABILITY_MARKERS)
    assert REQUIRED_WHEEL_FILES <= set(wheel_names)
    assert "iac_guard_v/oracles/preconditions.py" in wheel_names
    assert any(name.endswith(".dist-info/licenses/LICENSE") for name in wheel_names)
    assert any(name.endswith(".dist-info/licenses/NOTICE") for name in wheel_names)

    public_sdist_files = {
        Path(name).name for name in sdist_names if not name.endswith("/")
    }
    assert {
        "README.md",
        "RESEARCH_SNAPSHOT.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "ROADMAP.md",
        "CHANGELOG.md",
        "NOTICE",
        "CITATION.cff",
        "before.tf",
        "after.tf",
    } <= public_sdist_files
    assert "LICENSE" in public_sdist_files
    assert any(name.endswith("docs/spec/THREAT_MODEL.md") for name in sdist_names)
    assert any(name.endswith("docs/ALPHA_RELEASE_CHECKLIST.md") for name in sdist_names)
    assert any(name.endswith("docs/ADVANCED_INSTALLATION.md") for name in sdist_names)
    assert any(name.endswith("docs/SECURITY_MODEL.md") for name in sdist_names)
    assert any(name.endswith("docs/SUPPORTED_SCOPE.md") for name in sdist_names)
    assert any(name.endswith("docs/KUSTOMIZE_MATERIALIZATION.md") for name in sdist_names)
    assert any(name.endswith("docs/CANDIDATE_ACCEPTANCE.md") for name in sdist_names)
    assert any(name.endswith("docs/RELEASE_NOTES_0.1.0a9.md") for name in sdist_names)
    assert any(name.endswith("docs/NATIVE_PROPERTIES.md") for name in sdist_names)


def test_sdist_exact_allowlist_rejects_recursive_readme_license_decoys(
    tmp_path: Path,
) -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    sdist_config = configuration["tool"]["hatch"]["build"]["targets"]["sdist"]
    assert "include" not in sdist_config
    selected = tuple(sdist_config["only-include"])
    assert "README.md" in selected
    assert "LICENSE" in selected

    project = tmp_path / "project"
    project.mkdir()
    for relative in selected:
        source = ROOT / relative
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)

    decoys = (
        "private-screening/README.md",
        "research/README.md",
        "design/LICENSE",
        "nested/private/LICENSE.txt",
    )
    for relative in decoys:
        path = project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("must not ship\n", encoding="utf-8")

    output = tmp_path / "dist"
    completed = subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--outdir", str(output)],
        cwd=project,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    archive_path = next(output.glob(f"iac_guard_v-{VERSION}.tar.gz"))
    with tarfile.open(archive_path, "r:gz") as archive:
        names = {_sdist_relative(name) for name in archive.getnames()}

    assert "README.md" in names
    assert "LICENSE" in names
    assert not set(decoys) & names


def test_fresh_artifacts_have_stable_nonempty_hashes(alpha_artifacts) -> None:
    wheel, sdist = alpha_artifacts
    hashes = {
        artifact.name: hashlib.sha256(artifact.read_bytes()).hexdigest()
        for artifact in (wheel, sdist)
    }
    assert set(hashes) == {
        f"iac_guard_v-{VERSION}-py3-none-any.whl",
        f"iac_guard_v-{VERSION}.tar.gz",
    }
    assert all(len(value) == 64 and value != "0" * 64 for value in hashes.values())


def test_wheel_installs_and_runs_outside_source_checkout(
    alpha_artifacts, tmp_path: Path,
) -> None:
    wheel, _sdist = alpha_artifacts
    installed = tmp_path / "installed"
    install = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-compile",
            "--target",
            str(installed),
            str(wheel),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert install.returncode == 0, install.stderr
    environment = {
        **os.environ,
        "PATH": "",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    def run(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        script = (
            "import sys;"
            f"sys.path.insert(0,{str(installed)!r});"
            "from iac_guard_v.cli import main;"
            f"raise SystemExit(main({arguments!r}))"
        )
        return subprocess.run(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    version = run(["--version"])
    assert version.returncode == 0, version.stderr
    assert version.stdout.strip() == f"iac-guard {VERSION}"

    help_result = run(["--help"])
    assert help_result.returncode == 0, help_result.stderr
    for command in ("scan", "differential", "lock", "init", "pr"):
        assert command in help_result.stdout

    demo = run(["demo", "--format", "json"])
    assert demo.returncode == 0, demo.stderr
    payload = json.loads(demo.stdout)
    assert payload["verdict"] == "INCONCLUSIVE"
    assert payload["diagnostic"]["reason_code"] == "OFFLINE_DEMO_ONLY"

    doctor = run(["doctor", "--format", "json"])
    assert doctor.returncode == 3, doctor.stderr
    diagnosis = json.loads(doctor.stdout)
    assert diagnosis["product_version"] == VERSION
    assert diagnosis["checkov"]["reason_code"] == "CHECKOV_NOT_FOUND"
    assert diagnosis["hardened_container"]["status"] == "INCONCLUSIVE"

    native_root = tmp_path / "native-rendered"
    native_root.mkdir()
    (native_root / "objects.yaml").write_text(
        """apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec: {template: {metadata: {labels: {app: demo}}, spec: {containers: [{name: app, image: example}]}}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: app}
spec: {podSelector: {matchLabels: {app: demo}}, ingress: []}
""",
        encoding="utf-8",
    )
    native_config = tmp_path / "native.json"
    native_config.write_text(json.dumps({
        "schema_version": "native-property-request-v1",
        "root": "native-rendered",
        "artifact_class": "kubernetes_rendered",
        "requests": [{
            "request_id": "selection",
            "property_id": "IACGV_K8S_WORKLOAD_POLICY_SELECTED_V1",
            "property_version": "1",
            "subject_identity": "apps/v1/Deployment/default/app",
            "parameters": {},
        }],
    }), encoding="utf-8")
    native_script = (
        "import sys;"
        f"sys.path.insert(0,{str(installed)!r});"
        "from iac_guard_v.native_properties.__main__ import main;"
        f"raise SystemExit(main(['--config',{str(native_config)!r},'--format','json']))"
    )
    native = subprocess.run(
        [sys.executable, "-c", native_script], cwd=tmp_path, env=environment,
        capture_output=True, text=True, check=False, timeout=60,
    )
    assert native.returncode == 0, native.stderr
    assert json.loads(native.stdout)["summary"]["SATISFIED"] == 1
    assert not tuple(installed.rglob("__pycache__"))


def test_public_alpha_docs_state_current_boundaries() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for statement in (
        "Verify that an infrastructure-as-code security fix actually fixed",
        "python -m pip install iac-guard-v==0.1.0a9",
        "iac-guard demo",
        "Coder `demo-env-templates` PR #180",
        "25cff91e2c039ddc648541a06191f4b9b9a813b7",
        "technical alpha",
        "reduced-isolation",
        "trusted local input only",
        "may remain quiet for several minutes",
        "docs/ADVANCED_INSTALLATION.md",
        "docs/SUPPORTED_SCOPE.md",
        "docs/SECURITY_MODEL.md",
        "docs/KUSTOMIZE_MATERIALIZATION.md",
        "Checkov as the only authoritative scanner path",
        "witness-first, scanner-independent native property contracts",
        "general Helm interpretation",
        "awaiting a public arXiv identifier",
    ):
        assert statement in readme
    assert "After publication, replace the local wheel path" not in readme
    assert "zero `EXACT` mappings" not in readme
    assert "MANIFEST_ROOT" not in readme
    assert "V7 consensus" not in readme
    assert "arXiv:ADD" not in readme
    assert "XXXX.XXXXX" not in readme
    assert "not yet a published release" not in readme
    assert "package version `0.1.0a9` is not published" not in readme
    assert "10.5281/zenodo.22167878" in readme

    advanced = (ROOT / "docs/ADVANCED_INSTALLATION.md").read_text(encoding="utf-8")
    for statement in (
        "uv python find --managed-python 3.12",
        "--copies --without-pip",
        "PYTHONDONTWRITEBYTECODE=1",
        "bc-python-hcl2",
        "may remain quiet for several minutes",
        "iac-guard-v==0.1.0a9",
    ):
        assert statement in advanced

    supported = (ROOT / "docs/SUPPORTED_SCOPE.md").read_text(encoding="utf-8")
    assert "zero `EXACT` mappings" in supported
    assert "OpenTofu `.tofu` / `.tofu.json`" in supported
    assert "production hostile-input support" in supported
    assert "This is not general Helm interpretation" in supported
    assert "Advisory/future adapter work" in supported

    kustomize = (ROOT / "docs/KUSTOMIZE_MATERIALIZATION.md").read_text(
        encoding="utf-8"
    )
    assert "not general Kustomize support" in kustomize
    assert "remote URLs" in kustomize
    assert "Helm chart inflation" in kustomize

    release_notes = (ROOT / "docs/RELEASE_NOTES_0.1.0a9.md").read_text(
        encoding="utf-8"
    )
    for statement in (
        "witness-first native property framework",
        "NetworkPolicy selection and direction-specific isolation",
        "Service-to-workload and ServicePort-to-container-port resolution",
        "Bounded ServiceMonitor and PodMonitor composition",
        "RBAC binding identity and scope relationships",
        "Exact source-local Terraform resource-reference relationships",
        "Mechanical property violations do not automatically establish project defects",
        "general Kubernetes network reachability",
        "KICS and Trivy remain advisory",
    ):
        assert statement in release_notes

    security_model = (ROOT / "docs/SECURITY_MODEL.md").read_text(encoding="utf-8")
    assert "V7 consensus is disconnected" in security_model
    assert "There is no silent downgrade" in security_model
    assert "no telemetry, model-provider SDK" in security_model

    security_policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert f"IaC-Guard-V `{VERSION}` is a technical alpha" in security_policy
    assert "Checkov `3.3.0` scanner contract" in security_policy

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [0.1.0a1] - 2026-08-20" in changelog
    assert "correction released in `0.1.0a7`" in changelog
    assert "The Unreleased correction above" not in changelog
    assert "prepared, not published" not in changelog
    assert "10.5281/zenodo.22167878" in changelog


def test_public_deepsec_evidence_is_sanitized_and_bound() -> None:
    evidence = (
        ROOT / "examples/public-reproductions/vercel-labs-deepsec-112"
    )
    matcher = json.loads((evidence / "matcher-result.json").read_text(encoding="utf-8"))
    oracle = json.loads((evidence / "oracle-result.json").read_text(encoding="utf-8"))

    assert matcher["base_sha"] == "97ebd04b455a492dfd5b9ad86f2dd9cf8b05fa04"
    assert matcher["head_sha"] == "783195c4b2a1da94c23f5cacf55114a190c2032f"
    matcher_results = {item["id"]: item for item in matcher["results"]}
    assert matcher_results["block_privileged"]["matches"][0]["pattern"] == (
        "privileged container"
    )
    assert matcher_results["inline_privileged"]["matches"] == []

    assert oracle["result_kind"] == "protected-oracle-semantic-projection-v1"
    oracle_results = {item["id"]: item for item in oracle["results"]}
    inline = oracle_results["inline_privileged"]["oracle_result_projection"]
    assert inline["oracle_id"] == "kubernetes_no_privileged_containers_v1"
    assert inline["status"] == "FAIL"
    assert inline["reason"] == "ASSERTION_VIOLATED"

    for payload in (matcher, oracle):
        for item in payload["results"]:
            fixture = evidence / item["fixture"]
            assert hashlib.sha256(fixture.read_bytes()).hexdigest() == item["fixture_sha256"]

    public_bytes = b"\n".join(
        path.read_bytes() for path in evidence.rglob("*") if path.is_file()
    )
    for forbidden in (
        b"/Users/", b"iac-guard-v-private-screening", b"implementation_build_identity",
        b"sealed_snapshot_identity",
    ):
        assert forbidden not in public_bytes


def test_public_otterworks_evidence_is_sanitized_and_bound() -> None:
    evidence = (
        ROOT
        / "examples/public-reproductions/"
        "cognition-partner-workshops-otterworks-977"
    )
    report_path = evidence / "report.json"
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)

    assert hashlib.sha256(report_bytes).hexdigest() == (
        "51cc99498b6762461abc14b20f205a2ba2f76ad00d7d87ad6274201b8c96bc19"
    )
    assert report["schema_version"] == "report-v1"
    assert report["verdict"] == "VERIFIED"
    assert report["exit_code"] == 0
    verification = report["verification"]
    assert verification["scanner_integrity"]["status"] == "PASS"
    assert verification["regression"]["status"] == "PASS"
    assert verification["targets"][0]["identity"]["rule_id"] == "CKV2_AWS_6"
    assert verification["targets"][0]["identity"]["scope"] == (
        "aws_s3_bucket.audit_archive"
    )
    assert verification["targets"][0]["outcome"] == "FIXED"

    expected_files = {
        "audit_archive.tf",
        "cron-cleanup.tf",
        "main.tf",
        "outputs.tf",
        "variables.tf",
        "versions.tf",
    }
    for role in ("baseline", "candidate"):
        classifications = verification[f"{role}_snapshot"]["classifications"]
        by_path = {item["file_path"]: item for item in classifications}
        assert set(by_path) == expected_files
        for path in ("outputs.tf", "variables.tf", "versions.tf"):
            assert by_path[path]["coverage_kind"] == "STRUCTURAL_ONLY"

    candidate_evaluation = next(
        evaluation
        for evaluation in verification["candidate_run"]["evaluations"]
        if evaluation["rule_id"] == "CKV2_AWS_6"
        and evaluation["resource_address"] == "aws_s3_bucket.audit_archive"
        and evaluation["native_result"] == "PASSED"
    )
    graph = candidate_evaluation["graph_evidence"]
    assert graph["status"] == "PASS"
    assert graph["reason_code"] == "GRAPH_EVIDENCE_COMPLETE"
    assert {item["resource_address"] for item in graph["participants"]} == {
        "aws_s3_bucket.audit_archive",
        "aws_s3_bucket_public_access_block.audit_archive",
    }
    assert graph["edges"][0]["relation_key"] == (
        "resource.bucket:aws_s3_bucket.audit_archive"
    )

    public_bytes = b"\n".join(
        path.read_bytes() for path in evidence.rglob("*") if path.is_file()
    )
    for forbidden in (
        b"/Users/",
        b"/tmp/",
        b"iac-guard-v-private-screening",
        b"EB-1A",
    ):
        assert forbidden not in public_bytes


def test_public_teranode_evidence_is_sanitized_and_bound() -> None:
    evidence = (
        ROOT
        / "examples/public-reproductions/"
        "bsv-blockchain-teranode-1617"
    )
    report_path = evidence / "report.json"
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)

    assert hashlib.sha256(report_bytes).hexdigest() == (
        "a0f5b839e370430e2904096220c4d420e80e7e6d49b5c11096d7f3a02e5b8283"
    )
    assert report["schema_version"] == "report-v1"
    assert report["verdict"] == "VERIFIED"
    assert report["exit_code"] == 0
    verification = report["verification"]
    assert verification["scanner_integrity"]["status"] == "PASS"
    assert verification["regression"]["status"] == "PASS"
    assert verification["validators"] == [
        {
            "detail": "files=3",
            "gate_id": "kubernetes_yaml_parse",
            "reason_code": "VALIDATOR_COMPLETED",
            "status": "PASS",
        }
    ]
    target = verification["targets"][0]
    assert target["identity"]["rule_id"] == "CKV2_K8S_6"
    assert target["identity"]["scope"] == (
        "apps/v1/Deployment/default/kafka-shared"
    )
    assert target["outcome"] == "FIXED"

    candidate_evaluation = next(
        evaluation
        for evaluation in verification["candidate_run"]["evaluations"]
        if evaluation["rule_id"] == "CKV2_K8S_6"
        and evaluation["resource_address"]
        == "apps/v1/Deployment/default/kafka-shared"
        and evaluation["native_result"] == "PASSED"
    )
    graph = candidate_evaluation["graph_evidence"]
    assert graph["status"] == "PASS"
    assert graph["reason_code"] == "GRAPH_EVIDENCE_COMPLETE"
    assert {item["resource_address"] for item in graph["participants"]} == {
        "apps/v1/Deployment/default/kafka-shared",
        "networking.k8s.io/v1/NetworkPolicy/default/kafka-shared",
    }
    assert len(graph["edges"]) == 1
    edge = graph["edges"][0]
    assert edge["relation_type"] == "kubernetes_network_policy_selector"
    assert edge["source"]["resource_address"] == (
        "networking.k8s.io/v1/NetworkPolicy/default/kafka-shared"
    )
    assert edge["target"]["resource_address"] == (
        "apps/v1/Deployment/default/kafka-shared"
    )

    assert verification["baseline_run"]["coverage"]["files_parsed"] == 2
    assert verification["baseline_run"]["coverage"]["files_eligible"] == 2
    assert verification["candidate_run"]["coverage"]["files_parsed"] == 3
    assert verification["candidate_run"]["coverage"]["files_eligible"] == 3

    public_bytes = b"\n".join(
        path.read_bytes() for path in evidence.rglob("*") if path.is_file()
    )
    for forbidden in (
        b"/Users/",
        b"/tmp/",
        b"iac-guard-v-private-screening",
        b"EB-1A",
    ):
        assert forbidden not in public_bytes


def test_release_checklist_requires_paper_absence_without_fake_identifier() -> None:
    checklist = (ROOT / "docs/ALPHA_RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    assert "rm -rf dist build" in checklist
    assert "`paper.pdf` is absent from the current tree" in checklist
    assert "must not publish" in checklist
    assert "Do not push a tag" in checklist
    assert not (ROOT / "paper.pdf").exists()


def test_public_ci_actions_are_immutable() -> None:
    workflow = (ROOT / ".github/workflows/python-compat.yml").read_text(encoding="utf-8")
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in workflow
    assert "actions/checkout@v" not in workflow
    assert "actions/setup-python@v" not in workflow


def test_checkov_before_after_fixture_is_one_narrow_repair() -> None:
    before = (ROOT / "examples/checkov-before-after/before.tf").read_text(encoding="utf-8")
    after = (ROOT / "examples/checkov-before-after/after.tf").read_text(encoding="utf-8")
    assert 'resource "aws_s3_bucket_public_access_block" "example"' in before
    assert before.replace("block_public_acls       = false", "block_public_acls       = true") == after
