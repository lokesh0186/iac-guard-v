from __future__ import annotations

import importlib.util
import hashlib
import json
import copy
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_catalog", ROOT / "tools/check_catalog.py")
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def _catalog(tmp_path: Path, mutate) -> Path:
    data = yaml.safe_load((ROOT / "controls/catalog-v1.yml").read_text())
    mutate(data)
    target = tmp_path / "catalog.yml"
    target.write_text(yaml.safe_dump(data, sort_keys=False))
    return target


def _runtime_catalog(tmp_path: Path, mutate, monkeypatch) -> Path:
    copied_root = tmp_path / "runtime-root"
    (copied_root / "controls").mkdir(parents=True)
    (copied_root / "tools").mkdir()
    shutil.copyfile(
        ROOT / "tools/generate_catalog_runtime_evidence.py",
        copied_root / "tools/generate_catalog_runtime_evidence.py",
    )
    shutil.copytree(ROOT / "controls/fixtures", copied_root / "controls/fixtures")
    evidence = json.loads(
        (ROOT / "controls/runtime-evidence-v1.json").read_text(encoding="utf-8")
    )
    mutate(evidence)
    if "evidence_root_sha256" in evidence:
        payload = dict(evidence)
        payload.pop("evidence_root_sha256")
        evidence["evidence_root_sha256"] = CHECKER._canonical_sha(payload)
    runtime = copied_root / "controls/runtime-evidence-v1.json"
    runtime.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
    catalog = yaml.safe_load((ROOT / "controls/catalog-v1.yml").read_text())
    catalog["runtime_evidence"]["sha256"] = hashlib.sha256(runtime.read_bytes()).hexdigest()
    path = copied_root / "controls/catalog-v1.yml"
    path.write_text(yaml.safe_dump(catalog, sort_keys=False), encoding="utf-8")
    monkeypatch.setattr(CHECKER, "ROOT", copied_root)
    return path


def test_catalog_is_valid_and_deliberately_has_no_exact_mapping() -> None:
    data = CHECKER.validate_catalog(ROOT / "controls/catalog-v1.yml")
    assert data["exact_mapping_count"] == 0
    assert {item["classification"] for item in data["relationships"]} == {"OVERLAPPING"}


def test_exact_mapping_without_independent_signoff_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["relationships"][0]["classification"] = "EXACT"
        data["relationships"][0]["exact_blockers"] = []
        data["exact_mapping_count"] = 1

    with pytest.raises(ValueError, match="mechanically verified sign-off"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_mutable_source_identity_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["scanner_locks"]["kics"]["source_commit"] = "main"

    with pytest.raises(ValueError, match="reviewed lock"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_unknown_relationship_class_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["relationships"][0]["classification"] = "SAME_ENOUGH"

    with pytest.raises(ValueError, match="classification"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_missing_boundary_fixture_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["relationships"][0]["fixtures"]["boundary"] = "controls/fixtures/absent.yml"

    with pytest.raises(ValueError, match="fixture"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("repository", "https://github.com/attacker/checkov", "not approved"),
        ("commit", "a" * 40, "not the release commit"),
        ("url", "https://example.invalid/unrelated", "not commit-pinned"),
        ("sha256", "b" * 64, "reviewed source"),
    ),
)
def test_forged_source_evidence_is_rejected(
    tmp_path: Path, field: str, value: str, message: str,
) -> None:
    def mutate(data):
        data["relationships"][0]["authoritative_sources"]["checkov"][field] = value

    with pytest.raises(ValueError, match=message):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_random_valid_looking_release_commit_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        data["scanner_locks"]["checkov"]["source_commit"] = "a" * 40
        data["scanner_locks"]["checkov"]["tag_ref_commit"] = "a" * 40

    with pytest.raises(ValueError, match="reviewed lock"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


def test_runtime_evidence_digest_and_complete_matrix_are_required(
    tmp_path: Path, monkeypatch,
) -> None:
    source_root = ROOT
    copied_root = tmp_path / "root"
    (copied_root / "controls").mkdir(parents=True)
    shutil.copytree(source_root / "controls/fixtures", copied_root / "controls/fixtures")
    evidence = json.loads(
        (source_root / "controls/runtime-evidence-v1.json").read_text(encoding="utf-8")
    )
    evidence["records"].pop()
    payload = dict(evidence)
    payload.pop("evidence_root_sha256")
    evidence["evidence_root_sha256"] = CHECKER._canonical_sha(payload)
    runtime = copied_root / "controls/runtime-evidence-v1.json"
    runtime.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
    catalog = yaml.safe_load(
        (source_root / "controls/catalog-v1.yml").read_text(encoding="utf-8")
    )
    catalog["runtime_evidence"]["sha256"] = hashlib.sha256(runtime.read_bytes()).hexdigest()
    path = copied_root / "controls/catalog-v1.yml"
    path.write_text(yaml.safe_dump(catalog, sort_keys=False), encoding="utf-8")
    monkeypatch.setattr(CHECKER, "ROOT", copied_root)
    with pytest.raises(ValueError, match="does not cover every"):
        CHECKER.validate_catalog(path)


def test_runtime_evidence_outer_digest_is_enforced(tmp_path: Path) -> None:
    def mutate(data):
        data["runtime_evidence"]["sha256"] = "0" * 64

    with pytest.raises(ValueError, match="file digest"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (lambda data: data.update(contract="wrong"), "contract"),
        (lambda data: data.update(catalog_status="TRUST_ME"), "advisory"),
        (lambda data: data.update(relationships={}), "list"),
        (lambda data: data["relationships"][0].pop("semantics"), "fields"),
        (
            lambda data: data["relationships"][1].update(
                relationship_id=data["relationships"][0]["relationship_id"]
            ),
            "unique",
        ),
        (lambda data: data["relationships"][0].update(relationship_id=""), "unique"),
        (
            lambda data: data["relationships"][1].update(
                checkov_rule_id=data["relationships"][0]["checkov_rule_id"]
            ),
            "duplicated",
        ),
        (lambda data: data["relationships"][0].update(semantics={}), "semantics"),
        (
            lambda data: data["relationships"][0].update(authoritative_sources={}),
            "source evidence",
        ),
        (lambda data: data["relationships"][0].update(fixtures={}), "fixtures"),
        (
            lambda data: data["relationships"][0].update(
                expected_locked_observations={}
            ),
            "observations",
        ),
        (lambda data: data["relationships"][0].update(resource_type_scope=[]), "scope"),
        (lambda data: data["relationships"][0].update(exact_blockers=[]), "blockers"),
        (lambda data: data.update(exact_mapping_count=1), "count"),
        (lambda data: data.update(runtime_evidence={}), "reference"),
    ),
)
def test_closed_catalog_graph_rejects_structural_mutations(
    tmp_path: Path, mutate, message: str,
) -> None:
    with pytest.raises((ValueError, AttributeError), match=message):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (lambda locks: locks.pop("trivy"), "three scanner locks"),
        (lambda locks: locks["checkov"].pop("policy_identity"), "incomplete"),
        (
            lambda locks: locks["checkov"].update(tag_ref_commit="0" * 40),
            "tag relation",
        ),
        (lambda locks: locks["checkov"].update(policy_identity=""), "missing"),
        (
            lambda locks: locks["checkov"].update(runtime_policy_digest="bad"),
            "runtime identity",
        ),
    ),
)
def test_scanner_lock_contract_rejects_incomplete_evidence(mutate, message: str) -> None:
    data = yaml.safe_load((ROOT / "controls/catalog-v1.yml").read_text())
    locks = copy.deepcopy(data["scanner_locks"])
    mutate(locks)
    with pytest.raises(ValueError, match=message):
        CHECKER._validate_locks(locks)


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (lambda source: source.pop("sha256"), "incomplete"),
        (lambda source: source.update(relative_path="../escape"), "unsafe"),
        (
            lambda source: source.update(source_attestation_identity="0" * 64),
            "not canonical",
        ),
    ),
)
def test_source_attestation_rejects_incomplete_children(mutate, message: str) -> None:
    data = yaml.safe_load((ROOT / "controls/catalog-v1.yml").read_text())
    source = copy.deepcopy(data["relationships"][0]["authoritative_sources"]["checkov"])
    mutate(source)
    with pytest.raises(ValueError, match=message):
        CHECKER._validate_source("checkov", source, data["scanner_locks"]["checkov"])


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (lambda runtime: runtime.update(contract="wrong"), "contract"),
        (lambda runtime: runtime.update(records={}), "records"),
        (lambda runtime: runtime["records"][0].pop("native_result"), "fields"),
        (
            lambda runtime: runtime["records"].append(copy.deepcopy(runtime["records"][0])),
            "duplicate",
        ),
        (
            lambda runtime: runtime["records"][0].update(fixture_sha256="0" * 64),
            "fixture digest",
        ),
        (
            lambda runtime: runtime["records"][0].update(scanner_version="wrong"),
            "version",
        ),
        (
            lambda runtime: runtime["records"][0].update(policy_identity="wrong"),
            "policy identity",
        ),
        (
            lambda runtime: runtime["records"][0].update(environment_identity="0" * 64),
            "environment identity",
        ),
        (
            lambda runtime: runtime["records"][0].update(
                expected_relationship_observation="INCONCLUSIVE"
            ),
            "expectation",
        ),
        (
            lambda runtime: runtime["records"][0].update(normalized_result="INCONCLUSIVE"),
            "contradicts",
        ),
        (
            lambda runtime: runtime["records"][0].update(invocation_identity="bad"),
            "invocation_identity",
        ),
    ),
)
def test_runtime_evidence_rejects_every_unbound_child(
    tmp_path: Path, monkeypatch, mutate, message: str,
) -> None:
    path = _runtime_catalog(tmp_path, mutate, monkeypatch)
    with pytest.raises(ValueError, match=message):
        CHECKER.validate_catalog(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("architecture", "windows/386", "architecture"),
        ("protected_evidence_identity", "0" * 64, "protected-evidence"),
    ),
)
def test_runtime_top_level_identity_is_reviewed(
    tmp_path: Path, monkeypatch, field: str, value: str, message: str,
) -> None:
    path = _runtime_catalog(
        tmp_path, lambda runtime: runtime.update({field: value}), monkeypatch,
    )
    with pytest.raises(ValueError, match=message):
        CHECKER.validate_catalog(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("execution_status", "FABRICATED", "execution status"),
        ("native_result", "FABRICATED", "native result"),
    ),
)
def test_runtime_record_state_vocabularies_are_closed(
    tmp_path: Path, monkeypatch, field: str, value: str, message: str,
) -> None:
    path = _runtime_catalog(
        tmp_path,
        lambda runtime: runtime["records"][0].update({field: value}),
        monkeypatch,
    )
    with pytest.raises(ValueError, match=message):
        CHECKER.validate_catalog(path)


def test_fake_exact_with_runtime_errors_and_fake_signoff_is_rejected(
    tmp_path: Path,
) -> None:
    def mutate(data):
        relationship = data["relationships"][0]
        relationship["classification"] = "EXACT"
        relationship["exact_blockers"] = []
        relationship["independent_reviewer_signoff"] = {
            "verification_status": "VERIFIED",
            "verification_record_sha256": "1" * 64,
        }
        data["exact_mapping_count"] = 1

    with pytest.raises(ValueError, match="mechanically verified sign-off"):
        CHECKER.validate_catalog(_catalog(tmp_path, mutate))


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda record: record.update(normalized_result="BOGUS"), "contradicts"),
        (
            lambda record: record.update(
                execution_status="PARTIAL", normalized_result="FINDING"
            ),
            "contradicts normalized",
        ),
        (lambda record: record.update(exit_code="0"), "exit code"),
        (lambda record: record.update(diagnostics=[]), "diagnostics"),
        (lambda record: record.update(diagnostics=["NOT_COMPLETED"]), "PASS diagnostics"),
        (lambda record: record.update(command_argv=[]), "command argv"),
        (lambda record: record.update(command_argv_sha256="0" * 64), "argv digest"),
        (lambda record: record.update(duration_ms=-1), "duration"),
        (lambda record: record.update(policy_identity=""), "policy identity"),
    ),
)
def test_runtime_record_coherence_is_closed(
    tmp_path: Path, monkeypatch, mutation, message: str,
) -> None:
    path = _runtime_catalog(
        tmp_path, lambda runtime: mutation(runtime["records"][0]), monkeypatch,
    )
    with pytest.raises(ValueError, match=message):
        CHECKER.validate_catalog(path)


def test_nonpass_native_reason_must_be_retained(
    tmp_path: Path, monkeypatch,
) -> None:
    def mutate(runtime):
        record = next(item for item in runtime["records"] if item["execution_status"] == "ERROR")
        record["diagnostics"] = ["PROCESS_ERROR"]

    with pytest.raises(ValueError, match="retained"):
        CHECKER.validate_catalog(_runtime_catalog(tmp_path, mutate, monkeypatch))


@pytest.mark.parametrize(
    ("scanner", "mutate", "message"),
    (
        ("checkov", lambda commands: commands.pop(), "Checkov invocation"),
        ("kics", lambda commands: commands.append(list(commands[0])), "locked adapter"),
        ("kics", lambda commands: commands[0].remove("--read-only"), "locked adapter"),
        (
            "kics",
            lambda commands: commands[0].__setitem__(
                next(i for i, value in enumerate(commands[0]) if "@sha256:" in value),
                "floating:latest",
            ),
            "immutable image",
        ),
        (
            "trivy",
            lambda commands: commands[0].remove("<protected-cache>:/cache:rw"),
            "mount contract",
        ),
    ),
)
def test_locked_argv_contract_rejects_material_mutations(
    scanner: str, mutate, message: str,
) -> None:
    runtime = json.loads(
        (ROOT / "controls/runtime-evidence-v1.json").read_text(encoding="utf-8")
    )
    commands = copy.deepcopy(next(
        record["command_argv"] for record in runtime["records"]
        if record["scanner"] == scanner
    ))
    mutate(commands)
    with pytest.raises(ValueError, match=message):
        CHECKER._validate_locked_argv(scanner, commands)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("contract", "wrong", "contract"),
        ("status", "CLAIMED", "status"),
        ("creation_timestamp", "not-time", "timestamp"),
        ("architecture", "linux/amd64", "architecture"),
        ("protected_evidence_identity", "0" * 64, "protected evidence"),
        ("record_root_sha256", "0" * 64, "record root"),
    ),
)
def test_execution_attestation_reconciles_children(
    field: str, value: str, message: str,
) -> None:
    runtime = json.loads(
        (ROOT / "controls/runtime-evidence-v1.json").read_text(encoding="utf-8")
    )
    runtime.pop("evidence_root_sha256")
    runtime["execution_attestation"][field] = value
    with pytest.raises(ValueError, match=message):
        CHECKER._validate_execution_attestation(runtime)


def test_execution_attestation_rejects_resealed_and_malformed_identity(
    monkeypatch,
) -> None:
    runtime = json.loads(
        (ROOT / "controls/runtime-evidence-v1.json").read_text(encoding="utf-8")
    )
    runtime.pop("evidence_root_sha256")
    runtime["execution_attestation"]["creation_timestamp"] = "2026-08-13T00:00:00+00:00"
    with pytest.raises(ValueError, match="not canonical"):
        CHECKER._validate_execution_attestation(runtime)
    item = runtime["execution_attestation"]
    children = dict(item)
    children.pop("attestation_identity")
    item["attestation_identity"] = CHECKER._canonical_sha(children)
    with pytest.raises(ValueError, match="not the reviewed execution"):
        CHECKER._validate_execution_attestation(runtime)
    monkeypatch.setattr(
        CHECKER, "APPROVED_EXECUTION_ATTESTATION_IDENTITY",
        item["attestation_identity"],
    )
    item["runtime_identity"] = "bad"
    children = dict(item)
    children.pop("attestation_identity")
    item["attestation_identity"] = CHECKER._canonical_sha(children)
    monkeypatch.setattr(
        CHECKER, "APPROVED_EXECUTION_ATTESTATION_IDENTITY",
        item["attestation_identity"],
    )
    with pytest.raises(ValueError, match="runtime_identity"):
        CHECKER._validate_execution_attestation(runtime)


def test_exact_signoff_requires_verified_bytes_signer_and_signature(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(CHECKER, "ROOT", tmp_path)
    for name, raw in (("record.json", b"record"), ("record.sig", b"signature"), ("key.pem", b"key")):
        (tmp_path / name).write_bytes(raw)
    signoff = {
        "verification_status": "VERIFIED",
        "verification_record_path": "record.json",
        "verification_record_sha256": hashlib.sha256(b"record").hexdigest(),
        "signature_path": "record.sig",
        "signature_sha256": hashlib.sha256(b"signature").hexdigest(),
        "public_key_path": "key.pem",
        "public_key_sha256": hashlib.sha256(b"key").hexdigest(),
        "signer_identity": f"ed25519:{hashlib.sha256(b'key').hexdigest()}",
    }
    monkeypatch.setattr(CHECKER.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    CHECKER._validate_exact_signoff(signoff)
    with pytest.raises(ValueError, match="not verified"):
        CHECKER._validate_exact_signoff({**signoff, "verification_status": "CLAIMED"})
    with pytest.raises(ValueError, match="bytes"):
        CHECKER._validate_exact_signoff({**signoff, "signature_sha256": "0" * 64})
    with pytest.raises(ValueError, match="signer"):
        CHECKER._validate_exact_signoff({**signoff, "signer_identity": "unknown"})
    monkeypatch.setattr(CHECKER.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=1))
    with pytest.raises(ValueError, match="signature is invalid"):
        CHECKER._validate_exact_signoff(signoff)


def test_runtime_evidence_rejects_malformed_json_and_root(
    tmp_path: Path, monkeypatch,
) -> None:
    copied_root = tmp_path / "malformed-root"
    (copied_root / "controls").mkdir(parents=True)
    shutil.copytree(ROOT / "controls/fixtures", copied_root / "controls/fixtures")
    runtime = copied_root / "controls/runtime-evidence-v1.json"
    runtime.write_text("not-json", encoding="utf-8")
    catalog = yaml.safe_load((ROOT / "controls/catalog-v1.yml").read_text())
    catalog["runtime_evidence"]["sha256"] = hashlib.sha256(runtime.read_bytes()).hexdigest()
    path = copied_root / "controls/catalog-v1.yml"
    path.write_text(yaml.safe_dump(catalog, sort_keys=False))
    monkeypatch.setattr(CHECKER, "ROOT", copied_root)
    with pytest.raises(ValueError, match="malformed"):
        CHECKER.validate_catalog(path)

    invalid_root = json.loads(
        (ROOT / "controls/runtime-evidence-v1.json").read_text(encoding="utf-8")
    )
    invalid_root["evidence_root_sha256"] = "0" * 64
    runtime.write_text(json.dumps(invalid_root), encoding="utf-8")
    catalog["runtime_evidence"]["sha256"] = hashlib.sha256(runtime.read_bytes()).hexdigest()
    path.write_text(yaml.safe_dump(catalog, sort_keys=False))
    with pytest.raises(ValueError, match="root"):
        CHECKER.validate_catalog(path)


def test_safe_file_rejects_escape_missing_and_symlink(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(CHECKER, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="escapes"):
        CHECKER._safe_file("../outside")
    with pytest.raises(ValueError, match="unavailable"):
        CHECKER._safe_file("missing")
    target = tmp_path / "target"
    target.write_text("x")
    (tmp_path / "link").symlink_to(target)
    with pytest.raises(ValueError, match="unsafe"):
        CHECKER._safe_file("link")


def test_source_verification_binds_exact_refs_and_bytes(monkeypatch) -> None:
    data = CHECKER.validate_catalog(ROOT / "controls/catalog-v1.yml")

    def run(command, **_kwargs):
        scanner = next(
            lock for lock in data["scanner_locks"].values()
            if command[2] == lock["source_repository"] + ".git"
        )
        ref = command[3]
        return SimpleNamespace(stdout=f"{scanner['source_commit']}\t{ref}\n")

    class Response:
        def __init__(self, raw):
            self.raw = raw
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def read(self):
            return self.raw

    hashes = {
        source["url"]: source["sha256"]
        for relationship in data["relationships"]
        for source in relationship["authoritative_sources"].values()
    }
    # Digest preimages are not available here, so exercise the URL branch with a
    # patched hashlib wrapper that preserves the reviewed expected identity.
    current = {"url": ""}
    def open_url(url, **_kwargs):
        current["url"] = url
        return Response(url.encode())
    real_sha = hashlib.sha256
    def sha256(raw=b""):
        if raw == current["url"].encode() and current["url"] in hashes:
            return SimpleNamespace(hexdigest=lambda: hashes[current["url"]])
        return real_sha(raw)

    monkeypatch.setattr(CHECKER.subprocess, "run", run)
    monkeypatch.setattr(CHECKER.urllib.request, "urlopen", open_url)
    monkeypatch.setattr(CHECKER.hashlib, "sha256", sha256)
    CHECKER.verify_sources(data)

    monkeypatch.setattr(
        CHECKER.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="0" * 40 + "\trefs/tags/x\n"),
    )
    with pytest.raises(ValueError, match="release tag"):
        CHECKER.verify_sources(data)


def test_main_prints_pinned_catalog_result(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["check_catalog.py"])
    assert CHECKER.main() == 0
    assert "sources=PINNED" in capsys.readouterr().out
