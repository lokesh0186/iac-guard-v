#!/usr/bin/env python3
"""Gate C: refuse to let the specification stay vague.

The plan's spec-quality rule is "do not implement a feature whose semantics are still
described with words like successful, fixed, safe, supported, or consensus". A prose
rule is unenforceable, so this checker turns it into four mechanical ones:

  1. GLOSSARY     every ambiguous term has an explicit entry in the semantics glossary.
  2. ENUM_DEFINED every enum token used anywhere in docs/spec is defined in the
                  semantics document (or explicitly allowlisted).
  3. ENUM_COMPLETE the enum families the engine depends on are complete: 8 statuses,
                  3 verdicts, 10 target outcomes, 11 delta classes, 5 exit codes.
  4. SECTIONS     each specification document contains its required sections.

It also reports any use of an ambiguous term in a normative sentence (one containing
MUST, MUST NOT, SHOULD, or REQUIRED) that does not cite a definition, because that is
where vagueness does real damage.

Usage:
    python tools/spec_lint.py docs/spec/
    python tools/spec_lint.py --require-section trusted-configuration docs/spec/THREAT_MODEL.md
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SEMANTICS = "VERIFICATION_SEMANTICS.md"

AMBIGUOUS_TERMS = ("successful", "fixed", "resolved", "safe", "supported",
                   "consensus", "verified", "evidence")

STATUSES = ("PASS", "FAIL", "ERROR", "TIMEOUT", "UNSUPPORTED", "SKIPPED",
            "PARTIAL", "INCONCLUSIVE")
VERDICTS = ("VERIFIED", "FAILED", "INCONCLUSIVE")
TARGET_OUTCOMES = ("FIXED", "STILL_PRESENT", "PARTIALLY_FIXED", "SUPPRESSED",
                   "RESOURCE_DELETED", "FILE_DELETED_OR_RENAMED", "OUT_OF_SCOPE",
                   "RULE_OR_SCANNER_DRIFT", "SCANNER_ERROR", "INCONCLUSIVE")
DELTA_CLASSES = ("NEW_FINDING", "LOCATION_CHANGED", "SEVERITY_INCREASED",
                 "SCOPE_EXPANDED", "RULE_SUBSTITUTED", "SUPPRESSION_ADDED",
                 "COVERAGE_DECREASED", "DIAGNOSTIC_ADDED", "DESTRUCTIVE_CHANGE",
                 "POLICY_DRIFT", "RESOLVED_FINDING")
IDENTITY_TIERS = ("EXACT", "RELOCATED", "SEMANTIC", "OCCURRENCE")
AGREEMENT_STATES = ("AGREEMENT_PASS", "AGREEMENT_FAIL", "DISAGREEMENT",
                    "NOT_COMPARABLE")
MAPPING_CONFIDENCE = ("EXACT", "OVERLAPPING", "RELATED", "NOT_COMPARABLE", "UNKNOWN")
PROCESS_REASONS = (
    "COMPLETED_WITHIN_CONTRACT", "EXECUTABLE_NOT_FOUND", "SPAWN_FAILED",
    "DEADLINE_EXCEEDED", "OUTPUT_LIMIT_EXCEEDED", "PROCESS_GROUP_CLEANUP_FAILED",
    "LINGERING_DESCENDANTS_TERMINATED", "NO_EXIT_STATUS", "KILLED_BY_SIGNAL",
    "EXIT_CODE_OUTSIDE_CONTRACT", "SCRATCH_CLEANUP_FAILED",
)
PROCESS_GROUP_STATES = ("ABSENT", "ALIVE", "UNKNOWN")
MATCHING_REASONS = ("MATCHING_INCONCLUSIVE",)
CHECK_EVALUATION_RESULTS = ("PASSED", "FAILED", "SKIPPED", "UNKNOWN")
TRIVY_MISCONFIGURATION_STATUSES = ("PASS", "FAIL", "EXCEPTION")
ARTIFACT_KINDS = ("TERRAFORM", "KUBERNETES_YAML", "KUBERNETES_JSON")
SCAN_ROLES = ("DISCOVERY", "BASELINE", "CANDIDATE")
EXECUTION_MODES = ("PR_BASE", "PROTECTED_POLICY_REPOSITORY", "EXPLICIT_OPERATOR")
CHECK_TARGET_REASONS = (
    "AFFIRMATIVE_TARGET_PASS", "TARGET_FAILED", "TARGET_SUPPRESSED",
    "TARGET_EVALUATION_UNKNOWN", "TARGET_NOT_EVALUATED", "RESOURCE_NOT_OBSERVED",
    "RULE_NOT_OBSERVED", "AGGREGATE_ONLY_EVIDENCE",
    "SCANNER_RUN_NOT_PASS",
)
EXCEPTION_ORIGINS = (
    "OPERATOR", "PROTECTED_POLICY_REPO", "TRUSTED_BASE", "CANDIDATE_HEAD", "UNKNOWN",
)
ADAPTER_REASONS = (
    "COMPLETED", "PROCESS_ERROR", "EMPTY_OUTPUT", "MALFORMED_JSON",
    "TRUNCATED_OUTPUT", "UNEXPECTED_TOP_LEVEL", "EXIT_CODE_OUTSIDE_CONTRACT",
    "EXIT_RESULT_MISMATCH",
    "DEADLINE_EXCEEDED", "KILLED_PROCESS", "PARTIAL_SCAN",
    "ZERO_FILES_DISCOVERED", "UNSUPPORTED_VERSION", "VERSION_MISMATCH",
    "VERSION_PROBE_FAILED", "NO_RESULTS_STRUCTURE", "INVALID_RESULTS_STRUCTURE",
    "COVERAGE_MISMATCH", "FRAMEWORK_MISMATCH",
    "MISSING_RESOURCE_IDENTITY", "RAW_OUTPUT_MISSING", "OUTPUT_CLEANUP_FAILED",
    "INPUT_CHANGED_DURING_SCAN_PREPARATION", "SCAN_VIEW_PREPARATION_FAILED",
    "OUTPUT_DIRECTORY_INTEGRITY_FAILED", "UNKNOWN_RESULT_BUCKET",
    "AGGREGATE_ONLY_EVIDENCE", "SCANNER_ENVIRONMENT_MISMATCH",
    "POLICY_INVENTORY_MISMATCH",
    "RESOURCE_INVENTORY_MISSING", "RESOURCE_COUNT_MISMATCH",
    "CONTRADICTORY_EVALUATION_EVIDENCE", "EMPTY_ELIGIBLE_SCOPE",
    "INPUT_FILE_COUNT_EXCEEDED", "INPUT_FILE_BYTES_EXCEEDED",
    "INPUT_TOTAL_BYTES_EXCEEDED",
    "JSON_DEPTH_EXCEEDED",
    "LOCK_IDENTITY_MISMATCH", "DUPLICATE_JSON_KEY",
    "KICS_FAILED_TO_SCAN", "KICS_QUERY_EXECUTION_FAILED",
    "KICS_SIMILARITY_ID_FAILED", "UNKNOWN_NATIVE_CATEGORY",
    "EXTERNAL_CHECKS_MISSING", "EXTERNAL_CHECKS_CHANGED",
    "EMBEDDED_CHECKS_FALLBACK", "CACHE_CHANGED_DURING_EXECUTION",
    "MISSING_MISCONFIGURATIONS",
    "EXPERIMENTAL_MODIFIED_FINDINGS",
)
PACKAGED_IMPLEMENTATION_REASONS = (
    "GATE_IMPLEMENTATION_CHANGED",
    "GATE_IMPLEMENTATION_INTEGRITY_INCONCLUSIVE",
    "CHECKOV_ENVIRONMENT_INTERNALLY_CONSISTENT",
)
PHASE_E_LOCK_SIGNATURE_STATUSES = (
    "AVAILABLE_NOT_VERIFIED", "UNAVAILABLE",
)
PHASE_E_LOCK_REVIEW_STATUSES = (
    "STATIC_REVIEW", "STATIC_REVIEW_USER_SUPPLIED_ONLY",
    "STATIC_REVIEW_OPTIONAL_NON_SECURITY",
)
PHASE_E_LOCK_VALIDATOR_RESULTS = ("PHASE_E_LOCK_SCHEMA", "PHASE_E_LOCK_SOURCE")
PHASE_E_DISTRIBUTION_ROLES = (
    "USER_SUPPLIED_ONLY_NEVER_BUNDLED", "OPTIONAL_NON_SECURITY", "NOASSERTION",
)

REQUIRED_SECTIONS = {
    "PRODUCT_SPEC.md": ["Problem", "Personas", "Functional requirements",
                        "Non-functional requirements", "Release criteria"],
    "ARCHITECTURE.md": ["Layers", "Package layout", "Data flow", "Domain objects",
                        "Adapter boundary", "Execution layer"],
    SEMANTICS: ["Defined terms", "Status", "Trusted configuration", "Finding identity",
                "Target outcomes", "Regression delta classes", "Gates", "Verdict",
                "Exit codes", "Determinism"],
    "THREAT_MODEL.md": ["Assets", "Trust boundaries", "Attacker goals",
                        "Residual risks"],
    "SCANNER_CONTRACTS.md": ["Checkov", "KICS", "Trivy", "Support matrix",
                             "Contract test set"],
    "ADOPTION_PLAN.md": ["onboarding", "Pilot", "Upstream case workflow",
                         "Evidence hygiene"],
}

# Tokens that look like enum values but are not semantic enums: verifier diagnostic
# codes, freeze/replay result labels, path variables, filenames, and abbreviations.
# Diagnostic codes are deliberately listed rather than defined in the semantics
# document: they describe how a tool failed, not what a verification outcome means.
DIAGNOSTIC_CODES = {
    "SNAPSHOT_CHANGED_DURING_VERIFICATION",
    "ARTIFACT_UNIVERSE_UNRESOLVED",
    "OCCURRENCE_PASS_COVERAGE_INCOMPLETE", "NEW_FINDING_SEVERITY_UNKNOWN",
    "INDEX_MODE_CHANGED", "PHYSICAL_MODE_CHANGED", "SYMLINK_IN_PARENT_COMPONENT",
    "SYMLINKED_DIRECTORY_UNDER_FROZEN_PREFIX", "UNLISTED_PHYSICAL_FILE_UNDER_FROZEN_PREFIX",
    "PATH_ESCAPES_REPOSITORY", "NOT_A_REGULAR_FILE", "TAG_BINDING_REQUIRED",
    "TAG_NOT_ANNOTATED", "TAG_COMMIT_MISMATCH", "TAG_ROOT_ABSENT", "TAG_ROOT_AMBIGUOUS",
    "TAG_ROOT_MISMATCH", "TAG_TREE_PATH_NOT_IN_MANIFEST", "MANIFEST_PATH_NOT_IN_TAG_TREE",
    "TAG_TREE_MODE_MISMATCH", "TAG_TREE_BLOB_MISMATCH", "TAG_TREE_NON_BLOB",
    "MANIFEST_DUPLICATE_PATHS", "SNAPSHOT_BINDING_REQUIRED",
    "EXEC_BIT_FIDELITY_UNAVAILABLE", "TAG_BINDING_SKIPPED",
}

# Recorded owner-decision states. Like diagnostic codes, these are not verification
# outcomes, so they are listed rather than defined in the semantics document.
DECISION_LABELS = {
    "KEEP_UNCHANGED_PENDING_RIGHTS_CONFIRMATION",
}

# Names of the sets above, when a document refers to them by name.
META_NAMES = {"DIAGNOSTIC_CODES", "DECISION_LABELS", "ALLOWLIST", "META_NAMES"}

ALLOWLIST = DIAGNOSTIC_CODES | DECISION_LABELS | META_NAMES | {
    "MANIFEST_ROOT", "LEGACY_REPLAY_RESULT", "NO_RESULTS_STRUCTURE",
    "UNTRUSTED_VERSION_DRIFT", "PINNED_SCANNER", "SEMANTIC_MATCH", "SEMANTIC_DIFF",
    "NEEDS_INIT", "ADDED_TRACKED_FILE_UNDER_FROZEN_PREFIX",
    "ADDED_UNTRACKED_FILE_UNDER_FROZEN_PREFIX", "SYMLINK_APPEARED", "MISSING_FILE",
    "MODE_CHANGED", "SIZE_CHANGED", "SHA256_CHANGED", "GIT_BLOB_CHANGED",
    "ENTRY_COUNT", "MANIFEST_ROOT_MISMATCH", "MANIFEST_NOT_CANONICAL",
    "MANIFEST_PARSE", "MANIFEST_SCHEMA", "PATH_NOT_NORMALISED",
    "PATH_OUTSIDE_FROZEN_SCOPE", "UNTRACKED_LISTED_FILE", "MISSING_ROOT_SIDECAR",
    "ROOT_SIDECAR_SCHEMA", "ROOT_ENTRY_COUNT", "WORKING_TREE_BYTES_DIFFER_EOL_ONLY",
    "WORKING_TREE_CONTENT_CHANGED_UNSTAGED", "NO_NEW_BENCHMARK_INFERENCE_RUNS_EXECUTED",
    "NO_NEW_MODEL_PROVIDER_CALLS_FROM_IAC_GUARD_V",
    "MODEL_REFRESH_PROTOCOL_NOT_PREPARED_AND_NOT_EXECUTED",
    "MODEL_REFRESH_PROTOCOL_PREPARED_BUT_NOT_EXECUTED", "PRIVATE_WORKSPACE",
    "REPO_ROOT", "TEMP_ROOT", "SRC", "OUT", "HOME", "PATH", "TBD", "CI", "IaC",
    "ALLOW_EXTERNAL_SUBMISSIONS", "GITHUB_TOKEN", "AVDID", "CKV", "OK", "JSON",
    "SARIF", "YAML", "HCL", "URL", "API", "CLI", "UID", "PID", "SDK", "OS", "PR",
    "ADR", "PDF", "CSV", "LF", "CRLF", "AM", "DOI", "SHA", "OIDC", "SBOM", "SLSA",
    "LICENSE", "NOTICE", "BASE", "HEAD", "ID", "AVD", "MisconfSummary", "RECORD",
    "HISTORICAL_HARDENED_EVIDENCE_SUFFICIENCY_COMPARISON",
    "AFFIRMATIVE_CANDIDATE_TARGET_EVALUATION_MISSING",
    "CANDIDATE_SCANNER_EXECUTION_IDENTITY_MISSING",
    "CANDIDATE_COVERAGE_INVENTORY_MISSING", "HISTORICAL_SEALED_SNAPSHOT_MISSING",
    "HISTORICAL_TRUSTED_POLICY_PROVENANCE_MISSING",
    "SIGKILL", "SIGTERM", "TMPDIR", "TZ", "LANG", "LC_ALL",
    "IACGV_PHASE_E_CACHE",
    "ESRCH", "EPERM",
    "NON_KUBERNETES_YAML", "NON_KUBERNETES_JSON",
    "ACCEPTED", "REJECTED",
    "P0", "V1", "V2", "V3", "V4", "V5", "V6", "V7", "F1", "F2", "F3", "F4", "F5",
    "F6", "F12", "N", "A", "B", "C", "D", "E", "T1", "T2", "T3", "T4", "T5", "T6",
    "T7", "T8", "T9", "GHCR", "PyPI", "MCP", "OPA", "ARM", "CDK", "IDE",
}

ENUM_TOKEN = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[A-Z]{2,})\b")
NORMATIVE = re.compile(r"\b(MUST NOT|MUST|SHOULD NOT|SHOULD|REQUIRED|SHALL)\b")


def strip_code(text: str) -> str:
    """Remove fenced code blocks; examples are not normative prose."""
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--require-section", action="append", default=[])
    args = ap.parse_args()

    docs: dict[Path, str] = {}
    for target in args.paths:
        if target.is_dir():
            for path in sorted(target.rglob("*.md")):
                docs[path] = path.read_text(encoding="utf-8")
        elif target.is_file():
            docs[target] = target.read_text(encoding="utf-8")

    if not docs:
        print("FAIL: no specification documents found")
        return 1

    semantics_path = next((p for p in docs if p.name == SEMANTICS), None)
    if semantics_path is None:
        print(f"FAIL: {SEMANTICS} not among the inspected documents")
        return 1
    semantics = docs[semantics_path]

    failures: list[str] = []
    warnings: list[str] = []

    # ---- 1. glossary -------------------------------------------------------
    glossary = semantics.split("## 1.")[0]
    for term in AMBIGUOUS_TERMS:
        if not re.search(rf"\*\*{term}\*\*", glossary, re.IGNORECASE):
            failures.append(f"GLOSSARY: ambiguous term '{term}' has no glossary entry")

    # ---- 3. enum completeness ---------------------------------------------
    families = {
        "Status": STATUSES,
        "Verdict": VERDICTS,
        "TargetOutcome": TARGET_OUTCOMES,
        "DeltaClass": DELTA_CLASSES,
        "IdentityTier": IDENTITY_TIERS,
        "AgreementState": AGREEMENT_STATES,
        "MappingConfidence": MAPPING_CONFIDENCE,
        "ProcessReason": PROCESS_REASONS,
        "ProcessGroupState": PROCESS_GROUP_STATES,
        "MatchingReason": MATCHING_REASONS,
        "ArtifactKind": ARTIFACT_KINDS,
        "ScanRole": SCAN_ROLES,
        "ExecutionMode": EXECUTION_MODES,
        "CheckEvaluationResult": CHECK_EVALUATION_RESULTS,
        "TrivyMisconfigurationStatus": TRIVY_MISCONFIGURATION_STATUSES,
        "CheckTargetReason": CHECK_TARGET_REASONS,
        "ExceptionOrigin": EXCEPTION_ORIGINS,
        "AdapterReason": ADAPTER_REASONS,
        "PackagedImplementationReason": PACKAGED_IMPLEMENTATION_REASONS,
        "PhaseELockSignatureStatus": PHASE_E_LOCK_SIGNATURE_STATUSES,
        "PhaseELockReviewStatus": PHASE_E_LOCK_REVIEW_STATUSES,
        "PhaseELockValidatorResult": PHASE_E_LOCK_VALIDATOR_RESULTS,
        "PhaseEDistributionRole": PHASE_E_DISTRIBUTION_ROLES,
    }
    defined: set[str] = set()
    for family, members in families.items():
        for member in members:
            if re.search(rf"`{member}`", semantics):
                defined.add(member)
            else:
                failures.append(
                    f"ENUM_COMPLETE: {family} member `{member}` is not defined in {SEMANTICS}"
                )
    for code in range(5):
        if not re.search(rf"^\| {code} \|", semantics, re.MULTILINE):
            failures.append(f"ENUM_COMPLETE: exit code {code} is not defined in {SEMANTICS}")

    # ---- 2. enum tokens used must be defined ------------------------------
    # Only tokens written as inline code are candidates: that is how this project
    # writes enum values. Filenames (SECURITY.md), tool names (KICS), and scanner
    # rule ids (CKV_AWS_18, AVD-AWS-0088) are excluded by shape, so a warning here
    # means an undefined enum rather than an ordinary capitalised word.
    RULE_ID = re.compile(r"^(CKV|CKV2|BC|AVD|AVDID)[_-]")
    for path, text in docs.items():
        body = strip_code(text)
        for span in re.findall(r"`([^`]+)`", body):
            if "." in span or "/" in span or " " in span:
                continue
            token = span.strip()
            if not ENUM_TOKEN.fullmatch(token):
                continue
            if token in ALLOWLIST or token in defined or RULE_ID.match(token):
                continue
            warnings.append(
                f"ENUM_DEFINED: {path.name} uses `{token}` which is not a defined enum "
                f"value (define it in {SEMANTICS} or add it to the allowlist)"
            )

    # ---- 4. required sections ---------------------------------------------
    for path, text in docs.items():
        for needle in REQUIRED_SECTIONS.get(path.name, []):
            if needle.lower() not in text.lower():
                failures.append(f"SECTIONS: {path.name} is missing a section on '{needle}'")
    for needle in args.require_section:
        for path, text in docs.items():
            if needle.lower().replace("-", " ") not in text.lower().replace("-", " "):
                failures.append(f"SECTIONS: {path.name} lacks required section '{needle}'")

    # ---- normative vagueness ---------------------------------------------
    for path, text in docs.items():
        for lineno, line in enumerate(strip_code(text).splitlines(), start=1):
            if not NORMATIVE.search(line):
                continue
            for term in AMBIGUOUS_TERMS:
                if re.search(rf"\b{term}\b", line, re.IGNORECASE):
                    if re.search(r"`[A-Z_]+`|§|semantics|glossary", line, re.IGNORECASE):
                        continue
                    warnings.append(
                        f"VAGUE_NORMATIVE: {path.name}:{lineno} uses '{term}' in a "
                        f"normative sentence without citing a definition"
                    )

    print(f"documents inspected:  {len(docs)}")
    print(f"enum values defined:  {len(defined)}")
    for w in warnings:
        print(f"  WARN {w}")
    for f in failures:
        print(f"  FAIL {f}")
    print("FAIL" if failures else "PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
