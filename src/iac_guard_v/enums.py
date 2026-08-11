"""Typed vocabulary for IaC-Guard-V.

Every value here is defined in `docs/spec/VERIFICATION_SEMANTICS.md`. The document is
authoritative; this module is its transcription, and `tests/spec/spec_reference.py` is the
conformance oracle these values must agree with.

Nothing in this module collapses an operational failure into a boolean. `Status` carries
`ERROR`, `TIMEOUT`, `UNSUPPORTED`, `PARTIAL`, `SKIPPED` and `INCONCLUSIVE` all the way
through report generation, because merging them into "not PASS" is what allowed a
crashed scanner to look like a clean one (audit findings F1 and F6).
"""
from __future__ import annotations

from enum import Enum


class Status(str, Enum):
    """Outcome of one operation: a scan, a validator, an oracle, a policy evaluation."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"
    PARTIAL = "PARTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"


#: States meaning "we could not establish anything" (semantics §7 step 1).
UNDECIDED_STATES = frozenset({
    Status.ERROR, Status.TIMEOUT, Status.UNSUPPORTED, Status.PARTIAL,
    Status.INCONCLUSIVE, Status.SKIPPED,
})


class Verdict(str, Enum):
    """Outcome of a whole verification. There is no fourth value."""

    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class Outcome(str, Enum):
    """What happened to one target (semantics §4). Exactly one per target."""

    FIXED = "FIXED"
    STILL_PRESENT = "STILL_PRESENT"
    PARTIALLY_FIXED = "PARTIALLY_FIXED"
    SUPPRESSED = "SUPPRESSED"
    RESOURCE_DELETED = "RESOURCE_DELETED"
    FILE_DELETED_OR_RENAMED = "FILE_DELETED_OR_RENAMED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    RULE_OR_SCANNER_DRIFT = "RULE_OR_SCANNER_DRIFT"
    SCANNER_ERROR = "SCANNER_ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"


class DeltaClass(str, Enum):
    """Regression delta classes (semantics §5)."""

    NEW_FINDING = "NEW_FINDING"
    LOCATION_CHANGED = "LOCATION_CHANGED"
    SEVERITY_INCREASED = "SEVERITY_INCREASED"
    SCOPE_EXPANDED = "SCOPE_EXPANDED"
    RULE_SUBSTITUTED = "RULE_SUBSTITUTED"
    SUPPRESSION_ADDED = "SUPPRESSION_ADDED"
    COVERAGE_DECREASED = "COVERAGE_DECREASED"
    DIAGNOSTIC_ADDED = "DIAGNOSTIC_ADDED"
    DESTRUCTIVE_CHANGE = "DESTRUCTIVE_CHANGE"
    POLICY_DRIFT = "POLICY_DRIFT"
    RESOLVED_FINDING = "RESOLVED_FINDING"


class IdentityTier(str, Enum):
    """Finding identity tiers (semantics §3.2)."""

    EXACT = "EXACT"
    RELOCATED = "RELOCATED"
    SEMANTIC = "SEMANTIC"
    OCCURRENCE = "OCCURRENCE"


class MatchingReason(str, Enum):
    """Closed reasons why occurrence pairing could not be established."""

    MATCHING_INCONCLUSIVE = "MATCHING_INCONCLUSIVE"


class CheckEvaluationResult(str, Enum):
    """Native per-target result retained from a scanner result bucket."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    UNKNOWN = "UNKNOWN"


class CheckTargetReason(str, Enum):
    """Why Checkov evidence did or did not affirm one target."""

    AFFIRMATIVE_TARGET_PASS = "AFFIRMATIVE_TARGET_PASS"
    TARGET_FAILED = "TARGET_FAILED"
    TARGET_SUPPRESSED = "TARGET_SUPPRESSED"
    TARGET_EVALUATION_UNKNOWN = "TARGET_EVALUATION_UNKNOWN"
    TARGET_NOT_EVALUATED = "TARGET_NOT_EVALUATED"
    RESOURCE_NOT_OBSERVED = "RESOURCE_NOT_OBSERVED"
    RULE_NOT_OBSERVED = "RULE_NOT_OBSERVED"
    AGGREGATE_ONLY_EVIDENCE = "AGGREGATE_ONLY_EVIDENCE"
    SCANNER_RUN_NOT_PASS = "SCANNER_RUN_NOT_PASS"


class ArtifactKind(str, Enum):
    TERRAFORM_HCL = "terraform_hcl"
    TERRAFORM_PLAN_JSON = "terraform_plan_json"
    OPENTOFU_HCL = "opentofu_hcl"
    KUBERNETES_YAML = "kubernetes_yaml"
    KUBERNETES_JSON = "kubernetes_json"
    HELM_RENDERED_YAML = "helm_rendered_yaml"
    CLOUDFORMATION = "cloudformation"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


#: Ascending order, so "at or above the severity floor" is a comparison rather than a
#: table of special cases.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.UNKNOWN, Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH,
    Severity.CRITICAL,
)


class ExceptionOrigin(str, Enum):
    """Where a policy record came from. Stamped by the loader, never self-declared."""

    OPERATOR = "operator"
    PROTECTED_POLICY_REPO = "protected_policy_repo"
    TRUSTED_BASE = "trusted_base"
    CANDIDATE_HEAD = "candidate_head"
    UNKNOWN = "unknown"


TRUSTED_EXCEPTION_ORIGINS = frozenset({
    ExceptionOrigin.OPERATOR, ExceptionOrigin.PROTECTED_POLICY_REPO,
    ExceptionOrigin.TRUSTED_BASE,
})

#: Outcomes an organisation may knowingly accept through a trusted, target-scoped,
#: unexpired exception that names the event. Deliberately closed and small.
PERMITTABLE_EXCEPTION_OUTCOMES = frozenset({
    Outcome.SUPPRESSED, Outcome.RESOURCE_DELETED, Outcome.FILE_DELETED_OR_RENAMED,
})

#: Never waivable: the first two are unresolved defects, the rest are absences of
#: evidence, and approval cannot manufacture evidence.
NEVER_PERMITTABLE_OUTCOMES = frozenset({
    Outcome.STILL_PRESENT, Outcome.PARTIALLY_FIXED, Outcome.SCANNER_ERROR,
    Outcome.RULE_OR_SCANNER_DRIFT, Outcome.INCONCLUSIVE, Outcome.OUT_OF_SCOPE,
})

INCONCLUSIVE_OUTCOMES = frozenset({
    Outcome.SCANNER_ERROR, Outcome.RULE_OR_SCANNER_DRIFT, Outcome.INCONCLUSIVE,
})
PASSING_OUTCOMES = frozenset({Outcome.FIXED})

EXIT_CODES: dict[Verdict, int] = {
    Verdict.VERIFIED: 0, Verdict.FAILED: 1, Verdict.INCONCLUSIVE: 3,
}
EXIT_USAGE_ERROR = 2
EXIT_INTERNAL_ERROR = 4
