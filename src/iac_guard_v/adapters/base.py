"""Scanner-neutral adapter contract evidence."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..models import DomainError, canonical_identifier, require_int


class AdapterReason(str, Enum):
    """Closed reasons emitted by scanner adapters before the integrity engine."""

    COMPLETED = "COMPLETED"
    PROCESS_ERROR = "PROCESS_ERROR"
    EMPTY_OUTPUT = "EMPTY_OUTPUT"
    MALFORMED_JSON = "MALFORMED_JSON"
    TRUNCATED_OUTPUT = "TRUNCATED_OUTPUT"
    UNEXPECTED_TOP_LEVEL = "UNEXPECTED_TOP_LEVEL"
    EXIT_CODE_OUTSIDE_CONTRACT = "EXIT_CODE_OUTSIDE_CONTRACT"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    KILLED_PROCESS = "KILLED_PROCESS"
    PARTIAL_SCAN = "PARTIAL_SCAN"
    ZERO_FILES_DISCOVERED = "ZERO_FILES_DISCOVERED"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    VERSION_PROBE_FAILED = "VERSION_PROBE_FAILED"
    NO_RESULTS_STRUCTURE = "NO_RESULTS_STRUCTURE"
    INVALID_RESULTS_STRUCTURE = "INVALID_RESULTS_STRUCTURE"
    COVERAGE_MISMATCH = "COVERAGE_MISMATCH"
    FRAMEWORK_MISMATCH = "FRAMEWORK_MISMATCH"
    MISSING_RESOURCE_IDENTITY = "MISSING_RESOURCE_IDENTITY"
    RAW_OUTPUT_MISSING = "RAW_OUTPUT_MISSING"
    OUTPUT_CLEANUP_FAILED = "OUTPUT_CLEANUP_FAILED"
    INPUT_CHANGED_DURING_SCAN_PREPARATION = "INPUT_CHANGED_DURING_SCAN_PREPARATION"
    SCAN_VIEW_PREPARATION_FAILED = "SCAN_VIEW_PREPARATION_FAILED"
    OUTPUT_DIRECTORY_INTEGRITY_FAILED = "OUTPUT_DIRECTORY_INTEGRITY_FAILED"
    UNKNOWN_RESULT_BUCKET = "UNKNOWN_RESULT_BUCKET"
    AGGREGATE_ONLY_EVIDENCE = "AGGREGATE_ONLY_EVIDENCE"
    SCANNER_ENVIRONMENT_MISMATCH = "SCANNER_ENVIRONMENT_MISMATCH"
    POLICY_INVENTORY_MISMATCH = "POLICY_INVENTORY_MISMATCH"
    RESOURCE_INVENTORY_MISSING = "RESOURCE_INVENTORY_MISSING"
    RESOURCE_COUNT_MISMATCH = "RESOURCE_COUNT_MISMATCH"
    CONTRADICTORY_EVALUATION_EVIDENCE = "CONTRADICTORY_EVALUATION_EVIDENCE"
    EMPTY_ELIGIBLE_SCOPE = "EMPTY_ELIGIBLE_SCOPE"
    INPUT_FILE_COUNT_EXCEEDED = "INPUT_FILE_COUNT_EXCEEDED"
    INPUT_FILE_BYTES_EXCEEDED = "INPUT_FILE_BYTES_EXCEEDED"
    INPUT_TOTAL_BYTES_EXCEEDED = "INPUT_TOTAL_BYTES_EXCEEDED"
    JSON_DEPTH_EXCEEDED = "JSON_DEPTH_EXCEEDED"


@dataclass(frozen=True, slots=True)
class ScannerContract:
    """Pinned executable contract; tuples are copied and canonically ordered."""

    name: str
    supported_versions: tuple
    frameworks: tuple
    expected_exit_codes: tuple

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", canonical_identifier(self.name, "adapter name"))
        for field_name in ("supported_versions", "frameworks", "expected_exit_codes"):
            if type(getattr(self, field_name)) is not tuple:
                raise DomainError(f"{field_name} must be an exact tuple")
        versions = tuple(
            canonical_identifier(item, "supported scanner version")
            for item in self.supported_versions
        )
        frameworks = tuple(
            canonical_identifier(item, "scanner framework") for item in self.frameworks
        )
        exit_codes = tuple(
            require_int(item, "expected scanner exit code")
            for item in self.expected_exit_codes
        )
        if not versions or not frameworks or not exit_codes:
            raise DomainError("scanner contract tuples must not be empty")
        if any(len(values) != len(set(values)) for values in (versions, frameworks, exit_codes)):
            raise DomainError("scanner contract tuples must not contain duplicates")
        object.__setattr__(self, "supported_versions", tuple(sorted(versions)))
        object.__setattr__(self, "frameworks", tuple(sorted(frameworks)))
        object.__setattr__(self, "expected_exit_codes", tuple(sorted(exit_codes)))

    def canonical_dict(self) -> dict:
        return {
            "name": self.name,
            "supported_versions": list(self.supported_versions),
            "frameworks": list(self.frameworks),
            "expected_exit_codes": list(self.expected_exit_codes),
        }


__all__ = ["AdapterReason", "ScannerContract"]
