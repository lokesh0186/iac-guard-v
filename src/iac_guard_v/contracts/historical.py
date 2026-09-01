"""Typed historical reproducibility boundaries; never environment emulation."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..models import DomainError, canonical_identifier
from ..native_properties.model import canonical_digest, canonical_json, thaw_json


class HistoricalReproducibilityReason(str, Enum):
    HISTORICAL_SCANNER_IDENTITY_UNAVAILABLE = "HISTORICAL_SCANNER_IDENTITY_UNAVAILABLE"
    HISTORICAL_POLICY_BUNDLE_UNAVAILABLE = "HISTORICAL_POLICY_BUNDLE_UNAVAILABLE"
    HISTORICAL_RENDER_INPUTS_UNAVAILABLE = "HISTORICAL_RENDER_INPUTS_UNAVAILABLE"
    EXTERNAL_MATERIALIZATION_CONTRACT_INCOMPLETE = "EXTERNAL_MATERIALIZATION_CONTRACT_INCOMPLETE"
    EXTERNAL_BASELINE_BYTES_UNAVAILABLE = "EXTERNAL_BASELINE_BYTES_UNAVAILABLE"
    EXTERNAL_CANDIDATE_BYTES_UNAVAILABLE = "EXTERNAL_CANDIDATE_BYTES_UNAVAILABLE"
    HISTORICAL_RENDER_IDENTITY_UNAVAILABLE = "HISTORICAL_RENDER_IDENTITY_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class HistoricalReproducibilityRecord:
    case_id: str
    question: str
    expected_artifact_class: str
    available_identities: tuple[dict, ...]
    missing_identities: tuple[str, ...]
    reason: HistoricalReproducibilityReason
    product_version: str
    substitute_used: bool
    record_digest: str

    @classmethod
    def build(
        cls, *, case_id: str, question: str, expected_artifact_class: str,
        available_identities: tuple[dict, ...], missing_identities: tuple[str, ...],
        reason: HistoricalReproducibilityReason, product_version: str,
    ) -> "HistoricalReproducibilityRecord":
        if not missing_identities:
            raise DomainError("historical reproducibility record requires missing identities")
        case_id = canonical_identifier(case_id, "historical case ID")
        body = {
            "case_id": case_id, "question": question,
            "expected_artifact_class": expected_artifact_class,
            "available_identities": list(available_identities),
            "missing_identities": list(missing_identities),
            "reason": reason.value, "product_version": product_version,
            "substitute_used": False,
        }
        return cls(
            case_id, question, expected_artifact_class,
            tuple(thaw_json(canonical_json(item)) for item in available_identities),
            tuple(canonical_identifier(item, "missing identity") for item in missing_identities),
            reason, product_version, False, canonical_digest(body),
        )

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id, "question": self.question,
            "expected_artifact_class": self.expected_artifact_class,
            "available_identities": list(self.available_identities),
            "missing_identities": list(self.missing_identities),
            "reason": self.reason.value, "product_version": self.product_version,
            "substitute_used": self.substitute_used, "record_digest": self.record_digest,
        }


__all__ = ["HistoricalReproducibilityReason", "HistoricalReproducibilityRecord"]
