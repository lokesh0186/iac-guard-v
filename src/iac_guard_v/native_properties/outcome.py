"""Internal evaluator result before definition-bound observation construction."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .model import NativePropertyResult


@dataclass(frozen=True, slots=True)
class EvaluationOutcome:
    result: NativePropertyResult
    reason_code: str
    witness_contents: Mapping[str, Any]
    subject_provenance: Mapping[str, Any]


__all__ = ["EvaluationOutcome"]
