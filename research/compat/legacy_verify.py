#!/usr/bin/env python3
"""Reproduction-only access to the frozen QRS 2026 verification harness.

The frozen harness has four known unsafe behaviours (audit findings F1-F4,
F6). It is kept byte-unchanged because the accepted paper's numbers came from it.
This wrapper is the *only* sanctioned way to invoke it, and it exists to make
accidental production use impossible rather than merely discouraged:

  * it refuses to run without --acknowledge-legacy-non-production-semantics;
  * it prints the specific unsafe behaviours before producing any result;
  * it refuses to run when the installed Checkov is not the pinned 3.2.517,
    unless the caller explicitly asks for an untrusted inspection run;
  * it labels every result LEGACY_REPLAY_RESULT. It never emits VERIFIED, and it
    never returns exit code 0 for a "passing" artifact, so it cannot be wired into
    a CI gate that expects product semantics.

`scripts/verify_patch.py` is imported, never modified.

Usage:
    python research/compat/legacy_verify.py \
        --before path/to/original.tf --after path/to/candidate.tf \
        --target-rule CKV_AWS_18 --baseline scanners/outputs/baseline/BM-0002_baseline.json \
        --acknowledge-legacy-non-production-semantics
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FROZEN_HARNESS = REPO / "scripts" / "verify_patch.py"
PINNED_CHECKOV = "3.2.517"
PROFILE = REPO / "research" / "compat" / "qrs2026.yml"

BANNER = """\
================================================================================
LEGACY RESEARCH SEMANTICS — REPRODUCTION ONLY, NOT A VERIFICATION RESULT
--------------------------------------------------------------------------------
This runs the frozen QRS 2026 harness (scripts/verify_patch.py). In this mode:
  * an empty or failed Checkov run is read as "no findings"          (audit F1)
  * syntax validity is inferred from the absence of output           (audit F2)
  * findings are identified by rule ID only; moved and duplicated
    findings are invisible                                          (audit F3)
  * suppression, resource deletion, and a real fix look identical   (audit F4)
  * operational errors collapse into the same booleans as outcomes  (audit F6)
Output is labelled LEGACY_REPLAY_RESULT. It is not a product verdict and must not
gate any pipeline. Hardened semantics: docs/spec/VERIFICATION_SEMANTICS.md
================================================================================"""


def installed_checkov_version() -> str | None:
    try:
        proc = subprocess.run(["checkov", "--version"], capture_output=True, text=True,
                              timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip().splitlines()[-1].strip() if proc.stdout.strip() else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", type=Path, required=True)
    ap.add_argument("--after", type=Path, required=True)
    ap.add_argument("--target-rule", required=True)
    ap.add_argument("--baseline", type=Path, required=True,
                    help="frozen Checkov baseline JSON for the original artifact")
    ap.add_argument("--acknowledge-legacy-non-production-semantics", action="store_true",
                    dest="acknowledged")
    ap.add_argument("--allow-version-drift-for-inspection", action="store_true",
                    help="run with a non-pinned Checkov; result is marked UNTRUSTED")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    # All human-facing text goes to stderr so that --json stdout stays parseable.
    if not args.acknowledged:
        print(BANNER, file=sys.stderr)
        print(
            "REFUSED: legacy semantics require "
            "--acknowledge-legacy-non-production-semantics.\n"
            "         For real verification use the hardened profile instead.",
            file=sys.stderr,
        )
        return 2

    print(BANNER, file=sys.stderr)

    version = installed_checkov_version()
    drift_note = None
    if version != PINNED_CHECKOV:
        drift_note = (
            f"installed checkov {version!r} != pinned {PINNED_CHECKOV!r}"
        )
        if not args.allow_version_drift_for_inspection:
            print(f"REFUSED: {drift_note}.", file=sys.stderr)
            print("         Replication requires the pinned scanner. Install it in an "
                  "isolated environment, or pass --allow-version-drift-for-inspection "
                  "to obtain an explicitly UNTRUSTED result.", file=sys.stderr)
            return 3
        print(f"WARNING: {drift_note}; result marked UNTRUSTED_VERSION_DRIFT.",
              file=sys.stderr)

    sys.path.insert(0, str(REPO / "scripts"))
    from verify_patch import verify_patch  # noqa: E402  frozen harness, unmodified

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    if isinstance(baseline, list):
        baseline = baseline[0] if baseline else {}

    raw = verify_patch(
        args.before.read_text(encoding="utf-8"),
        args.after.read_text(encoding="utf-8"),
        args.target_rule,
        baseline,
    )
    raw.pop("repaired_checkov_output", None)

    payload = {
        "result_label": "LEGACY_REPLAY_RESULT",
        "profile": "qrs2026",
        "profile_file": str(PROFILE.relative_to(REPO)),
        "is_production_verdict": False,
        "trust": "UNTRUSTED_VERSION_DRIFT" if drift_note else "PINNED_SCANNER",
        "checkov_version_installed": version,
        "checkov_version_required": PINNED_CHECKOV,
        "legacy_gates": raw,
        "warning": (
            "Produced by the frozen research harness. An empty scanner result is "
            "indistinguishable from a clean scan in this mode."
        ),
    }

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        for key, value in payload.items():
            if key != "legacy_gates":
                print(f"{key}: {value}")
        print("legacy_gates:")
        for key, value in raw.items():
            print(f"  {key}: {value}")

    # Deliberately never 0: this tool must not be usable as a passing CI gate.
    return 4


if __name__ == "__main__":
    sys.exit(main())
