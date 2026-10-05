#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

# A repo-local hook for a project-owned, trusted before/after Terraform pair.
: "${IACGV_BEFORE:?set IACGV_BEFORE to the baseline directory}"
: "${IACGV_AFTER:?set IACGV_AFTER to the candidate directory}"
: "${IACGV_TARGET:?set IACGV_TARGET to an exact CKV_RULE=resource selector}"
: "${IACGV_GUARD:?set IACGV_GUARD to the released 1.0.0 executable}"
: "${IACGV_CHECKOV:?set IACGV_CHECKOV to the separate Checkov 3.3.0 executable}"

"$IACGV_GUARD" doctor --mode local-trusted --checkov-executable "$IACGV_CHECKOV"
report_root="${IACGV_REPORT_ROOT:-${TMPDIR:-/tmp}/iac-guard-v-repair-runs}"
mkdir -p "$report_root"
report_dir="$(mktemp -d "$report_root/run.XXXXXX")"
report="$report_dir/report.json"
printf 'IaC-Guard-V report: %s\n' "$report"

set +e
"$IACGV_GUARD" verify \
  --before "$IACGV_BEFORE" --after "$IACGV_AFTER" \
  --framework terraform --local-trusted \
  --checkov-executable "$IACGV_CHECKOV" \
  --target "$IACGV_TARGET" --format json --output "$report" --quiet
status=$?
set -e
if [[ ! -s "$report" ]]; then
  printf 'No canonical report was written; verification is inconclusive.\n' >&2
  exit 3
fi
exit "$status"
