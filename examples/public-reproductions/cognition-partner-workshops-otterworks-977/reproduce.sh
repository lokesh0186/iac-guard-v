#!/usr/bin/env bash
set -euo pipefail

readonly BASE_SHA="e78e75994afbbfd8453a65de24cbc6d357ae4c53"
readonly HEAD_SHA="fbad5383c50a5e1f3a4e5307b1497f4d5529f5d3"
readonly BASE_MODULE_TREE="46ea7799544e982b80389191edc171dfc06370c8"
readonly HEAD_MODULE_TREE="fc3aa2c378979587a74d72f30cdf327e3536f683"
readonly MODULE_PATH="infrastructure/terraform/tp-cronbox"
readonly IAC_GUARD_WHEEL_SHA256="7de633ff85595052c04a9fad2aa156a2e3f77062ba7d118f5a35fb15fd08405b"
readonly PYTHON_BIN="${PYTHON_BIN:-python3.11}"
readonly REPORT_OUTPUT="${1:-otterworks-977-report.json}"

if [[ -e "${REPORT_OUTPUT}" || -L "${REPORT_OUTPUT}" ]]; then
  echo "Refusing to overwrite existing report: ${REPORT_OUTPUT}" >&2
  exit 2
fi

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/iacgv-otterworks-977.XXXXXX")"
cleanup() {
  case "${tmp_root}" in
    "${TMPDIR:-/tmp}"/iacgv-otterworks-977.*)
      rm -rf -- "${tmp_root}"
      ;;
    *)
      echo "Refusing unsafe temporary cleanup target: ${tmp_root}" >&2
      ;;
  esac
}
trap cleanup EXIT

mkdir -p \
  "${tmp_root}/downloads" \
  "${tmp_root}/materialized/base" \
  "${tmp_root}/materialized/head"

"${PYTHON_BIN}" -m venv --copies --without-pip "${tmp_root}/product"
"${PYTHON_BIN}" -m venv --copies --without-pip "${tmp_root}/checkov"

"${PYTHON_BIN}" -m pip download \
  --index-url https://pypi.org/simple \
  --no-cache-dir \
  --no-deps \
  --dest "${tmp_root}/downloads" \
  iac-guard-v==0.1.0a3

wheel="${tmp_root}/downloads/iac_guard_v-0.1.0a3-py3-none-any.whl"
actual_wheel_sha="$("${PYTHON_BIN}" -c \
  'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' \
  "${wheel}")"
if [[ "${actual_wheel_sha}" != "${IAC_GUARD_WHEEL_SHA256}" ]]; then
  echo "Unexpected IaC-Guard-V wheel digest: ${actual_wheel_sha}" >&2
  exit 3
fi

"${PYTHON_BIN}" -m pip --python "${tmp_root}/product/bin/python" install \
  --index-url https://pypi.org/simple \
  --no-cache-dir \
  --no-compile \
  "${wheel}"

"${PYTHON_BIN}" -m pip --python "${tmp_root}/checkov/bin/python" install \
  --index-url https://pypi.org/simple \
  --no-cache-dir \
  --no-compile \
  checkov==3.3.0

git clone --no-checkout --filter=blob:none \
  https://github.com/Cognition-Partner-Workshops/otterworks.git \
  "${tmp_root}/upstream"
git -C "${tmp_root}/upstream" fetch origin "${BASE_SHA}" "${HEAD_SHA}"

test "$(git -C "${tmp_root}/upstream" rev-parse "${BASE_SHA}^{commit}")" = "${BASE_SHA}"
test "$(git -C "${tmp_root}/upstream" rev-parse "${HEAD_SHA}^{commit}")" = "${HEAD_SHA}"
test "$(git -C "${tmp_root}/upstream" rev-parse "${BASE_SHA}:${MODULE_PATH}")" = "${BASE_MODULE_TREE}"
test "$(git -C "${tmp_root}/upstream" rev-parse "${HEAD_SHA}:${MODULE_PATH}")" = "${HEAD_MODULE_TREE}"

git -C "${tmp_root}/upstream" archive "${BASE_SHA}" "${MODULE_PATH}" \
  | tar -x -C "${tmp_root}/materialized/base" --strip-components=3
git -C "${tmp_root}/upstream" archive "${HEAD_SHA}" "${MODULE_PATH}" \
  | tar -x -C "${tmp_root}/materialized/head" --strip-components=3

export PYTHONDONTWRITEBYTECODE=1

"${tmp_root}/product/bin/iac-guard" doctor \
  --mode local-trusted \
  --checkov-executable "${tmp_root}/checkov/bin/checkov"

"${tmp_root}/product/bin/iac-guard" verify \
  --before "${tmp_root}/materialized/base" \
  --after "${tmp_root}/materialized/head" \
  --target CKV2_AWS_6=aws_s3_bucket.audit_archive \
  --framework terraform \
  --local-trusted \
  --checkov-executable "${tmp_root}/checkov/bin/checkov" \
  --format console \
  --output "${REPORT_OUTPUT}"

"${tmp_root}/product/bin/iac-guard" explain "${REPORT_OUTPUT}"
