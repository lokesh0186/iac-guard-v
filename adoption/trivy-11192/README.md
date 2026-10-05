# Trivy #11192: independent fix-branch capture

This packet compares the base and head of the [maintainer-owned fix PR #11193](https://github.com/aquasecurity/trivy/pull/11193)
for [bug #11192](https://github.com/aquasecurity/trivy/issues/11192). The inputs are
new, synthetic Terraform/OpenTofu pairs; no private evidence is included.

The expected source-selection relationships are:

| Fixture | Expected source selection |
| --- | --- |
| `hcl/` | `main.tofu` shadows `main.tf` |
| `json/` | `main.tofu.json` shadows `main.tf.json` |
| `cross/` | `main.tofu` and `main.tf.json` both remain eligible |

The test does not assume a particular count of Checkov or Trivy findings. Its
raw JSON is the record to inspect for findings associated with the deliberately
unencrypted `shadowed` or `cross_json` resources. A clean process exit alone is
not evidence that the precedence bug is fixed.

In an author-run local capture on 2026-10-05, both pinned binaries built and
all three CLI scans completed. The base reported `main.tf` and `main.tf.json`
alongside their same-name OpenTofu files. The fix reported only the OpenTofu
file for those two pairs, while the mixed-syntax control remained in both.
The fix-branch parser regression also passed all five subcases. This is local
reproduction, not a Trivy maintainer's independent rerun or a merged release.
The [raw author-run base and fix captures](author-capture-2026-10-05/RUN_RECORD.md)
are available for inspection.

1. Check out the exact PR base
   `99fde13b1439de741034e564c22b358b4880bbe8` and head
   `d3ad0f949a529c47f451a9859b09e60a6a6294de` in separate directories.
   From each checkout, build `go build -o bin/trivy ./cmd/trivy`. The capture
   script checks the embedded Go VCS revision against the selected commit.
2. Run the source regression from the **head** checkout:

   ```bash
   cd /absolute/path/to/trivy-pr-11193
   go test ./pkg/iac/scanners/terraform/parser -run '^Test_OpenTofuFilePrecedence$' -count=1 -v
   ```

3. Capture the CLI behavior from both binaries:

   ```bash
   python3 adoption/trivy-11192/reproduce.py --revision base \
     --checkout /absolute/path/to/trivy-pr-base \
     --trivy /absolute/path/to/trivy-pr-base/bin/trivy \
     --output /absolute/path/to/new-base-capture
   python3 adoption/trivy-11192/reproduce.py --revision fix \
     --checkout /absolute/path/to/trivy-pr-11193 \
     --trivy /absolute/path/to/trivy-pr-11193/bin/trivy \
     --output /absolute/path/to/new-fix-capture
   ```

Each run binds the source commit, six input hashes, binary hash, version,
three raw reports, and process logs. Compare the two `run-summary.json` files
and raw reports. The script does not download a policy bundle; the
runner needs a locally available Trivy checks bundle. If that dependency is
missing, keep the setup error rather than reporting a fix. A maintainer rerun
could post the Go test output and both `run-summary.json` files with the raw JSON
reports in the PR or issue. Until then, this packet is a reproduction request,
not independent confirmation of the fix.
