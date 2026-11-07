# IaC-Guard-V 1.0.3 candidate

This unpublished maintenance candidate adds the exact Checkov 3.4.3 / Terraform
CKV_AWS_3 combination for declared EBS encryption repairs. It does not promote
other checks or intermediate/future scanner versions. The 31 existing 3.3.x
profiles are unchanged, including the CKV_K8S_40 exclusion from 3.3.8 onward.

Published package-source, launcher and property-definition identities are pinned.
Shared-installation provenance, RECORD and dependency checks remain enforced.
Diagnostics now refer to the selected qualified scanner instead of directing
users to reinstall 3.3.0. No scanner substitution, engine change, public interface change, schema change
or dependency requirement change is included. Python 3.10–3.13 remains the
supported product runtime.

See the [qualification record](docs/CHECKOV_3_4_3_QUALIFICATION.md) and
[compatibility contract](docs/CHECKOV_COMPATIBILITY.md). Candidate tests do not
constitute verification of a future PyPI distribution. Publication and exact
published-artifact replay require separate owner approval.

Implementation and validation preparation were assisted by Codex.
