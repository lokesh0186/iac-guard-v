# IaC-Guard-V 1.0.4 release candidate

Unpublished patch candidate. Published 1.0.3 artifacts are unchanged.

The executable CLI cooperatively handles SIGINT and SIGTERM. The native process
runner now terminates its owned scanner process group and reaps the direct child
when execution unwinds, including cancellation and exceptional exits. Repeated
signals cannot abandon bounded cleanup. CLI cancellation returns 3 with an
EXECUTION_CANCELLED diagnostic, never a verified result. No new report protocol,
request fields, scanner dependencies, or version/property qualifications are added.

This guarantee concerns cooperative POSIX cancellation. SIGKILL, machine failure,
and native Windows descendant cleanup are outside this guarantee. Library calls
retain their signal policy; run_command cleans up on raised BaseException.

All existing 3.3.x profiles remain unchanged. Checkov 3.4.3 remains qualified only
for Terraform CKV_AWS_3. Use protected operator-controlled snapshots and runtimes.
