# Finding: Storage `init-bucket` misses the component security context

## Narrow characterization

Supabase Kubernetes PR #245 is intended to apply each component's configured
`securityContext` to init containers so the chart can be used with restricted cluster
policies. The Storage template has two built-in init containers when MinIO is enabled.
The patch applies `deployment.storage.securityContext` to `init-db`, but
`init-bucket` still renders without any `securityContext`.

This is a configuration-propagation and chart correctness defect in the proposed
change. It is not characterized here as a vulnerability.

## Expected behavior

Under the pull request's stated values contract, the selected Storage security context
should reach every built-in Storage init container in the enabled branch, or the chart
should expose and document a distinct context contract for `init-bucket`.

## Actual behavior

At head `36ab1fc6e1bbb60597148b726a05bd842888f570`:

- `init-db` receives the configured values.
- `init-bucket` receives no container `securityContext`.
- Checkov `CKV_K8S_20`, `CKV_K8S_22`, and `CKV_K8S_30` remain failing on
  `initContainers[1]`.
- IaC-Guard-V classifies all three selected target outcomes as `STILL_PRESENT`.

The base findings point to `initContainers[0]`. The candidate findings point to
`initContainers[1]`. The finding location changed because one occurrence was repaired
while the second built-in occurrence remained.

## Kubernetes semantics

Kubernetes init containers support container security settings, just like application
containers:

https://kubernetes.io/docs/concepts/workloads/pods/init-containers/

The Restricted Pod Security Standard applies `allowPrivilegeEscalation: false` to
`spec.initContainers[*]` as well as ordinary containers:

https://kubernetes.io/docs/concepts/security/pod-security-standards/

Kubernetes' application security checklist also recommends disabling privilege
escalation and using a read-only root filesystem at container level:

https://kubernetes.io/docs/concepts/security/application-security-checklist/

## Existing project coverage

The repository's pull-request workflows run chart linting and chart installation. The
Storage and MinIO Helm test hooks perform HTTP health checks. None of those checks
asserts that the configured component security context reaches both built-in Storage
init containers, and this pull request adds no regression test for the MinIO-enabled
branch.

## Narrow remediation direction

The smallest likely correction is to render an explicit security context for
`init-bucket` from the intended public values contract and add a chart regression test
with a non-empty Storage context and `deployment.minio.enabled=true`. If maintainers
prefer a dedicated context for this MinIO client container, that distinct contract
should be explicit and tested rather than inferred.
