# ADR-0007 — Composite GitHub Action, not a Docker container action

- Status: Accepted
- Date: 2026-08-09

## Context

The Action is the main adoption surface, and it will process untrusted pull-request
content. The security promises in the threat model — no network, read-only source,
non-root, dropped capabilities, PID and memory limits — must be genuinely enforceable, not
aspirational.

Verified against the GitHub Actions metadata reference: `runs.using: 'docker'` accepts
only `image`, `env`, `entrypoint`, `pre-entrypoint`, `post-entrypoint`, and `args`.
There is **no** key for network mode, mounts, user, or resource limits; the runner
constructs `docker run` itself. A container action therefore cannot promise
`--network=none` or a read-only source mount.

Verified locally: `--read-only` without a writable tmpfs fails immediately —
`sh: can't create /tmp/probe: Read-only file system` — so the tmpfs mounts are
functional requirements, not decoration.

## Decision

Publish a **composite** action that invokes the container itself with explicit flags:

```
docker run --rm --network=none --read-only \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=256 --memory=2g --cpus=2 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --tmpfs /home/iacguard:rw,noexec,nosuid,size=128m \
  -e HOME=/home/iacguard \
  -v "$SRC:/src:ro" -v "$OUT:/out:rw" \
  <image@sha256:...> verify ...
```

Docker isolation on Ubuntu/Linux is the default and only supported mode for untrusted
content. A native pip mode exists, is labelled `reduced-isolation`, is documented as
unsuitable for hostile content, and is **never** auto-selected: if Docker is
unavailable the Action fails closed with exit 3. A reusable workflow is offered for
organisations that want the container pinned centrally.

Default output is the job summary plus a SARIF artifact, so the Action needs no write
permission. Comment posting is opt-in and degrades to the summary when permission is
absent. `pull_request_target` is never used.

## Consequences

- Linux-only for the supported path; documented plainly rather than implied.
- The composite action is more code than a container action, and the `docker run`
  invocation is itself a tested artifact.
- Users who cannot run Docker get an explicit failure and an opt-in alternative rather
  than a silent downgrade.
- The isolation claims are verifiable by reading the action, which is the point.

## Alternatives considered

**Docker container action.** Rejected: cannot enforce the promises made.

**JavaScript action shelling out to Docker.** Rejected: adds a Node toolchain for no
capability a composite action lacks.
