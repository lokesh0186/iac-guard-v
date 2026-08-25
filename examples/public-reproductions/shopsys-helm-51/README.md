# Shopsys Helm PR #51: candidate-property acceptance

Third-party pull request:
[shopsys/helm#51](https://github.com/shopsys/helm/pull/51)

Verified repository identities:

- Base: `29da91c8abd4d4e4c04d0d2a528b3c71cbae44c8`
- Candidate head: `381ceb17d5b630e38f6f6755c40acebd2a44d715`

Verifier:

- IaC-Guard-V `0.1.0a5`
- PyPI: `iac-guard-v==0.1.0a5`
- Software DOI: [10.5281/zenodo.22099303](https://doi.org/10.5281/zenodo.22099303)
- Checkov `3.3.0`
- Helm `4.2.4`, Darwin arm64 executable SHA-256 `ebf04b3606784d48568cf386483ac2b81fc747ed77859da4ba4f77df4c5e81d3`

## Result

IaC-Guard-V returned `VERIFIED` in `candidate_acceptance` mode for five selected Checkov `CKV2_K8S_6` properties:

- `apps/v1/Deployment/default/webserver-php-fpm`
- `apps/v1/Deployment/default/storefront`
- `apps/v1/Deployment/default/cron`
- `apps/v1/Deployment/default/redis`
- `apps/v1/StatefulSet/default/rabbitmq`

Each property is `SATISFIED`. The app and infra charts were rendered twice as one protected multi-chart universe. All 37 rendered resources remain in the governed resource universe. The exact workload, NetworkPolicy, namespace, selector, source provenance, and relationship evidence are bound in [report.json](report.json).

Checkov's raw run status remains `PARTIAL`. IaC-Guard-V does not hide that status. Twenty-seven governed resources are not primary scanner targets for the selected rule. One NetworkPolicy without a standalone Checkov evaluation remains governed and is structurally proven irrelevant to each selected workload property where that proof is used.

## Protected materialization identities

- Combined universe: `29868b6302074e82cf843c7b47ec9d46c4e0a6e9136cb37809cdcccb3dea250e`
- App chart inventory root: `2c58f5960d4237003c783851dbd9c787d3ea5c23e6ae39373ba7f4135c5366e1`
- App materialization: `2db4751586b89ca88594230a932b1a688ad5e15f58f013122b491220320756a6`
- App rendered bundle: `4b49009af1d693fcfc56f428f649b84d61323fca8df911c397b4691488c59035`
- Infra chart inventory root: `4386bf499b5726ec06ab711c67f5a0e4c7ab7e893c646733c01a704fc3a26f73`
- Infra materialization: `a0bd1ffc6091b70e405146fa3c9d5b0c348b5f352b949f6a7fa6d6117cc6fdec`
- Infra rendered bundle: `c017c8935c44e6589456262648705e284c931cfe10a55be5cb38d0ca7c1046d5`
- Combined rendered bundle: `794a49073335e99e175a14504348b69cf00a517a03bdf7749cda99076b564ece`

Canonical report SHA-256:

```text
a71c899ce22d0d5ab61b6a3a6eebb29961a2f9b6545f57698f761c422325ef00  report.json
```

## Scope

This is candidate-property acceptance, not baseline repair verification. `SATISFIED` means the five selected properties hold in the proposed candidate configuration under IaC-Guard-V's protected static-evidence contract. No property is labelled `FIXED` because the base revision cannot express the candidate's new NetworkPolicy values contract.

This is not a whole-chart or whole-PR security claim. It does not establish runtime CNI enforcement, admission behavior, application protocol security, or the correctness of unselected changes.

See [REPRODUCE.md](REPRODUCE.md) for the protected inputs and command.
