# Automated contributor testing

Read `docs/TESTING.md` before running tests.

- During implementation, use the `focused` and `dev` profiles.
- Before a pull request, run the `pr` profile once.
- Do not manually recreate `/tmp` compatibility environments unless diagnosing the
  harness itself.
- Never lower or bypass a coverage threshold to make CI pass.
- A reusable local environment is not release proof.
- Owner-authorized release validation must use the clean `release` profile.
- Do not modify frozen research paths or run benchmark inference/model-provider calls.
