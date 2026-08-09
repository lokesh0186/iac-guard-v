# Validation Log

Unedited command output for every gate in the adoption programme. Paths are
repository-relative or use `$REPO_ROOT` / `$TEMP_ROOT`; absolute local paths,
usernames, and hostnames are never recorded here.

Conventions:
- Commands are shown exactly as run, from `$REPO_ROOT`.
- Output is pasted unedited except for path substitution noted above.
- A gate is only "passed" when its recorded output says so.

---

## Environment of record

| Item | Value |
| --- | --- |
| Audited commit | `7646d5930832cc7a6b4dcd7c59de57a6c50fc4b5` |
| Branch | `adoption/p1-research-and-spec` |
| Python | 3.11.5 |
| git | 2.50.1 |
| Docker | 29.6.2 (present; not used in Phases A–C) |
| checkov available locally | 3.3.0 — **differs from the research pin 3.2.517** |
| trivy / conftest available | 0.71.1 / OPA 1.15.2 (not used in Phases A–C) |
| Not installed | kics, tflint, terraform, tofu, kubeconform, gh, pipx, uv |

Phases A–C perform no scanner execution and no model calls.

---

## Gate A — workspace and audit

### A.1 Branch

```console
$ test "$(git rev-parse --abbrev-ref HEAD)" = "adoption/p1-research-and-spec" && echo OK
OK
```

### A.2 Audit citations

```console
$ python3 tools/check_audit_citations.py docs/spec/CURRENT_STATE_AUDIT.md --min 15
distinct valid citations: 34 (minimum 15)
  OK  README.md:220
  OK  README.md:23
  OK  README.md:57
  OK  README.md:92
  OK  docs/VERIFICATION_PROCEDURE.md:15
  OK  docs/VERIFICATION_PROCEDURE.md:22
  OK  requirements.txt:4
  OK  requirements.txt:5
  OK  scripts/analyze_part1.py:13
  OK  scripts/analyze_part1.py:65
  OK  scripts/call_bedrock.py:12
  OK  scripts/call_bedrock.py:25
  OK  scripts/call_bedrock.py:28
  OK  scripts/call_bedrock.py:38
  OK  scripts/call_bedrock.py:62
  OK  scripts/run_baseline_checkov.py:38
  OK  scripts/run_experiment.py:132
  OK  scripts/run_experiment.py:172
  OK  scripts/run_experiment.py:26
  OK  scripts/run_experiment.py:34
  OK  scripts/run_k8s_baseline.py:26
  OK  scripts/verify_patch.py:16
  OK  scripts/verify_patch.py:161
  OK  scripts/verify_patch.py:164
  OK  scripts/verify_patch.py:25
  OK  scripts/verify_patch.py:27
  OK  scripts/verify_patch.py:41
  OK  scripts/verify_patch.py:57
  OK  scripts/verify_patch.py:66
  OK  scripts/verify_patch.py:80
  OK  scripts/verify_patch.py:82
  OK  scripts/verify_patch.py:90
  OK  scripts/verify_patch.py:93
  OK  scripts/verify_patch.py:95
PASS
```

### A.3 Semantic spot-check of quoted lines

```console
$ sed -n '15p;22p' docs/VERIFICATION_PROCEDURE.md
- A verified fix `A'` — a repaired artifact that passes all three binary gates (V1, V2, V3), or
Run Checkov on the original artifact `A` and record the set of failed rule IDs as `B`. This baseline is the reference point for V3 (regression detection): any rule that appears in `B'` (the repaired file's failed rules) but not in `B` is a regression.

$ sed -n '161,165p' scripts/verify_patch.py
    results['overall_verified_fix'] = (
        results['v1_syntax_valid']
        and results['v2_target_resolved']
        and results['v3_new_issues_count'] == 0
    )

$ sed -n '220p' README.md
- **Single scanner**: Results are Checkov-specific; multi-scanner consensus untested.
```

**Gate A: PASS.**

---

<!-- Gate B and Gate C sections are appended by their respective phases. -->
