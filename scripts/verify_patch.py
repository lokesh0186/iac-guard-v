#!/usr/bin/env python3
"""
IaC-Guard-V Verification Harness.
Evaluates a repaired Terraform file across 4 verification dimensions:
  V1. Syntax validity
  V2. Target issue resolution
  V3. Regression safety
  V4. Patch minimality
"""
import subprocess
import json
import os
import tempfile
import difflib

CHECKOV_BIN = "checkov"


def check_syntax(tf_content):
    """V1: Check if the repaired content is valid HCL."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.tf', delete=False) as f:
        f.write(tf_content)
        tmp_path = f.name
    try:
        # Use Checkov's parser as syntax check — if it can scan, it can parse
        result = subprocess.run(
            [CHECKOV_BIN, '-f', tmp_path, '--framework', 'terraform',
             '--output', 'json', '--quiet', '--compact'],
            capture_output=True, text=True, timeout=30
        )
        # If Checkov produces JSON output (even with failures), syntax is valid
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                return True, "Parsed successfully"
            except json.JSONDecodeError:
                return False, f"Checkov output not valid JSON: {result.stdout[:200]}"
        # Check stderr for parse errors
        if 'error' in result.stderr.lower() or result.returncode not in (0, 1):
            return False, f"Parse error: {result.stderr[:300]}"
        return True, "No output but no errors"
    except subprocess.TimeoutExpired:
        return False, "Timeout during syntax check"
    except Exception as e:
        return False, str(e)
    finally:
        os.unlink(tmp_path)


def run_checkov_on_content(tf_content):
    """Run Checkov on content and return structured findings."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.tf', delete=False) as f:
        f.write(tf_content)
        tmp_path = f.name
    try:
        result = subprocess.run(
            [CHECKOV_BIN, '-f', tmp_path, '--framework', 'terraform',
             '--output', 'json', '--quiet', '--compact'],
            capture_output=True, text=True, timeout=60
        )
        if result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, list):
                data = data[0] if data else {}
            return data
        return {}
    except Exception as e:
        return {'error': str(e)}
    finally:
        os.unlink(tmp_path)


def check_target_resolution(repaired_content, target_rule_id):
    """V2: Check if the target Checkov rule is resolved in the repaired file."""
    checkov_out = run_checkov_on_content(repaired_content)
    if 'error' in checkov_out:
        return False, checkov_out['error'], checkov_out

    failed = checkov_out.get('results', {}).get('failed_checks', [])
    failed_ids = [c.get('check_id') for c in failed]

    resolved = target_rule_id not in failed_ids
    detail = "Target rule cleared" if resolved else f"Target rule {target_rule_id} still present in {len(failed)} failures"
    return resolved, detail, checkov_out


def check_regression(original_baseline_json, repaired_checkov_output):
    """V3: Check if new issues were introduced by the repair."""
    orig_failed = original_baseline_json.get('results', {}).get('failed_checks', [])
    orig_failed_ids = set(c.get('check_id') for c in orig_failed)

    repair_failed = repaired_checkov_output.get('results', {}).get('failed_checks', [])
    repair_failed_ids = set(c.get('check_id') for c in repair_failed)

    new_issues = repair_failed_ids - orig_failed_ids
    return len(new_issues), list(new_issues)


def check_minimality(original_content, repaired_content):
    """V4: Measure patch size — lines changed, added, removed."""
    orig_lines = original_content.splitlines(keepends=True)
    repair_lines = repaired_content.splitlines(keepends=True)

    diff = list(difflib.unified_diff(orig_lines, repair_lines, lineterm=''))

    added = sum(1 for l in diff if l.startswith('+') and not l.startswith('+++'))
    removed = sum(1 for l in diff if l.startswith('-') and not l.startswith('---'))
    changed = added + removed

    return {
        'lines_added': added,
        'lines_removed': removed,
        'lines_changed': changed,
        'original_lines': len(orig_lines),
        'repaired_lines': len(repair_lines),
        'diff_ratio': round(changed / max(len(orig_lines), 1), 4),
    }


def verify_patch(original_content, repaired_content, target_rule_id, original_baseline_json):
    """
    Run full verification harness on a repaired Terraform file.
    Returns a dict with all verification dimensions and overall verdict.
    """
    results = {
        'target_rule_id': target_rule_id,
        'v1_syntax_valid': False,
        'v1_syntax_detail': '',
        'v2_target_resolved': False,
        'v2_resolution_detail': '',
        'v3_new_issues_count': -1,
        'v3_new_issues_list': [],
        'v4_minimality': {},
        'overall_verified_fix': False,
        'repaired_checkov_output': {},
    }

    # V1: Syntax
    syntax_ok, syntax_detail = check_syntax(repaired_content)
    results['v1_syntax_valid'] = syntax_ok
    results['v1_syntax_detail'] = syntax_detail

    if not syntax_ok:
        return results  # No point checking further if syntax fails

    # V2: Target resolution
    resolved, res_detail, repaired_checkov = check_target_resolution(repaired_content, target_rule_id)
    results['v2_target_resolved'] = resolved
    results['v2_resolution_detail'] = res_detail
    results['repaired_checkov_output'] = repaired_checkov

    # V3: Regression
    new_count, new_list = check_regression(original_baseline_json, repaired_checkov)
    results['v3_new_issues_count'] = new_count
    results['v3_new_issues_list'] = new_list

    # V4: Minimality
    results['v4_minimality'] = check_minimality(original_content, repaired_content)

    # Overall verdict: all gates must pass
    results['overall_verified_fix'] = (
        results['v1_syntax_valid']
        and results['v2_target_resolved']
        and results['v3_new_issues_count'] == 0
    )

    return results


if __name__ == '__main__':
    # Quick self-test with a trivial example
    original = 'resource "aws_s3_bucket" "fail" {\n  bucket = "test"\n}\n'
    repaired = 'resource "aws_s3_bucket" "fail" {\n  bucket = "test"\n}\n'
    baseline = {'results': {'failed_checks': [{'check_id': 'CKV_AWS_18'}], 'passed_checks': []}}

    result = verify_patch(original, repaired, 'CKV_AWS_18', baseline)
    print(json.dumps({k: v for k, v in result.items() if k != 'repaired_checkov_output'}, indent=2))
