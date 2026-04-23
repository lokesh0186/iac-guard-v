#!/usr/bin/env python3
"""
IaC-Guard-V Experiment Runner.
Runs all benchmark items through all methods and models, logs everything.
"""
import csv
import json
import os
import sys
import time
import re

# Add scripts dir to path
sys.path.insert(0, os.path.dirname(__file__))
from call_bedrock import call_model
from verify_patch import verify_patch

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = f"{BASE}/benchmark/selected_manifest_enriched.csv"
RAW_DIR = f"{BASE}/benchmark/raw"
BASELINE_DIR = f"{BASE}/scanners/outputs/baseline"
PROMPTS_DIR = f"{BASE}/prompts"
RUNS_DIR = f"{BASE}/runs/raw"
PATCHES_DIR = f"{BASE}/runs/patches"
LOGS_DIR = f"{BASE}/runs/logs"
RESULTS_CSV = f"{BASE}/results/tables/all_runs.csv"

os.makedirs(RUNS_DIR, exist_ok=True)
os.makedirs(PATCHES_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(os.path.dirname(RESULTS_CSV), exist_ok=True)

METHODS = ['plain', 'structured', 'verify_loop']
MAX_RETRIES = 2  # For verify_loop method


def load_prompt(method):
    """Load prompt template for a method."""
    filemap = {'plain': 'plain_v1.txt', 'structured': 'structured_v1.txt', 'verify_loop': 'structured_v1.txt'}
    with open(os.path.join(PROMPTS_DIR, filemap[method])) as f:
        return f.read()


def load_retry_prompt():
    with open(os.path.join(PROMPTS_DIR, 'retry_v1.txt')) as f:
        return f.read()


def extract_fixed_artifact(response_text, method):
    """Extract the fixed Terraform content from model response."""
    if method == 'plain':
        # Plain method: response should be raw HCL
        text = response_text.strip()
        # Strip markdown code fences if present
        text = re.sub(r'^```(?:hcl|terraform)?\s*\n', '', text)
        text = re.sub(r'\n```\s*$', '', text)
        return text

    # Structured/verify_loop: extract from JSON
    text = response_text.strip()
    # Strip markdown code fences
    text = re.sub(r'^```(?:json)?\s*\n', '', text)
    text = re.sub(r'\n```\s*$', '', text)

    try:
        data = json.loads(text)
        return data.get('fixed_artifact', '')
    except json.JSONDecodeError:
        # Try to find JSON in the response
        match = re.search(r'\{[\s\S]*"fixed_artifact"[\s\S]*\}', text)
        if match:
            try:
                data = json.loads(match.group())
                return data.get('fixed_artifact', '')
            except json.JSONDecodeError:
                pass
        return ''


def build_prompt(template, item, artifact_text, **kwargs):
    """Fill in prompt template with item data."""
    return template.format(
        artifact_text=artifact_text,
        checkov_rule_id=item.get('checkov_rule_id', ''),
        checkov_rule_name=item.get('checkov_rule_name', ''),
        violation_class=item.get('violation_class', ''),
        resource=item.get('baseline_target_resource', ''),
        file_line_range=item.get('baseline_target_lines', ''),
        **kwargs,
    )


def run_single(item, model_name, method):
    """Run a single benchmark item through one method and model."""
    aid = item['artifact_id']
    target_rule = item['checkov_rule_id']

    # Load original artifact
    tf_path = os.path.join(RAW_DIR, item['benchmark_file'])
    with open(tf_path) as f:
        original_text = f.read()

    # Load baseline Checkov output
    baseline_path = os.path.join(BASELINE_DIR, f"{aid}_baseline.json")
    with open(baseline_path) as f:
        baseline_json = json.load(f)

    # Build prompt
    template = load_prompt(method)
    prompt = build_prompt(template, item, original_text)

    # Call model
    try:
        response_text, call_meta = call_model(model_name, prompt)
    except Exception as e:
        return {
            'artifact_id': aid, 'model': model_name, 'method': method,
            'error': str(e), 'overall_verified_fix': False,
        }

    # Extract fixed artifact
    fixed_text = extract_fixed_artifact(response_text, method)

    if not fixed_text.strip():
        return {
            'artifact_id': aid, 'model': model_name, 'method': method,
            'error': 'empty_extraction', 'raw_response_length': len(response_text),
            'overall_verified_fix': False, **call_meta,
        }

    # Verify
    verification = verify_patch(original_text, fixed_text, target_rule, baseline_json)

    # For verify_loop: retry if verification fails
    attempts = [{'attempt': 1, 'response': response_text, 'fixed_text': fixed_text, 'verification': verification}]

    if method == 'verify_loop' and not verification['overall_verified_fix']:
        retry_template = load_retry_prompt()
        for retry_num in range(2, MAX_RETRIES + 2):
            # Build feedback for retry
            checkov_feedback = json.dumps(
                {k: v for k, v in verification.items() if k != 'repaired_checkov_output'},
                indent=2
            )
            retry_prompt = retry_template.format(
                artifact_text=original_text,
                checkov_rule_id=target_rule,
                checkov_rule_name=item.get('checkov_rule_name', ''),
                violation_class=item.get('violation_class', ''),
                resource=item.get('baseline_target_resource', ''),
                previous_attempt=fixed_text,
                syntax_valid=verification['v1_syntax_valid'],
                target_resolved=verification['v2_target_resolved'],
                new_issues_count=verification['v3_new_issues_count'],
                checkov_feedback=checkov_feedback,
            )

            try:
                retry_response, retry_meta = call_model(model_name, retry_prompt)
                call_meta['input_tokens'] += retry_meta.get('input_tokens', 0)
                call_meta['output_tokens'] += retry_meta.get('output_tokens', 0)
                call_meta['latency_seconds'] += retry_meta.get('latency_seconds', 0)
            except Exception as e:
                attempts.append({'attempt': retry_num, 'error': str(e)})
                break

            fixed_text = extract_fixed_artifact(retry_response, 'structured')
            if not fixed_text.strip():
                attempts.append({'attempt': retry_num, 'error': 'empty_extraction'})
                break

            verification = verify_patch(original_text, fixed_text, target_rule, baseline_json)
            attempts.append({'attempt': retry_num, 'response': retry_response, 'fixed_text': fixed_text, 'verification': verification})

            if verification['overall_verified_fix']:
                break

    # Use final attempt's results
    final_verification = attempts[-1].get('verification', verification)

    # Save patch
    patch_file = f"{aid}_{model_name}_{method}.tf"
    with open(os.path.join(PATCHES_DIR, patch_file), 'w') as f:
        f.write(fixed_text)

    # Build result row
    result = {
        'artifact_id': aid,
        'model': model_name,
        'method': method,
        'checkov_rule_id': target_rule,
        'violation_class': item.get('violation_class', ''),
        'v1_syntax_valid': final_verification.get('v1_syntax_valid', False),
        'v2_target_resolved': final_verification.get('v2_target_resolved', False),
        'v3_new_issues_count': final_verification.get('v3_new_issues_count', -1),
        'v4_lines_changed': final_verification.get('v4_minimality', {}).get('lines_changed', -1),
        'v4_diff_ratio': final_verification.get('v4_minimality', {}).get('diff_ratio', -1),
        'overall_verified_fix': final_verification.get('overall_verified_fix', False),
        'num_attempts': len(attempts),
        'input_tokens': call_meta.get('input_tokens', 0),
        'output_tokens': call_meta.get('output_tokens', 0),
        'latency_seconds': call_meta.get('latency_seconds', 0),
        'error': '',
    }

    # Save full run log as JSONL
    log_entry = {**result, 'attempts': [{k: v for k, v in a.items() if k != 'verification' or True} for a in attempts]}
    # Strip large fields for log readability
    for a in log_entry['attempts']:
        if 'verification' in a and isinstance(a['verification'], dict):
            a['verification'] = {k: v for k, v in a['verification'].items() if k != 'repaired_checkov_output'}
    log_file = os.path.join(RUNS_DIR, f"{aid}_{model_name}_{method}.json")
    with open(log_file, 'w') as f:
        json.dump(log_entry, f, indent=2, default=str)

    return result


def main():
    # Load manifest
    with open(MANIFEST) as f:
        items = list(csv.DictReader(f))

    # Parse CLI args for model/method filtering
    models = sys.argv[1].split(',') if len(sys.argv) > 1 else ['claude-sonnet-4.6']
    methods = sys.argv[2].split(',') if len(sys.argv) > 2 else METHODS
    max_items = int(sys.argv[3]) if len(sys.argv) > 3 else len(items)

    items = items[:max_items]
    total = len(items) * len(models) * len(methods)

    print(f"IaC-Guard-V Experiment Runner")
    print(f"Items: {len(items)} | Models: {models} | Methods: {methods}")
    print(f"Total runs: {total}")
    print(f"{'='*70}")

    all_results = []
    run_num = 0

    for model in models:
        for method in methods:
            print(f"\n--- {model} / {method} ---")
            for item in items:
                run_num += 1
                aid = item['artifact_id']
                print(f"  [{run_num:3d}/{total}] {aid} ({item['checkov_rule_id']})...", end=' ', flush=True)

                result = run_single(item, model, method)
                all_results.append(result)

                status = "✅ VERIFIED" if result['overall_verified_fix'] else "❌"
                detail = f"syn={result['v1_syntax_valid']} res={result['v2_target_resolved']} reg={result['v3_new_issues_count']} Δ={result['v4_lines_changed']}"
                print(f"{status} ({detail}) [{result['latency_seconds']:.1f}s]")

    # Write results CSV (append if exists, create if not)
    if all_results:
        file_exists = os.path.exists(RESULTS_CSV)
        with open(RESULTS_CSV, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
            if not file_exists:
                writer.writeheader()
            writer.writerows(all_results)

    # Print summary
    print(f"\n{'='*70}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*70}")
    for model in models:
        for method in methods:
            subset = [r for r in all_results if r['model'] == model and r['method'] == method]
            verified = sum(1 for r in subset if r['overall_verified_fix'])
            syntax = sum(1 for r in subset if r['v1_syntax_valid'])
            resolved = sum(1 for r in subset if r['v2_target_resolved'])
            no_reg = sum(1 for r in subset if r['v3_new_issues_count'] == 0)
            n = len(subset)
            print(f"  {model} / {method}:")
            print(f"    Syntax valid:     {syntax}/{n} ({100*syntax/max(n,1):.1f}%)")
            print(f"    Target resolved:  {resolved}/{n} ({100*resolved/max(n,1):.1f}%)")
            print(f"    No regressions:   {no_reg}/{n} ({100*no_reg/max(n,1):.1f}%)")
            print(f"    VERIFIED FIX:     {verified}/{n} ({100*verified/max(n,1):.1f}%)")

    print(f"\nResults CSV: {RESULTS_CSV}")
    print(f"Run logs: {RUNS_DIR}/")
    print(f"Patches: {PATCHES_DIR}/")


if __name__ == '__main__':
    main()
