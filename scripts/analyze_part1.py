#!/usr/bin/env python3
"""
IaC-Guard-V Analysis Script — Part 1: Data Loading and Core Metrics
Loads all 630 runs and computes verified-fix rates, bootstrap CIs, and per-dimension breakdowns.
"""
import csv
import json
import os
import numpy as np
from collections import Counter, defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_CSV = f"{BASE}/results/tables/all_runs.csv"
TABLES_DIR = f"{BASE}/results/tables"
STATS_DIR = f"{BASE}/results/stats"
os.makedirs(TABLES_DIR, exist_ok=True)
os.makedirs(STATS_DIR, exist_ok=True)

# Load all runs
with open(RESULTS_CSV) as f:
    ALL_RUNS = list(csv.DictReader(f))

# Convert types
for r in ALL_RUNS:
    r['v1_syntax_valid'] = r['v1_syntax_valid'] == 'True'
    r['v2_target_resolved'] = r['v2_target_resolved'] == 'True'
    r['v3_new_issues_count'] = int(r['v3_new_issues_count'])
    r['v4_lines_changed'] = int(r['v4_lines_changed']) if r['v4_lines_changed'] not in ('', '-1') else -1
    r['v4_diff_ratio'] = float(r['v4_diff_ratio']) if r['v4_diff_ratio'] not in ('', '-1') else -1
    r['overall_verified_fix'] = r['overall_verified_fix'] == 'True'
    r['input_tokens'] = int(r['input_tokens']) if r['input_tokens'] else 0
    r['output_tokens'] = int(r['output_tokens']) if r['output_tokens'] else 0
    r['latency_seconds'] = float(r['latency_seconds']) if r['latency_seconds'] else 0
    r['num_attempts'] = int(r['num_attempts']) if r['num_attempts'] else 1
    # Infer technology from artifact_id
    r['technology'] = 'kubernetes' if r['artifact_id'].startswith('BM-2') or r['artifact_id'].startswith('BM-3') else 'terraform'

print(f"Loaded {len(ALL_RUNS)} runs")
print(f"Terraform: {sum(1 for r in ALL_RUNS if r['technology']=='terraform')}")
print(f"Kubernetes: {sum(1 for r in ALL_RUNS if r['technology']=='kubernetes')}")

# ============================================================
# 1. CORE METRICS: Verified-fix rate per model × method × technology
# ============================================================
def compute_rates(runs):
    n = len(runs)
    if n == 0:
        return {}
    return {
        'n': n,
        'syntax_valid': sum(r['v1_syntax_valid'] for r in runs),
        'target_resolved': sum(r['v2_target_resolved'] for r in runs),
        'no_regressions': sum(r['v3_new_issues_count'] == 0 for r in runs),
        'verified_fix': sum(r['overall_verified_fix'] for r in runs),
        'syntax_rate': round(100 * sum(r['v1_syntax_valid'] for r in runs) / n, 1),
        'resolved_rate': round(100 * sum(r['v2_target_resolved'] for r in runs) / n, 1),
        'no_reg_rate': round(100 * sum(r['v3_new_issues_count'] == 0 for r in runs) / n, 1),
        'verified_rate': round(100 * sum(r['overall_verified_fix'] for r in runs) / n, 1),
    }

# ============================================================
# 2. BOOTSTRAP CONFIDENCE INTERVALS
# ============================================================
def bootstrap_ci(runs, metric_key='overall_verified_fix', n_boot=1000, ci=95):
    np.random.seed(42)
    values = [1 if r[metric_key] else 0 for r in runs]
    n = len(values)
    boot_means = []
    for _ in range(n_boot):
        sample = np.random.choice(values, size=n, replace=True)
        boot_means.append(np.mean(sample))
    lower = np.percentile(boot_means, (100 - ci) / 2)
    upper = np.percentile(boot_means, 100 - (100 - ci) / 2)
    return round(lower * 100, 1), round(upper * 100, 1)

# ============================================================
# COMPUTE AND SAVE
# ============================================================
models = sorted(set(r['model'] for r in ALL_RUNS))
methods = ['plain', 'structured', 'verify_loop']
technologies = ['terraform', 'kubernetes']

print("\n" + "=" * 80)
print("TABLE 2 & 3: MAIN RESULTS WITH 95% BOOTSTRAP CI")
print("=" * 80)

main_results = []
for tech in technologies:
    print(f"\n--- {tech.upper()} ---")
    for model in models:
        for method in methods:
            subset = [r for r in ALL_RUNS if r['model'] == model and r['method'] == method and r['technology'] == tech]
            if not subset:
                continue
            rates = compute_rates(subset)
            ci_low, ci_high = bootstrap_ci(subset)
            row = {
                'technology': tech, 'model': model, 'method': method,
                **rates,
                'ci_lower': ci_low, 'ci_upper': ci_high,
            }
            main_results.append(row)
            print(f"  {model:20s} {method:12s}: {rates['verified_rate']:5.1f}% (95% CI: {ci_low}-{ci_high}%) [n={rates['n']}]")

# Save main results
with open(f"{TABLES_DIR}/main_results_with_ci.csv", 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=main_results[0].keys())
    writer.writeheader()
    writer.writerows(main_results)

print(f"\nSaved: {TABLES_DIR}/main_results_with_ci.csv")

# ============================================================
# 3. PER-VIOLATION-CLASS BREAKDOWN
# ============================================================
print("\n" + "=" * 80)
print("TABLE 4: FIX RATE BY VIOLATION CLASS")
print("=" * 80)

class_results = []
for tech in technologies:
    tech_runs = [r for r in ALL_RUNS if r['technology'] == tech]
    classes = sorted(set(r['violation_class'] for r in tech_runs))
    for cls in classes:
        for method in methods:
            subset = [r for r in tech_runs if r['violation_class'] == cls and r['method'] == method]
            if not subset:
                continue
            rates = compute_rates(subset)
            class_results.append({
                'technology': tech, 'violation_class': cls, 'method': method,
                'n': rates['n'], 'verified_rate': rates['verified_rate'],
            })
            print(f"  {tech:10s} {cls:25s} {method:12s}: {rates['verified_rate']:5.1f}% (n={rates['n']})")

with open(f"{TABLES_DIR}/results_by_violation_class.csv", 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=class_results[0].keys())
    writer.writeheader()
    writer.writerows(class_results)

print(f"\nSaved: {TABLES_DIR}/results_by_violation_class.csv")

# ============================================================
# 4. COST-EFFECTIVENESS
# ============================================================
print("\n" + "=" * 80)
print("TABLE 5: COST-EFFECTIVENESS")
print("=" * 80)

cost_results = []
for model in models:
    for method in methods:
        subset = [r for r in ALL_RUNS if r['model'] == model and r['method'] == method]
        if not subset:
            continue
        verified = [r for r in subset if r['overall_verified_fix']]
        avg_tokens = np.mean([r['input_tokens'] + r['output_tokens'] for r in subset])
        avg_latency = np.mean([r['latency_seconds'] for r in subset])
        avg_attempts = np.mean([r['num_attempts'] for r in subset])
        fix_rate = len(verified) / len(subset) * 100
        cost_per_fix = avg_tokens / (len(verified) / len(subset)) if verified else float('inf')

        row = {
            'model': model, 'method': method,
            'n': len(subset), 'verified_fixes': len(verified),
            'verified_rate': round(fix_rate, 1),
            'avg_total_tokens': round(avg_tokens, 0),
            'avg_latency_s': round(avg_latency, 1),
            'avg_attempts': round(avg_attempts, 1),
            'tokens_per_verified_fix': round(cost_per_fix, 0),
        }
        cost_results.append(row)
        print(f"  {model:20s} {method:12s}: {fix_rate:5.1f}% | {avg_tokens:7.0f} tok | {avg_latency:5.1f}s | {avg_attempts:.1f} att")

with open(f"{TABLES_DIR}/cost_effectiveness.csv", 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=cost_results[0].keys())
    writer.writeheader()
    writer.writerows(cost_results)

print(f"\nSaved: {TABLES_DIR}/cost_effectiveness.csv")
print("\nPart 1 complete. Run analyze_part2.py for statistical tests.")
