#!/usr/bin/env python3
"""
IaC-Guard-V Analysis Script — Part 3: Deep Analyses
Difficulty scores, regression analysis, minimality, convergence, failure categorization,
sensitivity analysis, items where plain beats verify-loop, retry marginal value.
"""
import csv
import json
import os
import numpy as np
from collections import Counter, defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_CSV = f"{BASE}/results/tables/all_runs.csv"
RUNS_DIR = f"{BASE}/runs/raw"
TABLES_DIR = f"{BASE}/results/tables"
STATS_DIR = f"{BASE}/results/stats"

with open(RESULTS_CSV) as f:
    ALL_RUNS = list(csv.DictReader(f))
for r in ALL_RUNS:
    r['overall_verified_fix'] = r['overall_verified_fix'] == 'True'
    r['v1_syntax_valid'] = r['v1_syntax_valid'] == 'True'
    r['v2_target_resolved'] = r['v2_target_resolved'] == 'True'
    r['v3_new_issues_count'] = int(r['v3_new_issues_count'])
    r['v4_lines_changed'] = int(r['v4_lines_changed']) if r['v4_lines_changed'] not in ('', '-1') else -1
    r['latency_seconds'] = float(r['latency_seconds']) if r['latency_seconds'] else 0
    r['num_attempts'] = int(r['num_attempts']) if r['num_attempts'] else 1
    r['technology'] = 'kubernetes' if r['artifact_id'].startswith('BM-2') or r['artifact_id'].startswith('BM-3') else 'terraform'

# ============================================================
# 1. PER-ITEM DIFFICULTY SCORE
# ============================================================
print("=" * 80)
print("ANALYSIS 1: PER-ITEM DIFFICULTY SCORE")
print("=" * 80)

for tech in ['terraform', 'kubernetes']:
    tech_runs = [r for r in ALL_RUNS if r['technology'] == tech]
    items = sorted(set(r['artifact_id'] for r in tech_runs))
    difficulty = []
    for item in items:
        item_runs = [r for r in tech_runs if r['artifact_id'] == item]
        fixes = sum(r['overall_verified_fix'] for r in item_runs)
        total = len(item_runs)
        cls = item_runs[0].get('violation_class', 'unknown')
        difficulty.append({'artifact_id': item, 'technology': tech, 'violation_class': cls,
                          'fixes_out_of': total, 'fix_count': fixes,
                          'difficulty': 'easy' if fixes >= 7 else 'medium' if fixes >= 4 else 'hard'})

    dist = Counter(d['difficulty'] for d in difficulty)
    print(f"\n{tech.upper()}: {len(items)} items")
    print(f"  Easy (7-9 fixes): {dist.get('easy', 0)}")
    print(f"  Medium (4-6):     {dist.get('medium', 0)}")
    print(f"  Hard (0-3):       {dist.get('hard', 0)}")

    # Hard items by class
    hard = [d for d in difficulty if d['difficulty'] == 'hard']
    if hard:
        hard_classes = Counter(d['violation_class'] for d in hard)
        print(f"  Hard items by class: {dict(hard_classes.most_common())}")
        for h in hard:
            print(f"    {h['artifact_id']}: {h['fix_count']}/{h['fixes_out_of']} fixes [{h['violation_class']}]")

    with open(f"{TABLES_DIR}/difficulty_{tech}.csv", 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=difficulty[0].keys())
        writer.writeheader()
        writer.writerows(difficulty)

# ============================================================
# 2. REGRESSION DEEP-DIVE
# ============================================================
print("\n" + "=" * 80)
print("ANALYSIS 2: REGRESSION DEEP-DIVE")
print("=" * 80)

regressions = [r for r in ALL_RUNS if r['v3_new_issues_count'] > 0]
print(f"Total runs with regressions: {len(regressions)} / {len(ALL_RUNS)}")

reg_by_method = Counter(r['method'] for r in regressions)
print(f"By method: {dict(reg_by_method.most_common())}")

reg_by_model = Counter(r['model'] for r in regressions)
print(f"By model: {dict(reg_by_model.most_common())}")

reg_by_class = Counter(r['violation_class'] for r in regressions)
print(f"By violation class: {dict(reg_by_class.most_common())}")

reg_by_tech = Counter(r['technology'] for r in regressions)
print(f"By technology: {dict(reg_by_tech.most_common())}")

print("\nDetailed regression items:")
for r in regressions:
    print(f"  {r['artifact_id']} | {r['model']:20s} | {r['method']:12s} | +{r['v3_new_issues_count']} new issues | {r['violation_class']} | {r['technology']}")

# ============================================================
# 3. MINIMALITY COMPARISON
# ============================================================
print("\n" + "=" * 80)
print("ANALYSIS 3: MINIMALITY (V4) COMPARISON")
print("=" * 80)

for tech in ['terraform', 'kubernetes']:
    print(f"\n{tech.upper()}:")
    for method in ['plain', 'structured', 'verify_loop']:
        subset = [r for r in ALL_RUNS if r['method'] == method and r['technology'] == tech and r['v4_lines_changed'] > 0]
        if not subset:
            continue
        changes = [r['v4_lines_changed'] for r in subset]
        verified = [r for r in subset if r['overall_verified_fix']]
        verified_changes = [r['v4_lines_changed'] for r in verified] if verified else [0]
        print(f"  {method:12s}: mean={np.mean(changes):5.1f}, median={np.median(changes):5.1f}, "
              f"p95={np.percentile(changes, 95):5.1f} (all) | "
              f"mean={np.mean(verified_changes):5.1f}, median={np.median(verified_changes):5.1f} (verified only)")

# ============================================================
# 4. CONVERGENCE ANALYSIS (VERIFY-LOOP ONLY)
# ============================================================
print("\n" + "=" * 80)
print("ANALYSIS 4: CONVERGENCE (VERIFY-LOOP ATTEMPTS)")
print("=" * 80)

convergence_results = []
for tech in ['terraform', 'kubernetes']:
    for model in sorted(set(r['model'] for r in ALL_RUNS)):
        vl_runs = [r for r in ALL_RUNS if r['model'] == model and r['method'] == 'verify_loop' and r['technology'] == tech]
        if not vl_runs:
            continue

        attempt_fixes = {1: 0, 2: 0, 3: 0, 'never': 0}
        for r in vl_runs:
            log_file = os.path.join(RUNS_DIR, f"{r['artifact_id']}_{model}_verify_loop.json")
            if os.path.exists(log_file):
                with open(log_file) as f:
                    log = json.load(f)
                attempts = log.get('attempts', [])
                fixed_at = 'never'
                for i, a in enumerate(attempts):
                    v = a.get('verification', {})
                    if v.get('overall_verified_fix', False):
                        fixed_at = i + 1
                        break
                if fixed_at == 'never':
                    attempt_fixes['never'] += 1
                else:
                    attempt_fixes[min(fixed_at, 3)] += 1
            else:
                if r['overall_verified_fix']:
                    attempt_fixes[1] += 1
                else:
                    attempt_fixes['never'] += 1

        total = len(vl_runs)
        row = {'technology': tech, 'model': model, 'total': total,
               'attempt_1': attempt_fixes[1], 'attempt_2': attempt_fixes[2],
               'attempt_3': attempt_fixes[3], 'never': attempt_fixes['never']}
        convergence_results.append(row)
        print(f"  {tech:10s} {model:20s}: att1={attempt_fixes[1]} att2={attempt_fixes[2]} att3={attempt_fixes[3]} never={attempt_fixes['never']}")

with open(f"{TABLES_DIR}/convergence.csv", 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=convergence_results[0].keys())
    writer.writeheader()
    writer.writerows(convergence_results)

# ============================================================
# 5. ITEMS WHERE PLAIN BEATS VERIFY-LOOP
# ============================================================
print("\n" + "=" * 80)
print("ANALYSIS 5: ITEMS WHERE PLAIN BEATS VERIFY-LOOP")
print("=" * 80)

for tech in ['terraform', 'kubernetes']:
    for model in sorted(set(r['model'] for r in ALL_RUNS)):
        plain_runs = {r['artifact_id']: r for r in ALL_RUNS if r['model'] == model and r['method'] == 'plain' and r['technology'] == tech}
        vl_runs = {r['artifact_id']: r for r in ALL_RUNS if r['model'] == model and r['method'] == 'verify_loop' and r['technology'] == tech}
        common = set(plain_runs.keys()) & set(vl_runs.keys())

        plain_wins = [item for item in common if plain_runs[item]['overall_verified_fix'] and not vl_runs[item]['overall_verified_fix']]
        if plain_wins:
            print(f"\n  {tech} / {model}: {len(plain_wins)} items where plain wins over verify-loop:")
            for item in plain_wins:
                pr = plain_runs[item]
                vr = vl_runs[item]
                print(f"    {item}: plain=✅ verify=❌ | class={pr['violation_class']} | verify: resolved={vr['v2_target_resolved']}, reg={vr['v3_new_issues_count']}")

# ============================================================
# 6. SENSITIVITY ANALYSIS (EXCLUDING PROBLEMATIC ITEMS)
# ============================================================
print("\n" + "=" * 80)
print("ANALYSIS 6: SENSITIVITY (EXCLUDING HARNESS-LIMITED ITEMS)")
print("=" * 80)

EXCLUDE_ITEMS = {'BM-0276', 'BM-0449', 'BM-0040'}  # 2 harness-limited + 1 graph-based
filtered = [r for r in ALL_RUNS if r['artifact_id'] not in EXCLUDE_ITEMS]

print(f"Full benchmark: {len(ALL_RUNS)} runs")
print(f"Excluding {len(EXCLUDE_ITEMS)} items: {len(filtered)} runs")

for tech in ['terraform']:
    for model in sorted(set(r['model'] for r in filtered)):
        for method in ['plain', 'structured', 'verify_loop']:
            full = [r for r in ALL_RUNS if r['model'] == model and r['method'] == method and r['technology'] == tech]
            filt = [r for r in filtered if r['model'] == model and r['method'] == method and r['technology'] == tech]
            if not full or not filt:
                continue
            full_rate = round(100 * sum(r['overall_verified_fix'] for r in full) / len(full), 1)
            filt_rate = round(100 * sum(r['overall_verified_fix'] for r in filt) / len(filt), 1)
            delta = round(filt_rate - full_rate, 1)
            print(f"  {model:20s} {method:12s}: full={full_rate}% → filtered={filt_rate}% (Δ={delta:+.1f}pp)")

# ============================================================
# 7. RETRY MARGINAL VALUE (1 RETRY VS 2 RETRIES)
# ============================================================
print("\n" + "=" * 80)
print("ANALYSIS 7: RETRY MARGINAL VALUE")
print("=" * 80)

for tech in ['terraform', 'kubernetes']:
    for model in sorted(set(r['model'] for r in ALL_RUNS)):
        vl_runs = [r for r in ALL_RUNS if r['model'] == model and r['method'] == 'verify_loop' and r['technology'] == tech]
        if not vl_runs:
            continue

        fixed_by_1 = 0
        fixed_by_2 = 0
        fixed_by_3 = 0
        total = len(vl_runs)

        for r in vl_runs:
            log_file = os.path.join(RUNS_DIR, f"{r['artifact_id']}_{model}_verify_loop.json")
            if os.path.exists(log_file):
                with open(log_file) as f:
                    log = json.load(f)
                for i, a in enumerate(log.get('attempts', [])):
                    v = a.get('verification', {})
                    if v.get('overall_verified_fix', False):
                        if i == 0: fixed_by_1 += 1
                        elif i == 1: fixed_by_2 += 1
                        else: fixed_by_3 += 1
                        break

        rate_1only = round(100 * fixed_by_1 / total, 1)
        rate_1plus2 = round(100 * (fixed_by_1 + fixed_by_2) / total, 1)
        rate_all = round(100 * (fixed_by_1 + fixed_by_2 + fixed_by_3) / total, 1)
        print(f"  {tech:10s} {model:20s}: 1-retry={rate_1only}% → 2-retry={rate_1plus2}% → 3-retry={rate_all}% | marginal: +{rate_1plus2-rate_1only:.1f}pp, +{rate_all-rate_1plus2:.1f}pp")

# ============================================================
# 8. CROSS-MODEL AGREEMENT
# ============================================================
print("\n" + "=" * 80)
print("ANALYSIS 8: CROSS-MODEL AGREEMENT (VERIFY-LOOP, TERRAFORM)")
print("=" * 80)

tf_models = sorted(set(r['model'] for r in ALL_RUNS if r['technology'] == 'terraform'))
vl_by_model = {}
for model in tf_models:
    vl_by_model[model] = {r['artifact_id']: r['overall_verified_fix']
                          for r in ALL_RUNS if r['model'] == model and r['method'] == 'verify_loop' and r['technology'] == 'terraform'}

common_items = sorted(set.intersection(*[set(v.keys()) for v in vl_by_model.values()]))
all_fix = sum(1 for item in common_items if all(vl_by_model[m][item] for m in tf_models))
none_fix = sum(1 for item in common_items if not any(vl_by_model[m][item] for m in tf_models))
some_fix = len(common_items) - all_fix - none_fix

print(f"Items: {len(common_items)}")
print(f"All 3 models fix:  {all_fix} ({round(100*all_fix/len(common_items),1)}%)")
print(f"No model fixes:    {none_fix} ({round(100*none_fix/len(common_items),1)}%)")
print(f"Disagreement:      {some_fix} ({round(100*some_fix/len(common_items),1)}%)")

# ============================================================
# 9. FAILURE CATEGORIZATION
# ============================================================
print("\n" + "=" * 80)
print("ANALYSIS 9: FAILURE CATEGORIZATION (TERRAFORM VERIFY-LOOP)")
print("=" * 80)

HARNESS_LIMITED = {'BM-0276', 'BM-0449'}
GRAPH_RULES = {'BM-0040'}

for model in tf_models:
    vl = [r for r in ALL_RUNS if r['model'] == model and r['method'] == 'verify_loop' and r['technology'] == 'terraform']
    failures = [r for r in vl if not r['overall_verified_fix']]
    harness = [r for r in failures if r['artifact_id'] in HARNESS_LIMITED]
    graph = [r for r in failures if r['artifact_id'] in GRAPH_RULES]
    model_fail = [r for r in failures if r['artifact_id'] not in HARNESS_LIMITED and r['artifact_id'] not in GRAPH_RULES]

    print(f"\n  {model}: {len(failures)} failures")
    print(f"    Harness limitation: {len(harness)}")
    print(f"    Graph-based rules:  {len(graph)}")
    print(f"    Model limitation:   {len(model_fail)}")
    for r in model_fail:
        print(f"      {r['artifact_id']}: {r['checkov_rule_id']} [{r['violation_class']}] resolved={r['v2_target_resolved']} reg={r['v3_new_issues_count']}")

print("\n" + "=" * 80)
print("ALL DEEP ANALYSES COMPLETE")
print(f"Results saved to: {TABLES_DIR}/")
print("=" * 80)
