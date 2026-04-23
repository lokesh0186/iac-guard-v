#!/usr/bin/env python3
"""
IaC-Guard-V Analysis Script — Part 2: Statistical Tests
Cochran's Q, McNemar's, Cliff's delta, Bonferroni correction.
"""
import csv
import os
import numpy as np
from itertools import combinations

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_CSV = f"{BASE}/results/tables/all_runs.csv"
TABLES_DIR = f"{BASE}/results/tables"
STATS_DIR = f"{BASE}/results/stats"
os.makedirs(STATS_DIR, exist_ok=True)

# Load
with open(RESULTS_CSV) as f:
    ALL_RUNS = list(csv.DictReader(f))
for r in ALL_RUNS:
    r['overall_verified_fix'] = r['overall_verified_fix'] == 'True'
    r['technology'] = 'kubernetes' if r['artifact_id'].startswith('BM-2') or r['artifact_id'].startswith('BM-3') else 'terraform'

models = sorted(set(r['model'] for r in ALL_RUNS))
methods = ['plain', 'structured', 'verify_loop']
technologies = ['terraform', 'kubernetes']

# ============================================================
# COCHRAN'S Q TEST
# ============================================================
def cochrans_q(binary_matrix):
    """Cochran's Q test for k related samples. binary_matrix: n_items × k_methods."""
    k = binary_matrix.shape[1]
    n = binary_matrix.shape[0]
    T = binary_matrix.sum()
    Tj = binary_matrix.sum(axis=0)  # column sums
    Li = binary_matrix.sum(axis=1)  # row sums
    num = (k - 1) * (k * np.sum(Tj**2) - T**2)
    den = k * T - np.sum(Li**2)
    if den == 0:
        return 0.0, 1.0
    Q = num / den
    from scipy.stats import chi2
    p = 1 - chi2.cdf(Q, k - 1)
    return round(Q, 4), round(p, 6)

# ============================================================
# McNEMAR'S TEST
# ============================================================
def mcnemar_test(a_results, b_results):
    """McNemar's test for paired binary outcomes. Returns chi2, p-value."""
    n01 = sum(1 for a, b in zip(a_results, b_results) if not a and b)  # a fails, b succeeds
    n10 = sum(1 for a, b in zip(a_results, b_results) if a and not b)  # a succeeds, b fails
    if n01 + n10 == 0:
        return 0.0, 1.0
    # Use exact binomial test for small counts
    if n01 + n10 < 25:
        from scipy.stats import binomtest
        p = binomtest(n01, n01 + n10, 0.5).pvalue
        return round((n01 - n10)**2 / (n01 + n10), 4), round(p, 6)
    chi2 = (abs(n01 - n10) - 1)**2 / (n01 + n10)  # with continuity correction
    from scipy.stats import chi2 as chi2_dist
    p = 1 - chi2_dist.cdf(chi2, 1)
    return round(chi2, 4), round(p, 6)

# ============================================================
# CLIFF'S DELTA
# ============================================================
def cliffs_delta(a_results, b_results):
    """Cliff's delta for paired binary outcomes."""
    n = len(a_results)
    if n == 0:
        return 0.0, 'negligible'
    more = sum(1 for a, b in zip(a_results, b_results) if b > a)
    less = sum(1 for a, b in zip(a_results, b_results) if b < a)
    delta = (more - less) / n
    # Effect size interpretation
    abs_d = abs(delta)
    if abs_d < 0.147:
        effect = 'negligible'
    elif abs_d < 0.33:
        effect = 'small'
    elif abs_d < 0.474:
        effect = 'medium'
    else:
        effect = 'large'
    return round(delta, 4), effect

# ============================================================
# RUN ALL TESTS
# ============================================================
print("=" * 80)
print("STATISTICAL TESTS")
print("=" * 80)

all_stats = []
n_comparisons = 0

for tech in technologies:
    for model in models:
        # Get items for this model × technology
        items_by_method = {}
        for method in methods:
            subset = [r for r in ALL_RUNS if r['model'] == model and r['method'] == method and r['technology'] == tech]
            if subset:
                items_by_method[method] = {r['artifact_id']: r['overall_verified_fix'] for r in subset}

        if len(items_by_method) < 2:
            continue

        # Get common items
        common_items = sorted(set.intersection(*[set(v.keys()) for v in items_by_method.values()]))
        if not common_items:
            continue

        print(f"\n--- {tech.upper()} / {model} (n={len(common_items)}) ---")

        # Cochran's Q
        available_methods = [m for m in methods if m in items_by_method]
        matrix = np.array([[1 if items_by_method[m][item] else 0 for m in available_methods] for item in common_items])
        Q, q_p = cochrans_q(matrix)
        print(f"  Cochran's Q: Q={Q}, p={q_p} {'***' if q_p < 0.001 else '**' if q_p < 0.01 else '*' if q_p < 0.05 else 'ns'}")

        # Pairwise McNemar's + Cliff's delta
        for m_a, m_b in combinations(available_methods, 2):
            a_vals = [items_by_method[m_a][item] for item in common_items]
            b_vals = [items_by_method[m_b][item] for item in common_items]

            chi2, p = mcnemar_test(a_vals, b_vals)
            delta, effect = cliffs_delta(a_vals, b_vals)
            n_comparisons += 1

            rate_a = round(100 * sum(a_vals) / len(a_vals), 1)
            rate_b = round(100 * sum(b_vals) / len(b_vals), 1)

            row = {
                'technology': tech, 'model': model,
                'method_a': m_a, 'method_b': m_b,
                'rate_a': rate_a, 'rate_b': rate_b,
                'mcnemar_chi2': chi2, 'mcnemar_p': p,
                'cliffs_delta': delta, 'effect_size': effect,
                'n_items': len(common_items),
            }
            all_stats.append(row)
            sig = '***' if p < 0.001 else '**' if p < 0.01 else '*' if p < 0.05 else 'ns'
            print(f"  {m_a:12s} vs {m_b:12s}: {rate_a}% vs {rate_b}% | McNemar p={p:.6f} {sig} | Cliff's δ={delta} ({effect})")

# Bonferroni correction
bonferroni_threshold = 0.05 / max(n_comparisons, 1)
print(f"\n{'='*80}")
print(f"BONFERRONI CORRECTION")
print(f"Total pairwise comparisons: {n_comparisons}")
print(f"Bonferroni threshold: {bonferroni_threshold:.6f}")
print(f"{'='*80}")

for row in all_stats:
    row['bonferroni_threshold'] = round(bonferroni_threshold, 6)
    row['bonferroni_significant'] = row['mcnemar_p'] < bonferroni_threshold
    sig = "✅ SIG" if row['bonferroni_significant'] else "❌ ns"
    print(f"  {row['technology']:10s} {row['model']:20s} {row['method_a']:12s} vs {row['method_b']:12s}: p={row['mcnemar_p']:.6f} {sig}")

# Save
with open(f"{TABLES_DIR}/statistical_tests.csv", 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=all_stats[0].keys())
    writer.writeheader()
    writer.writerows(all_stats)

print(f"\nSaved: {TABLES_DIR}/statistical_tests.csv")
print("Part 2 complete. Run analyze_part3.py for deep analyses.")
