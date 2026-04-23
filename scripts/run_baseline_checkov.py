#!/usr/bin/env python3
"""
Run Checkov on each selected benchmark item and save baseline findings.
These baseline results are the "before" state for verification comparison.
"""
import subprocess
import json
import csv
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKOV_BIN = "checkov"
RAW_DIR = f"{BASE}/benchmark/raw"
BASELINE_DIR = f"{BASE}/scanners/outputs/baseline"
SELECTED_CSV = f"{BASE}/benchmark/selected_manifest.csv"
ENRICHED_CSV = f"{BASE}/benchmark/selected_manifest_enriched.csv"

os.makedirs(BASELINE_DIR, exist_ok=True)

# Load selected manifest
with open(SELECTED_CSV) as f:
    items = list(csv.DictReader(f))

print(f"Running baseline Checkov scans on {len(items)} items...")
print(f"Saving results to: {BASELINE_DIR}/")
print()

enriched = []

for i, item in enumerate(items):
    aid = item['artifact_id']
    tf_file = os.path.join(RAW_DIR, item['benchmark_file'])
    target_rule = item['checkov_rule_id']
    
    # Run Checkov on individual file
    try:
        result = subprocess.run(
            [CHECKOV_BIN, '-f', tf_file, '--framework', 'terraform', '--output', 'json', '--quiet', '--compact'],
            capture_output=True, text=True, timeout=60
        )
        
        if result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, list):
                data = data[0] if data else {}
        else:
            data = {'error': 'no output', 'stderr': result.stderr[:500]}
    except Exception as e:
        data = {'error': str(e)}
    
    # Save full Checkov JSON
    output_file = os.path.join(BASELINE_DIR, f"{aid}_baseline.json")
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    # Extract key metrics
    results = data.get('results', {})
    failed_checks = results.get('failed_checks', [])
    passed_checks = results.get('passed_checks', [])
    
    # Find the target rule in failed checks
    target_found = any(c.get('check_id') == target_rule for c in failed_checks)
    
    # Get all failed rule IDs
    failed_rule_ids = [c.get('check_id') for c in failed_checks]
    
    # Get target rule details
    target_details = next((c for c in failed_checks if c.get('check_id') == target_rule), {})
    
    # Enrich the manifest item
    enriched_item = dict(item)
    enriched_item['baseline_total_failed'] = len(failed_checks)
    enriched_item['baseline_total_passed'] = len(passed_checks)
    enriched_item['baseline_target_found'] = target_found
    enriched_item['baseline_failed_rules'] = '|'.join(failed_rule_ids)
    enriched_item['baseline_target_resource'] = target_details.get('resource', '')
    enriched_item['baseline_target_lines'] = str(target_details.get('file_line_range', []))
    enriched_item['baseline_json_file'] = f"{aid}_baseline.json"
    enriched.append(enriched_item)
    
    status = "✅" if target_found else "❌ TARGET NOT FOUND"
    print(f"  [{i+1:2d}/50] {aid}: {target_rule} — failed={len(failed_checks)}, passed={len(passed_checks)} {status}")

# Write enriched manifest
with open(ENRICHED_CSV, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=enriched[0].keys())
    writer.writeheader()
    writer.writerows(enriched)

# Summary
target_found_count = sum(1 for e in enriched if e['baseline_target_found'])
print(f"\n=== SUMMARY ===")
print(f"Total items: {len(enriched)}")
print(f"Target rule found in baseline: {target_found_count}/{len(enriched)}")
print(f"Target rule NOT found: {len(enriched) - target_found_count}")
print(f"Enriched manifest: {ENRICHED_CSV}")
print(f"Baseline JSONs: {BASELINE_DIR}/")

# Flag items where target wasn't found
missing = [e for e in enriched if not e['baseline_target_found']]
if missing:
    print(f"\n⚠️  Items where target rule was NOT found in baseline scan:")
    for m in missing:
        print(f"  {m['artifact_id']}: {m['checkov_rule_id']} — {m['checkov_rule_name'][:60]}")
