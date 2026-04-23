import os
#!/usr/bin/env python3
"""Run Checkov baseline on K8s items and create enriched manifest."""
import subprocess, json, csv, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKOV_BIN = "checkov"
RAW_DIR = f"{BASE}/benchmark/raw"
BASELINE_DIR = f"{BASE}/scanners/outputs/baseline"
K8S_CSV = f"{BASE}/benchmark/k8s_selected_manifest.csv"
ENRICHED_CSV = f"{BASE}/benchmark/k8s_selected_manifest_enriched.csv"

with open(K8S_CSV) as f:
    items = list(csv.DictReader(f))

print(f"Running baseline Checkov on {len(items)} K8s items...")
enriched = []

for i, item in enumerate(items):
    aid = item['artifact_id']
    tf_file = os.path.join(RAW_DIR, item['benchmark_file'])
    target_rule = item['checkov_rule_id']

    try:
        result = subprocess.run(
            [CHECKOV_BIN, '-f', tf_file, '--framework', 'kubernetes', '--output', 'json', '--quiet', '--compact'],
            capture_output=True, text=True, timeout=60
        )
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        if isinstance(data, list):
            data = data[0] if data else {}
    except Exception as e:
        data = {'error': str(e)}

    output_file = os.path.join(BASELINE_DIR, f"{aid}_baseline.json")
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    failed = data.get('results', {}).get('failed_checks', [])
    passed = data.get('results', {}).get('passed_checks', [])
    target_found = any(c.get('check_id') == target_rule for c in failed)
    target_details = next((c for c in failed if c.get('check_id') == target_rule), {})

    enriched_item = dict(item)
    enriched_item['baseline_total_failed'] = len(failed)
    enriched_item['baseline_total_passed'] = len(passed)
    enriched_item['baseline_target_found'] = target_found
    enriched_item['baseline_failed_rules'] = '|'.join(c.get('check_id') for c in failed)
    enriched_item['baseline_target_resource'] = target_details.get('resource', '')
    enriched_item['baseline_target_lines'] = str(target_details.get('file_line_range', []))
    enriched_item['baseline_json_file'] = f"{aid}_baseline.json"
    enriched.append(enriched_item)

    status = "✅" if target_found else "❌"
    print(f"  [{i+1:2d}/20] {aid}: {target_rule} — failed={len(failed)} {status}")

with open(ENRICHED_CSV, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=enriched[0].keys())
    writer.writeheader()
    writer.writerows(enriched)

found = sum(1 for e in enriched if e['baseline_target_found'])
print(f"\nTarget found: {found}/{len(enriched)}")
