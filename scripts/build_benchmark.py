#!/usr/bin/env python3
"""
Scan Checkov test cases to build benchmark manifest.
Identifies misconfigured Terraform files with specific Checkov rule violations.
"""
import subprocess
import json
import csv
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKOV_TESTS = f"{BASE}/benchmark/checkov_repo/tests/terraform/checks/resource/aws"
CHECKOV_BIN = "checkov"
OUTPUT_CSV = f"{BASE}/benchmark/manifest.csv"
RAW_DIR = f"{BASE}/benchmark/raw"

os.makedirs(RAW_DIR, exist_ok=True)

# Violation class mapping based on Checkov rule prefixes/patterns
VIOLATION_CLASS_MAP = {
    'encrypt': 'missing_encryption',
    'Encrypt': 'missing_encryption',
    'CMK': 'missing_encryption',
    'KMS': 'missing_encryption',
    'SSE': 'missing_encryption',
    'TLS': 'missing_encryption',
    'HTTPS': 'missing_encryption',
    'IAM': 'over_permissive_access',
    'Admin': 'over_permissive_access',
    'Policy': 'over_permissive_access',
    'Privilege': 'over_permissive_access',
    'Public': 'public_exposure',
    'Ingress': 'network_hardening',
    'SecurityGroup': 'network_hardening',
    'VPC': 'network_hardening',
    'Network': 'network_hardening',
    'Logging': 'weak_observability',
    'Log': 'weak_observability',
    'CloudTrail': 'weak_observability',
    'Monitor': 'weak_observability',
    'Backup': 'insecure_defaults',
    'Versioning': 'insecure_defaults',
    'Default': 'insecure_defaults',
    'Tag': 'insecure_defaults',
}

def classify_violation(dir_name):
    """Map directory name to violation class."""
    for key, cls in VIOLATION_CLASS_MAP.items():
        if key.lower() in dir_name.lower():
            return cls
    return 'other'

def run_checkov(tf_dir):
    """Run Checkov on a directory and return findings."""
    try:
        result = subprocess.run(
            [CHECKOV_BIN, '-d', tf_dir, '--framework', 'terraform', '--output', 'json', '--quiet', '--compact'],
            capture_output=True, text=True, timeout=60
        )
        if result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, list):
                data = data[0] if data else {}
            return data
        return {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        return {'error': str(e)}

def extract_failed_checks(checkov_output):
    """Extract failed checks from Checkov JSON output."""
    results = checkov_output.get('results', {})
    failed = results.get('failed_checks', [])
    return failed

# Scan all test directories
print("Scanning Checkov test directories...")
manifest = []
artifact_id = 0
scanned = 0
errors = 0

dirs = sorted([d for d in os.listdir(CHECKOV_TESTS) if d.startswith('example_') and os.path.isdir(os.path.join(CHECKOV_TESTS, d))])

for dir_name in dirs:
    dir_path = os.path.join(CHECKOV_TESTS, dir_name)
    
    # Find .tf files
    tf_files = [f for f in os.listdir(dir_path) if f.endswith('.tf')]
    if not tf_files:
        continue
    
    scanned += 1
    if scanned % 50 == 0:
        print(f"  Scanned {scanned} directories...")
    
    # Run Checkov
    checkov_out = run_checkov(dir_path)
    if 'error' in checkov_out:
        errors += 1
        continue
    
    failed_checks = extract_failed_checks(checkov_out)
    if not failed_checks:
        continue  # No failures = not useful as a misconfigured benchmark item
    
    # For each failed check, create a benchmark item
    seen_rules = set()
    for check in failed_checks:
        rule_id = check.get('check_id', '')
        if rule_id in seen_rules:
            continue  # One item per unique rule per directory
        seen_rules.add(rule_id)
        
        artifact_id += 1
        
        # Read the source file
        source_file = check.get('file_path', '').lstrip('/')
        if not source_file:
            source_file = tf_files[0]
        
        full_source_path = os.path.join(dir_path, source_file) if not os.path.isabs(os.path.join(dir_path, source_file)) else os.path.join(dir_path, source_file)
        # Checkov returns paths relative to scanned dir
        actual_path = os.path.join(dir_path, source_file.lstrip('/'))
        if not os.path.exists(actual_path):
            actual_path = os.path.join(dir_path, tf_files[0])
        
        violation_class = classify_violation(dir_name)
        
        # Copy to raw benchmark dir
        dest_name = f"BM-{artifact_id:04d}.tf"
        try:
            with open(actual_path, 'r') as f:
                content = f.read()
            dest_path = os.path.join(RAW_DIR, dest_name)
            with open(dest_path, 'w') as f:
                f.write(content)
        except Exception:
            continue
        
        manifest.append({
            'artifact_id': f'BM-{artifact_id:04d}',
            'source_dir': dir_name,
            'source_file': source_file,
            'technology': 'terraform',
            'checkov_rule_id': rule_id,
            'checkov_rule_name': check.get('check_name', ''),
            'violation_class': violation_class,
            'severity': check.get('severity', 'UNKNOWN'),
            'resource': check.get('resource', ''),
            'guideline': check.get('guideline', ''),
            'file_line_range': str(check.get('file_line_range', [])),
            'benchmark_file': dest_name,
        })

# Write manifest
with open(OUTPUT_CSV, 'w', newline='') as f:
    if manifest:
        writer = csv.DictWriter(f, fieldnames=manifest[0].keys())
        writer.writeheader()
        writer.writerows(manifest)

print(f"\nDone!")
print(f"Scanned: {scanned} directories")
print(f"Errors: {errors}")
print(f"Benchmark items: {len(manifest)}")
print(f"Manifest: {OUTPUT_CSV}")

# Summary by violation class
from collections import Counter
class_counts = Counter(item['violation_class'] for item in manifest)
print(f"\nBy violation class:")
for cls, count in class_counts.most_common():
    print(f"  {cls}: {count}")

# Summary by severity
sev_counts = Counter(item['severity'] for item in manifest)
print(f"\nBy severity:")
for sev, count in sev_counts.most_common():
    print(f"  {sev}: {count}")
