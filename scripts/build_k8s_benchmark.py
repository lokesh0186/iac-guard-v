import os
#!/usr/bin/env python3
"""Build K8s benchmark from Checkov's Kubernetes test cases."""
import subprocess, json, csv, os
from collections import Counter, defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
K8S_TESTS = f"{BASE}/benchmark/checkov_repo/tests/kubernetes/checks"
CHECKOV_BIN = "checkov"
RAW_DIR = f"{BASE}/benchmark/raw"
os.makedirs(RAW_DIR, exist_ok=True)

K8S_CLASS_MAP = {
    'Privilege': 'over_permissive_access', 'AllowPrivilege': 'over_permissive_access',
    'Capabilities': 'over_permissive_access', 'ReadOnly': 'over_permissive_access',
    'Root': 'over_permissive_access', 'HostPID': 'over_permissive_access',
    'HostIPC': 'over_permissive_access', 'HostNetwork': 'network_hardening',
    'Tiller': 'over_permissive_access', 'ServiceAccount': 'over_permissive_access',
    'Limit': 'missing_runtime_safety', 'Resource': 'missing_runtime_safety',
    'Memory': 'missing_runtime_safety', 'Cpu': 'missing_runtime_safety',
    'Liveness': 'missing_runtime_safety', 'Readiness': 'missing_runtime_safety',
    'Image': 'insecure_defaults', 'Tag': 'insecure_defaults',
    'Secret': 'missing_encryption', 'Encrypt': 'missing_encryption',
    'Tls': 'missing_encryption', 'Https': 'missing_encryption',
    'Audit': 'weak_observability', 'Log': 'weak_observability',
    'Profiling': 'weak_observability',
    'Namespace': 'insecure_defaults', 'Default': 'insecure_defaults',
    'ApiServer': 'network_hardening', 'Etcd': 'network_hardening',
    'Kubelet': 'network_hardening',
}

def classify(name):
    for key, cls in K8S_CLASS_MAP.items():
        if key.lower() in name.lower():
            return cls
    return 'other'

print("Scanning K8s test directories...")
manifest = []
artifact_id = 2000  # Start at 2000 to avoid collision with Terraform IDs
scanned = 0

dirs = sorted([d for d in os.listdir(K8S_TESTS) if d.startswith('example_') and os.path.isdir(os.path.join(K8S_TESTS, d))])

for dir_name in dirs:
    dir_path = os.path.join(K8S_TESTS, dir_name)
    yaml_files = [f for f in os.listdir(dir_path) if f.endswith(('.yaml', '.yml'))]
    if not yaml_files:
        continue
    scanned += 1

    try:
        result = subprocess.run(
            [CHECKOV_BIN, '-d', dir_path, '--framework', 'kubernetes', '--output', 'json', '--quiet', '--compact'],
            capture_output=True, text=True, timeout=60
        )
        if not result.stdout.strip():
            continue
        data = json.loads(result.stdout)
        if isinstance(data, list):
            data = data[0] if data else {}
    except:
        continue

    failed = data.get('results', {}).get('failed_checks', [])
    if not failed:
        continue

    seen_rules = set()
    for check in failed:
        rule_id = check.get('check_id', '')
        if rule_id in seen_rules:
            continue
        seen_rules.add(rule_id)
        artifact_id += 1

        source_file = check.get('file_path', '').lstrip('/')
        if not source_file:
            source_file = yaml_files[0]
        actual_path = os.path.join(dir_path, source_file.lstrip('/'))
        if not os.path.exists(actual_path):
            actual_path = os.path.join(dir_path, yaml_files[0])

        dest_name = f"BM-{artifact_id:04d}.yaml"
        try:
            with open(actual_path, 'r') as f:
                content = f.read()
            with open(os.path.join(RAW_DIR, dest_name), 'w') as f:
                f.write(content)
        except:
            continue

        manifest.append({
            'artifact_id': f'BM-{artifact_id:04d}',
            'source_dir': dir_name, 'source_file': source_file,
            'technology': 'kubernetes',
            'checkov_rule_id': rule_id,
            'checkov_rule_name': check.get('check_name', ''),
            'violation_class': classify(dir_name),
            'severity': check.get('severity', 'UNKNOWN'),
            'resource': check.get('resource', ''),
            'guideline': check.get('guideline', ''),
            'file_line_range': str(check.get('file_line_range', [])),
            'benchmark_file': dest_name,
        })

# Select diverse subset of 20
selected = []
seen_rules = set()
targets = {'over_permissive_access': 6, 'missing_runtime_safety': 4, 'network_hardening': 3,
           'insecure_defaults': 3, 'missing_encryption': 2, 'weak_observability': 1, 'other': 1}

by_class = defaultdict(list)
for item in manifest:
    by_class[item['violation_class']].append(item)

for cls, target in targets.items():
    count = 0
    for item in by_class.get(cls, []):
        if count >= target:
            break
        if item['checkov_rule_id'] not in seen_rules:
            selected.append(item)
            seen_rules.add(item['checkov_rule_id'])
            count += 1

# Save
K8S_CSV = f"{BASE}/benchmark/k8s_selected_manifest.csv"
with open(K8S_CSV, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=selected[0].keys())
    writer.writeheader()
    writer.writerows(selected)

print(f"\nScanned: {scanned} | Total items: {len(manifest)} | Selected: {len(selected)}")
class_counts = Counter(i['violation_class'] for i in selected)
print(f"By class: {dict(class_counts.most_common())}")
print(f"Manifest: {K8S_CSV}")
