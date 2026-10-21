"""Compare relevant upstream policy definitions in already verified Checkov wheels.

This is an evidence generator, never a support-set updater. Runtime qualification
and review are required independently of matching implementation bytes.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import zipfile


def inventory(wheel: Path, properties: set[str]) -> dict:
    with zipfile.ZipFile(wheel) as archive:
        result = {rule: {} for rule in properties}
        for name in archive.namelist():
            if not name.startswith(('checkov/terraform/checks/', 'checkov/kubernetes/checks/')):
                continue
            if not name.endswith(('.py', '.json', '.yaml', '.yml')):
                continue
            data = archive.read(name)
            text = data.decode('utf-8')
            for rule in properties:
                if re.search(r'(?<![A-Z0-9_])' + re.escape(rule) + r'(?![A-Z0-9_])', text):
                    expected = 'checkov/kubernetes/' if '_K8S_' in rule else 'checkov/terraform/'
                    if name.startswith(expected):
                        result[rule][name] = hashlib.sha256(data).hexdigest()
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheels', type=Path, required=True)
    parser.add_argument('--profiles', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.profiles.read_text())
    properties = set().union(*(p['properties'] for p in data['versions'].values()))
    # Changed policies remain visible even when excluded from authority.
    properties |= {'CKV_AWS_70', 'CKV_AZURE_53', 'CKV_AZURE_190', 'CKV_GCP_62',
                   'CKV_GCP_63', 'CKV_GCP_123', 'CKV_AWS_394'}
    rows = []
    baseline = None
    for version, profile in data['versions'].items():
        wheel, = args.wheels.glob(f'checkov-{version}-*.whl')
        definitions = inventory(wheel, properties)
        if baseline is None:
            baseline = definitions
        for rule in sorted(properties):
            current = definitions[rule]
            original = baseline[rule]
            digest = lambda files: hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            rows.append({'check_id': rule, 'version': version,
                         'framework': 'kubernetes' if '_K8S_' in rule else 'terraform',
                         'baseline_definition_digest': digest(original),
                         'version_definition_digest': digest(current),
                         'implementation_files': current,
                         'definition_unchanged': bool(current) and current == original,
                         'candidate_authority_allowed': rule in profile['properties'],
                         'runtime_qualification_required': True})
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'policy-definitions.json').write_text(json.dumps(rows, indent=2) + '\n')
    fields = ['check_id', 'version', 'framework', 'baseline_definition_digest',
              'version_definition_digest', 'definition_unchanged', 'candidate_authority_allowed']
    with (args.output / 'policy-definitions.csv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader(); writer.writerows(rows)
    missing = [r for r in rows if r['candidate_authority_allowed'] and not r['implementation_files']]
    if missing:
        raise RuntimeError('Candidate authority has no located policy definition: ' + repr(missing))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
