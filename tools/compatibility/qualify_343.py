"""Offline public-interface controls for the exact 3.4.3/AWS EBS profile.

This is deliberately separate from the broader 3.3.x qualification corpus:
passing it grants no other property or version authority. Run using an installed
non-editable product and an already prepared source-only scanner launcher.
"""
from pathlib import Path
import argparse
import json
import subprocess
import sys
import tempfile

from iac_guard_v.external_checkov import BOOTSTRAP, load_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ordinary', type=Path, required=True)
    parser.add_argument('--controlled', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = load_manifest(args.controlled)
    assert manifest['version'] == '3.4.3', 'This corpus qualifies exactly 3.4.3'
    commands = []

    def run(name, argv, expected):
        result = subprocess.run([str(x) for x in argv], capture_output=True,
                                text=True, timeout=600)
        (args.output / (name + '.stdout')).write_text(result.stdout)
        (args.output / (name + '.stderr')).write_text(result.stderr)
        commands.append({'name': name, 'argv': [str(x) for x in argv],
                         'exit_code': result.returncode, 'expected': expected})
        (args.output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        assert result.returncode in expected, (name, result.returncode, result.stderr[-2000:])
        return result

    guard = [sys.executable, '-I', '-B', '-m', 'iac_guard_v.cli']
    doctor = run('doctor', [*guard, 'doctor', '--mode', 'local-trusted',
                 '--checkov-executable', args.controlled, '--format', 'json'], [0])
    readiness = json.loads(doctor.stdout)
    assert readiness['checkov']['status'] == 'PASS'
    assert readiness['checkov']['qualified_properties'] == ['CKV_AWS_3']
    assert readiness['validator_registry']['status'] == 'PASS'
    probe = Path(__file__).with_name('import_inventory.py')
    ordinary_imports = run('ordinary-imports', [manifest['interpreter'], '-B', probe], [0])
    with tempfile.TemporaryDirectory(prefix='iacgv-343-import-cache-') as cache:
        roots = [manifest['stdlib'], str(Path(manifest['stdlib']) / 'lib-dynload'),
                 manifest['site_packages']]
        controlled_imports = run('controlled-imports', [manifest['interpreter'],
            '-I', '-S', '-B', '-X', 'pycache_prefix=' + cache, '-c', BOOTSTRAP,
            json.dumps(roots), probe], [0])
    assert json.loads(ordinary_imports.stdout) == json.loads(controlled_imports.stdout), (
        'Source-only imports, dependencies or policy registrations changed')
    source = ('resource "aws_ebs_volume" "target" {\n'
              ' availability_zone="us-east-1a"\n size=1\n encrypted=false\n}\n')
    outcomes = {}
    with tempfile.TemporaryDirectory(prefix='iacgv-343-qualification-') as temporary:
        root = Path(temporary)
        before = root / 'before'; before.mkdir()
        (before / 'main.tf').write_text(source)
        cases = [
            ('repaired', source.replace('false', 'true'), 0, 'VERIFIED'),
            ('unchanged', source + '# still defective\n', 1, 'FAILED'),
            # Adding another resource also introduces unqualified incidental
            # findings: the public policy preserves uncertainty (not success).
            ('wrong-resource', source + source.replace('target', 'other').replace('false', 'true'), 3, 'INCONCLUSIVE'),
            ('deleted', '# deleted\n', 3, 'INCONCLUSIVE'),
            ('missing', source.replace('target', 'other').replace('false', 'true'), 3, 'INCONCLUSIVE'),
            ('duplicate', source.replace('false', 'true') * 2, 1, 'FAILED'),
            ('suppressed', source.replace('encrypted=false', '#checkov:skip=CKV_AWS_3:control\n encrypted=true'), 3, 'INCONCLUSIVE'),
            ('malformed-input', 'resource "aws_ebs_volume" "target" { encrypted = [\n', 1, 'FAILED'),
            ('unresolved', source.replace('false', 'var.encrypted') + 'variable "encrypted" { type=bool }\n', 3, 'INCONCLUSIVE'),
            ('disabled-resource', source.replace('false', 'true').replace(' size=1', ' count=0\n size=1'), 3, 'INCONCLUSIVE'),
            ('remote-module', 'module "target" { source="git::https://example.invalid/unavailable.git" }\n', 3, 'INCONCLUSIVE'),
        ]
        for name, content, exit_code, verdict in cases:
            after = root / name; after.mkdir(); (after / 'main.tf').write_text(content)
            report = args.output / (name + '.json')
            run(name, [*guard, 'verify', '--before', before, '--after', after,
                '--target', 'CKV_AWS_3=aws_ebs_volume.target', '--framework', 'terraform',
                '--local-trusted', '--checkov-executable', args.controlled,
                '--format', 'json', '--output', report, '--quiet'], [exit_code])
            payload = json.loads(report.read_text())
            assert payload['verdict'] == verdict, (name, payload)
            outcomes[name] = {'exit_code': exit_code, 'verdict': verdict}

        # The same version is intentionally unqualified for other properties.
        after = root / 'repaired'
        for name, target in [('unqualified-terraform', 'CKV_AWS_23=aws_ebs_volume.target'),
                             ('unknown-property', 'CKV_AWS_999999=aws_ebs_volume.target')]:
            report = args.output / (name + '.json')
            run(name, [*guard, 'verify', '--before', before, '--after', after,
                '--target', target, '--framework', 'terraform', '--local-trusted',
                '--checkov-executable', args.controlled, '--format', 'json',
                '--output', report, '--quiet'], [3])
            payload = json.loads(report.read_text())
            assert payload['verdict'] == 'INCONCLUSIVE', (name, payload)
            outcomes[name] = {'exit_code': 3, 'verdict': 'INCONCLUSIVE'}

        # Compare actual normal/source-only PASSED, FAILED and SKIPPED records.
        corpus = root / 'scanner-corpus'; corpus.mkdir()
        (corpus / 'bad.tf').write_text(source)
        (corpus / 'good.tf').write_text(source.replace('target', 'good').replace('false', 'true'))
        (corpus / 'skip.tf').write_text(source.replace('target', 'skipped').replace(
            'encrypted=false', '#checkov:skip=CKV_AWS_3:control\n encrypted=false'))
        config = root / 'safe.yml'; config.write_text('quiet: false\n')
        observations = []
        for name, executable in [('ordinary', args.ordinary), ('controlled', args.controlled)]:
            result = run(name, [executable, '-d', corpus, '--framework', 'terraform',
                '--check', 'CKV_AWS_3', '--config-file', config, '--skip-download',
                '--download-external-modules', 'false', '--skip-results-upload',
                '--output', 'json', '--compact'], [1])
            payload = json.loads(result.stdout)
            rows = sorted((category, row['check_id'], row['resource'], row['file_path'])
                for category in ('passed_checks', 'failed_checks', 'skipped_checks')
                for row in payload['results'][category])
            assert {row[0] for row in rows} == {'passed_checks', 'failed_checks', 'skipped_checks'}
            observations.append({'rows': rows, 'summary': payload['summary'],
                                 'parsing_errors': payload['results'].get('parsing_errors')})
        assert observations[0] == observations[1], 'Source-only execution changed semantics'
    (args.output / 'RESULT.json').write_text(json.dumps({
        'version': '3.4.3', 'properties': ['CKV_AWS_3'], 'result': 'PASS',
        'qualification': 'EBS_ENCRYPTION_ONLY', 'outcomes': outcomes,
        'ordinary_source_only_equal': True, 'commands': commands}, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
