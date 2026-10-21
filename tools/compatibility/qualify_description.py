"""Supplemental positive/negative policy control for CKV_AWS_23 only."""
from pathlib import Path
import argparse
import json
import subprocess
import tempfile

from iac_guard_v.api import _untrusted_scan_request
from iac_guard_v.adapters.checkov import CheckovAdapter, evaluate_checkov_target
from iac_guard_v.engine import attest_checkov_scan_plan
from iac_guard_v.enums import Status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--controlled', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='iacgv-description-') as temporary:
        root = Path(temporary)
        for name, description in [('positive', ' description="qualification control"\n'), ('negative', '')]:
            (root / (name + '.tf')).write_text('resource "aws_security_group_rule" "' + name + '" {\n'
                + description + ' type="ingress"\n from_port=22\n to_port=22\n protocol="tcp"\n cidr_blocks=["10.0.0.0/8"]\n security_group_id="sg-placeholder"\n}\n')
        config = root / 'safe.yml';config.write_text('quiet: false\n')
        results = []
        for label, exe in [('ordinary', Path('/usr/bin/checkov')), ('controlled', args.controlled)]:
            command = [str(exe), '-d', str(root), '--framework', 'terraform', '--check', 'CKV_AWS_23',
                '--config-file', str(config), '--skip-download', '--download-external-modules', 'false',
                '--skip-results-upload', '--output', 'json', '--compact']
            run = subprocess.run(command, capture_output=True, text=True, timeout=180)
            (args.output / (label + '.stdout')).write_text(run.stdout)
            (args.output / (label + '.stderr')).write_text(run.stderr)
            assert run.returncode == 1
            payload = json.loads(run.stdout)['results']
            rows = sorted((x['check_id'], x['resource'], x['check_result']['result'])
                for category in ('passed_checks', 'failed_checks') for x in payload[category])
            assert rows == [('CKV_AWS_23', 'aws_security_group_rule.negative', 'FAILED'),
                            ('CKV_AWS_23', 'aws_security_group_rule.positive', 'PASSED')]
            results.append(rows)
        assert results[0] == results[1]
        raw = _untrusted_scan_request(root, root, args.controlled, ('terraform',))
        run = CheckovAdapter().scan(attest_checkov_scan_plan(raw).request)
        assert run.status is Status.PASS
        assert evaluate_checkov_target(run, 'CKV_AWS_23', 'aws_security_group_rule.positive').status is Status.PASS
        assert evaluate_checkov_target(run, 'CKV_AWS_23', 'aws_security_group_rule.negative').status is Status.FAIL
        (args.output / 'RESULT.json').write_text(json.dumps({'version': run.scanner_version,
            'result': 'PASS', 'property': 'CKV_AWS_23', 'ordinary_controlled_equal': True,
            'positive': 'PASS', 'negative': 'FAIL', 'adapter': 'PASS'}, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
