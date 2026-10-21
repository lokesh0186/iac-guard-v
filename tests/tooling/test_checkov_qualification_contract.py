"""Compatibility CI is explicit and cannot promote a floating scanner version."""
from pathlib import Path
import json

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_release_matrix_matches_the_closed_candidate_profile() -> None:
    workflow = yaml.safe_load((ROOT / '.github/workflows/checkov-compatibility.yml').read_text())
    profiles = json.loads((ROOT / 'src/iac_guard_v/adapters/checkov_profiles.json').read_text())
    matrix = workflow['jobs']['release-required-matrix']['strategy']['matrix']['checkov']
    assert matrix == list(profiles['versions'])
    assert len(matrix) == len(set(matrix)) == 31
    for job in workflow['jobs'].values():
        assert all('write' not in permission for permission in workflow['permissions'].values())
        commands = '\n'.join(step.get('run', '') for step in job['steps'])
        assert '--system-site-packages' not in commands  # delegated to reviewed helper
        assert 'prepare_shared.py' in commands
        assert 'qualify.py' in commands
        assert '--adapter-only' not in commands
        assert not any(token in commands for token in ('git push', 'gh release', 'twine upload'))
    canary = workflow['jobs']['latest-canary']
    assert 'schedule' in canary['if']
    assert not canary.get('continue-on-error', False)


def test_profile_does_not_grant_changed_policy_authority_on_newer_versions() -> None:
    profiles = json.loads((ROOT / 'src/iac_guard_v/adapters/checkov_profiles.json').read_text())
    for patch in range(1, 31):
        properties = profiles['versions'][f'3.3.{patch}']['properties']
        assert ('CKV_K8S_40' in properties) is (patch < 8)
        assert not set(properties) & {'CKV_AWS_70', 'CKV_AZURE_53', 'CKV_AZURE_190',
                                      'CKV_GCP_62', 'CKV_GCP_63', 'CKV_GCP_123', 'CKV_AWS_394'}
