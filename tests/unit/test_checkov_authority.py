"""Qualified versions are explicit; property and adapter authority are separate."""
from pathlib import Path
import json

import pytest

import iac_guard_v.checkov_authority as authority
from iac_guard_v.models import DomainError


def test_qualified_line_is_explicit_and_future_does_not_self_promote() -> None:
    assert authority.QUALIFIED_VERSIONS==tuple(f'3.3.{i}' for i in range(31))
    for version in authority.QUALIFIED_VERSIONS:
        authority.require_authority(version,('CKV_AWS_3','CKV2_AWS_6','CKV2_K8S_6'))
    for version in ['3.3.31','3.4.0','latest','3.2.517']:
        with pytest.raises(authority.CheckovAuthorityUnavailable,match='Native|native'):
            authority.require_authority(version)


def test_changed_or_unqualified_properties_do_not_gain_authority() -> None:
    assert authority.property_supported('3.3.0','CKV_K8S_40')
    assert not authority.property_supported('3.3.30','CKV_K8S_40')
    assert not authority.property_supported('3.3.30','CKV_AWS_70')
    assert not authority.property_supported('3.3.31','CKV_AWS_3')
    with pytest.raises(authority.CheckovAuthorityUnavailable,match='CKV_K8S_40'):
        authority.require_authority('3.3.30',('CKV_K8S_40',))
    assert 'CKV_AWS_3' in authority.authority_properties('3.3.30')
    assert authority.authority_properties('3.3.31')==()


def test_metadata_version_is_read_without_scanner_execution(tmp_path: Path) -> None:
    prefix=tmp_path/'runtime';exe=prefix/'bin/checkov';exe.parent.mkdir(parents=True)
    exe.write_text('#!'+str(prefix/'bin/python')+'\n')
    md=prefix/'lib/python3.12/site-packages/checkov-3.3.30.dist-info';md.mkdir(parents=True)
    (md/'METADATA').write_text('Name: checkov\nVersion: 3.3.30\n')
    assert authority.installed_version(exe)=='3.3.30'
    (md/'METADATA').write_text('Name: checkov\n')
    assert authority.installed_version(exe)=='3.3.0'
    assert authority.installed_version(tmp_path/'missing')=='3.3.0'


def test_published_source_must_match_profile(monkeypatch) -> None:
    import hashlib
    files={'checkov/example.py':'0'*64}
    digest=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    monkeypatch.setitem(authority._DATA['versions'],'fixture',{'package_source_digest':digest})
    authority.require_published_package('fixture',files)
    with pytest.raises(DomainError,match='qualified published'):
        authority.require_published_package('fixture',{'checkov/example.py':'1'*64})
    with pytest.raises(authority.CheckovAuthorityUnavailable):
        authority.require_published_package('3.4.0',files)


def test_qualified_properties_are_bound_to_the_reviewed_framework() -> None:
    assert authority.property_supported('3.3.30','CKV_K8S_20','v1/Pod/default/app')
    assert not authority.property_supported('3.3.30','CKV_K8S_20','kubernetes_pod.app')
    assert authority.property_supported('3.3.30','CKV_AWS_3','aws_ebs_volume.app')
    assert not authority.property_supported('3.3.30','CKV_AWS_3','v1/Pod/default/app')
    with pytest.raises(authority.CheckovAuthorityUnavailable,match='CKV_K8S_20'):
        authority.require_authority('3.3.30',('CKV_K8S_20',),resources=('kubernetes_pod.app',))
    with pytest.raises(DomainError,match='correspond'):
        authority.require_authority('3.3.30',('CKV_AWS_3',),resources=('a','b'))
    assert authority.property_supported('3.3.30','CKV_AWS_3','aws_ebs_volume.app["a/b"]')
    assert not authority.property_supported('3.3.30','CKV_AWS_3','unstructured')
    assert not authority.property_supported('3.3.30','CKV_K8S_20','bad version/Pod/default/app')
    # Existing 3.3.0 scope is retained; this is not a retroactive narrowing.
    assert authority.property_supported('3.3.0','CKV_K8S_20','kubernetes_pod.app')


def test_console_body_is_pinned_but_normal_absolute_shebang_may_differ(monkeypatch) -> None:
    import hashlib
    body=b'import sys\nfrom checkov.main import run\nsys.exit(run())\n'
    monkeypatch.setitem(authority._DATA['versions'],'fixture',
        {'launcher_body_sha256':hashlib.sha256(body).hexdigest()})
    authority.require_published_launcher('fixture',b'#!/operator/bin/python\n'+body)
    with pytest.raises(DomainError,match='published launcher'):
        authority.require_published_launcher('fixture',b'#!/operator/bin/python\n'+body+b'print("changed")\n')


def test_every_profile_binds_property_definition_and_framework() -> None:
    import hashlib
    for profile in authority._DATA['versions'].values():
        definitions=profile['property_definitions']
        assert set(definitions)==set(profile['properties'])
        assert profile['policy_qualification_identity']==hashlib.sha256(
            json.dumps(definitions,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        assert all(d['framework'] in {'terraform','kubernetes'} and len(d['definition_digest'])==64
                   for d in definitions.values())
