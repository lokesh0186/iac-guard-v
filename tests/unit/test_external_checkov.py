"""External source-only contract: bind source and exclude derived cache execution."""
from pathlib import Path
import base64
import hashlib
import json
import os
import py_compile
import subprocess
import sys

import pytest

from iac_guard_v.external_checkov import (
    BOOTSTRAP, _canonical, _regular, _source_records, inventory,
    is_external, launcher_bytes, load_manifest, prepare,
)
from iac_guard_v.models import DomainError


def test_source_loader_uses_source_not_existing_cache(tmp_path: Path) -> None:
    module = tmp_path/'qualification_probe.py'
    module.write_text("VALUE = 'cached'\n")
    timestamp=module.stat().st_mtime_ns
    py_compile.compile(str(module),doraise=True)
    module.write_text("VALUE = 'source'\n")
    os.utime(module,ns=(timestamp,timestamp))
    ordinary=subprocess.run([sys.executable,'-I','-S','-B','-c',
        'import sys;sys.path.insert(0,sys.argv[1]);import qualification_probe;print(qualification_probe.VALUE)',str(tmp_path)],
        capture_output=True,text=True)
    assert ordinary.returncode==0,ordinary.stderr
    assert ordinary.stdout.strip()=='cached'
    launcher = tmp_path/'launcher'
    launcher.write_text("import qualification_probe; print(qualification_probe.VALUE)\n")
    private = tmp_path/'private'
    private.mkdir(mode=0o700)
    # sitecustomize and .pth remain inert under -I -S, even when present.
    (tmp_path/'sitecustomize.py').write_text("raise RuntimeError('unexpected site processing')\n")
    (tmp_path/'injection.pth').write_text("import definitely_missing_qualification_module\n")
    roots = [p for p in sys.path if p and 'site-packages' not in p]
    roots += [str(tmp_path)]
    p=subprocess.run([sys.executable,'-I','-S','-B','-X','pycache_prefix='+str(private),'-c',BOOTSTRAP,
        json.dumps(roots),str(launcher)],capture_output=True,text=True)
    assert p.returncode==0, p.stderr
    assert p.stdout.strip()=='source'
    assert not list(private.iterdir())


def test_source_less_bytecode_is_not_importable(tmp_path: Path) -> None:
    module=tmp_path/'qualification_probe.py'
    module.write_text('VALUE=1\n')
    py_compile.compile(str(module),cfile=str(tmp_path/'qualification_probe.pyc'),doraise=True)
    module.unlink()
    launcher=tmp_path/'launcher'
    launcher.write_text('import qualification_probe\n')
    p=subprocess.run([sys.executable,'-I','-S','-B','-X','pycache_prefix='+str(tmp_path/'private'),'-c',BOOTSTRAP,
        json.dumps([p for p in sys.path if p and 'site-packages' not in p]+[str(tmp_path)]),str(launcher)],capture_output=True,text=True)
    assert p.returncode!=0
    assert 'ModuleNotFoundError' in p.stderr


def test_inventory_accepts_only_derived_regular_cache_files(tmp_path: Path) -> None:
    (tmp_path/'source.py').write_text('VALUE=1\n')
    cache=tmp_path/'__pycache__'
    cache.mkdir()
    (cache/'source.cpython-312.pyc').write_bytes(b'derived cache excluded from execution')
    assert set(inventory(tmp_path))=={'source.py'}
    (cache/'hidden.py').write_text('VALUE=2\n')
    with pytest.raises(DomainError,match='non-cache'):
        inventory(tmp_path)


@pytest.mark.parametrize('kind',['source-symlink','cache-symlink','loose-cache-symlink','cache-directory-symlink','cache-directory-file','empty'])
def test_unsafe_inventory_shape_rejected(tmp_path: Path,kind: str) -> None:
    if kind=='source-symlink':
        (tmp_path/'source.py').symlink_to('absent')
    elif kind=='cache-symlink':
        d=tmp_path/'__pycache__';d.mkdir();(d/'cache.pyc').symlink_to('absent')
    elif kind=='loose-cache-symlink':
        (tmp_path/'cache.pyc').symlink_to('absent')
    elif kind=='cache-directory-symlink':
        derived=tmp_path/'derived';derived.mkdir()
        (derived/'qualification.pyc').write_bytes(b'derived')
        (tmp_path/'__pycache__').symlink_to(derived,target_is_directory=True)
    elif kind=='cache-directory-file':
        (tmp_path/'__pycache__').write_bytes(b'not a directory')
    with pytest.raises(DomainError): inventory(tmp_path)


def test_every_live_importable_source_needs_matching_record(tmp_path: Path) -> None:
    source=tmp_path/'module.py';source.write_text('VALUE=1\n')
    files=inventory(tmp_path)
    with pytest.raises(DomainError,match='RECORD'): _source_records(tmp_path,files)
    md=tmp_path/'example-1.dist-info';md.mkdir()
    h=base64.urlsafe_b64encode(hashlib.sha256(source.read_bytes()).digest()).rstrip(b'=').decode()
    (md/'RECORD').write_text('module.py,sha256='+h+',8\n../../../bin/unused-console,,\n')
    assert _source_records(tmp_path,files)==files
    source.write_text('VALUE=2\n')
    with pytest.raises(DomainError,match='matching RECORD'): _source_records(tmp_path,inventory(tmp_path))


@pytest.mark.parametrize('row',['broken-row\n','module.py,md5=abc,8\n','module.py,,8\n'])
def test_bad_source_records_rejected(tmp_path: Path,row: str) -> None:
    (tmp_path/'module.py').write_text('VALUE=1\n')
    md=tmp_path/'example-1.dist-info';md.mkdir();(md/'RECORD').write_text(row)
    with pytest.raises(DomainError): _source_records(tmp_path,inventory(tmp_path))


def test_manifest_and_launcher_are_bound(tmp_path: Path) -> None:
    std=tmp_path/'stdlib';std.mkdir();(std/'module.py').write_text('VALUE=1\n')
    sites=tmp_path/'site-packages';sites.mkdir();(sites/'package.py').write_text('VALUE=2\n')
    metadata=sites/'example-1.dist-info';metadata.mkdir()
    encoded=base64.urlsafe_b64encode(hashlib.sha256((sites/'package.py').read_bytes()).digest()).rstrip(b'=').decode()
    (metadata/'RECORD').write_text('package.py,sha256='+encoded+',8\n')
    interpreter=tmp_path/'python';interpreter.write_bytes(b'bound interpreter')
    original=tmp_path/'original';original.write_text('#!python\n')
    d={'schema':'iacgv-external-source-v1','version':'0.0.0','interpreter':str(interpreter),
        'interpreter_sha256':hashlib.sha256(interpreter.read_bytes()).hexdigest(),'original_launcher':str(original),
        'launcher_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),'stdlib':str(std),'site_packages':str(sites),
        'stdlib_files':inventory(std),'site_files':inventory(sites),
        'source_records_digest':hashlib.sha256(_canonical(_source_records(sites,inventory(sites)))).hexdigest()}
    raw=_canonical(d)
    launcher=tmp_path/'checkov';launcher.write_bytes(launcher_bytes(d,raw))
    (tmp_path/'checkov.json').write_bytes(raw)
    assert is_external(launcher)
    assert load_manifest(launcher)==d
    (sites/'package.py').write_text('VALUE=3\n')
    with pytest.raises(DomainError,match='source changed'):load_manifest(launcher)
    assert load_manifest(launcher,verify=False)==d
    (tmp_path/'checkov.json').write_bytes(raw+b' ')
    with pytest.raises(DomainError,match='launcher'):load_manifest(launcher)


def test_legacy_launcher_does_not_opt_into_external_contract(tmp_path: Path) -> None:
    p=tmp_path/'checkov';p.write_text('#!/bin/sh\nexit 0\n')
    assert load_manifest(p) is None
    assert not is_external(p)
    with pytest.raises(DomainError):_regular(tmp_path)


def _prefix(tmp_path: Path):
    prefix=tmp_path/'runtime'
    interpreter=prefix/'bin/python3.12';interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b'operator controlled interpreter');interpreter.chmod(0o755)
    launcher=prefix/'bin/checkov';launcher.write_text('#!'+str(interpreter)+'\nprint("qualification")\n')
    std=prefix/'lib/python3.12';std.mkdir(parents=True);(std/'stdlib.py').write_text('VALUE=1\n')
    sites=std/'site-packages'
    policy=sites/'checkov/checks/rule.py';policy.parent.mkdir(parents=True);policy.write_text('RULE=1\n')
    md=sites/'checkov-0.0.0.dist-info';md.mkdir()
    (md/'METADATA').write_text('Name: checkov\nVersion: 0.0.0\n')
    digest=base64.urlsafe_b64encode(hashlib.sha256(policy.read_bytes()).digest()).rstrip(b'=').decode()
    (md/'RECORD').write_text('checkov/checks/rule.py,sha256='+digest+',7\n')
    return launcher,interpreter,std,sites,md


def test_prepare_attests_live_sources_without_editing_global_files(tmp_path: Path) -> None:
    original,interpreter,std,sites,md=_prefix(tmp_path)
    before={str(p):p.read_bytes() for p in original.parent.parent.rglob('*') if p.is_file()}
    launcher=prepare(original,tmp_path/'protected')
    d=load_manifest(launcher)
    assert d['original_launcher']==str(original)
    assert d['interpreter']==str(interpreter)
    assert d['site_packages']==str(sites)
    assert before=={str(p):p.read_bytes() for p in original.parent.parent.rglob('*') if p.is_file()}
    # Reusing an existing destination is refused, never overwritten.
    with pytest.raises(FileExistsError): prepare(original,tmp_path/'protected')


@pytest.mark.parametrize('mutation',['shebang','metadata-missing','metadata-ambiguous','metadata-version','source-record','source-link'])
def test_prepare_fails_closed_on_invalid_source_provenance(tmp_path: Path,mutation: str) -> None:
    original,interpreter,std,sites,md=_prefix(tmp_path)
    if mutation=='shebang':original.write_text('#!/usr/bin/env python\n')
    elif mutation=='metadata-missing':(md/'METADATA').unlink()
    elif mutation=='metadata-ambiguous':
        other=sites/'checkov-other.dist-info';other.mkdir();(other/'METADATA').write_text('Version: other\n')
    elif mutation=='metadata-version':(md/'METADATA').write_text('Name: checkov\n')
    elif mutation=='source-record':(sites/'checkov/checks/rule.py').write_text('RULE=2\n')
    else:(sites/'link.py').symlink_to('absent')
    with pytest.raises(DomainError): prepare(original,tmp_path/'protected')


@pytest.mark.parametrize('mutation',['schema','json','path','interpreter','original','stdlib','launcher'])
def test_manifest_drift_is_rejected(tmp_path: Path,mutation: str) -> None:
    original,interpreter,std,sites,md=_prefix(tmp_path)
    launcher=prepare(original,tmp_path/'protected')
    manifest=launcher.with_name('checkov.json')
    if mutation in ['schema','path']:
        d=json.loads(manifest.read_text())
        if mutation=='schema':d['extra']='unreviewed'
        else:d['interpreter']='relative/python'
        raw=_canonical(d);manifest.write_bytes(raw);launcher.write_bytes(launcher_bytes(d,raw))
    elif mutation=='json':manifest.write_text('not json')
    elif mutation=='interpreter':interpreter.write_bytes(b'changed runtime')
    elif mutation=='original':original.write_text('#!changed\n')
    elif mutation=='stdlib':(std/'stdlib.py').write_text('VALUE=2\n')
    else:launcher.write_bytes(launcher.read_bytes()+b'# changed\n')
    with pytest.raises(DomainError):load_manifest(launcher)


def test_bootstrap_refuses_missing_isolation_controls(tmp_path: Path) -> None:
    p=subprocess.run([sys.executable,'-c',BOOTSTRAP],capture_output=True,text=True)
    assert p.returncode==3


def test_cli_prepare_success_and_failure(monkeypatch,tmp_path: Path,capsys) -> None:
    from iac_guard_v.external_checkov import main
    original,*_=_prefix(tmp_path)
    monkeypatch.setattr(sys,'argv',['prepare','--checkov',str(original),'--destination',str(tmp_path/'protected')])
    assert main()==0
    assert 'checkov' in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:main()
    assert exc.value.code==3


def test_real_wrapper_isolates_runtime_state_and_cleans_only_its_private_directory(tmp_path: Path) -> None:
    import sysconfig
    sites=tmp_path/'sites';sites.mkdir()
    (sites/'qualification_probe.py').write_text('VALUE="source"\n')
    original=tmp_path/'ordinary-checkov'
    original.write_text('import json,os,sys,qualification_probe\n'
        'print(json.dumps({"home":os.environ["HOME"],"tmp":os.environ["TMPDIR"],'
        '"cache":sys.pycache_prefix,"value":qualification_probe.VALUE,"path":sys.path}))\n')
    manifest={'interpreter':str(Path(sys.executable).resolve()),
        'stdlib':sysconfig.get_path('stdlib'),'site_packages':str(sites),'original_launcher':str(original)}
    launcher=tmp_path/'controlled';launcher.write_bytes(launcher_bytes(manifest,_canonical(manifest)));launcher.chmod(0o755)
    scratch=tmp_path/'scratch';scratch.mkdir()
    sentinel=scratch/'existing-operator-data';sentinel.write_text('preserved')
    p=subprocess.run([str(launcher)],env=dict(os.environ,TMPDIR=str(scratch)),capture_output=True,text=True)
    assert p.returncode==0,p.stderr
    observed=json.loads(p.stdout)
    assert observed['value']=='source'
    assert observed['home']==observed['tmp']==observed['cache']
    assert Path(observed['cache']).parent==scratch
    assert not Path(observed['cache']).exists()
    assert list(scratch.iterdir())==[sentinel]
    assert sentinel.read_text()=='preserved'
    assert observed['path']==[sysconfig.get_path('stdlib'),str(Path(sysconfig.get_path('stdlib'))/'lib-dynload'),str(sites)]
