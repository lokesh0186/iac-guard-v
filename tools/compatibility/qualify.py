"""Reproducible per-version qualification; no compatibility is auto-promoted.

Run with the separately installed product Python and an already prepared external
scanner launcher. Public repair controls are required unless --adapter-only is
explicitly selected for development; such output is not a full qualification.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

from corpus import create
from iac_guard_v.api import _untrusted_scan_request
from iac_guard_v.adapters.checkov import CheckovAdapter, evaluate_checkov_target
from iac_guard_v.engine import attest_checkov_scan_plan
from iac_guard_v.enums import CheckEvaluationResult, Status
from iac_guard_v.external_checkov import BOOTSTRAP, load_manifest


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--ordinary',type=Path,required=True)
    p.add_argument('--controlled',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--adapter-only',action='store_true')
    p.add_argument('--synthetic-fixture',type=Path)
    args=p.parse_args()
    out=args.output;out.mkdir(parents=True,exist_ok=False)
    commands=[]
    def run(name,argv,expected=(0,),env=None,timeout=600):
        result=subprocess.run([str(x) for x in argv],capture_output=True,text=True,env=env,timeout=timeout)
        (out/(name+'.stdout')).write_text(result.stdout)
        (out/(name+'.stderr')).write_text(result.stderr)
        commands.append({'name':name,'argv':[str(x) for x in argv],'exit_code':result.returncode})
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        assert result.returncode in expected,(name,result.returncode,result.stderr[-1000:])
        return result
    manifest=load_manifest(args.controlled)
    version=manifest['version']
    result={'version':version,'qualification':'ADAPTER_ONLY' if args.adapter_only else 'FULL',
        'product_python':sys.executable,'schema_version':'checkov-compatibility-qualification-v1'}
    with tempfile.TemporaryDirectory(prefix='iacgv-qualification-') as tmp:
        tmp=Path(tmp);root=tmp/'corpus';create(root)
        synthetic=args.synthetic_fixture or (Path(__file__).parents[2]/'tests/fixtures/kubernetes/synthetic-pod-controllers.yaml')
        shutil.copy2(synthetic,root/'kubernetes/synthetic-pod-controllers.yaml')
        ordinary={};controlled={}
        for label,exe,collection in [('ordinary',args.ordinary,ordinary),('source-only',args.controlled,controlled)]:
            for framework,folder in [('terraform','terraform'),('kubernetes','kubernetes'),('terraform','parser_failure')]:
                command=[exe,'-d',root/folder,'--framework',framework,'--output','json','--compact','--config-file',root/'safe-config.yml',
                    '--skip-download','--download-external-modules','false','--skip-results-upload']
                run_result=run(label+'-'+folder,command,expected=(0,1))
                payload=json.loads(run_result.stdout)
                docs=payload if isinstance(payload,list) else [payload]
                rows=[]
                for doc in docs:
                    for kind in ['passed_checks','failed_checks','skipped_checks']:
                        for x in doc.get('results',{}).get(kind,[]):
                            rows.append((x['check_id'],x.get('check_class'),x.get('resource'),x.get('file_path'),
                                x.get('check_result',{}).get('result','SKIPPED' if kind=='skipped_checks' else None)))
                collection[folder]={'evaluations':sorted(rows,key=repr),'summary':[d['summary'] for d in docs],
                    'parsing_errors':[d['results'].get('parsing_errors') for d in docs]}
        assert ordinary==controlled,'Source-only execution changed scanner semantics'
        result['ordinary_source_only_semantics']='PASS'
        result['property_observations']={framework:{rule:sorted({row[4] for row in payload['evaluations'] if row[0]==rule})
            for rule in sorted({row[0] for row in payload['evaluations']})} for framework,payload in ordinary.items()}
        (out/'SEMANTIC.json').write_text(json.dumps(ordinary,indent=2)+'\n')
        probe=Path(__file__).with_name('import_inventory.py')
        ordinary_import=run('ordinary-imports',[manifest['interpreter'],probe])
        with tempfile.TemporaryDirectory(prefix='iacgv-qualification-cache-') as cache:
            roots=[manifest['stdlib'],str(Path(manifest['stdlib'])/'lib-dynload'),manifest['site_packages']]
            isolated_import=run('source-only-imports',[manifest['interpreter'],'-I','-S','-B','-X','pycache_prefix='+cache,
                '-c',BOOTSTRAP,json.dumps(roots),probe])
        assert json.loads(ordinary_import.stdout)==json.loads(isolated_import.stdout),'Imports, dependencies or policy registration changed'
        result['imports_dependencies_policies']='PASS'
        adapter_results={}
        # Synthetic workload identity is compared above against normal Checkov.
        # Use the bounded manifest subset for direct/graph adapter conformance.
        (root/'kubernetes/synthetic-pod-controllers.yaml').unlink()
        for framework in ['terraform','kubernetes']:
            request=_untrusted_scan_request(root/framework,root/framework,args.controlled,(framework,))
            plan=attest_checkov_scan_plan(request)
            scan=CheckovAdapter().scan(plan.request)
            assert scan.status is Status.PASS,(framework,scan.diagnostics)
            graph_rule='CKV2_AWS_6' if framework=='terraform' else 'CKV2_K8S_6'
            graph=[e for e in scan.evaluations if e.rule_id==graph_rule]
            (out/('adapter-'+framework+'.json')).write_text(json.dumps({'status':scan.status.value,'diagnostics':scan.diagnostics,
                'evaluations':[e.canonical_dict() for e in graph]},indent=2)+'\n')
            assert graph and {CheckEvaluationResult.PASSED,CheckEvaluationResult.FAILED}<={e.native_result for e in graph}
            decisive = graph if framework=='terraform' else [e for e in graph if e.file_path in {'graph_good.json','graph_bad.json'}]
            assert decisive and all(e.graph_evidence is not None and e.graph_evidence.status is Status.PASS for e in decisive)
            if framework=='kubernetes':
                # Checkov's existing unlabeled-Pod behavior disagrees with the
                # independent selector proof. Preserve that fail-closed result;
                # do not mistake raw scanner PASS for graph authority.
                ambiguous=[e for e in graph if e not in decisive]
                assert ambiguous and all(e.graph_evidence is not None
                    and e.graph_evidence.reason_code=='GRAPH_RESULT_MISMATCH'
                    and e.graph_evidence.status is Status.INCONCLUSIVE for e in ambiguous)
                assert all(evaluate_checkov_target(scan,e.rule_id,e.resource_address,e.file_path).status is Status.INCONCLUSIVE for e in ambiguous)
            adapter_results[framework]={'status':scan.status.value,'evaluations':len(scan.evaluations),
                'graph_participants':[e.graph_evidence.canonical_dict() for e in graph]}
        result['adapter_resource_graph_conformance']=adapter_results
        guard=Path(sys.executable).parent/'iac-guard'
        run('doctor',[guard,'doctor','--mode','local-trusted','--checkov-executable',args.controlled,'--format','json'])
        if not args.adapter_only:
            before=tmp/'before';before.mkdir()
            source='resource "aws_ebs_volume" "target" {\n availability_zone="us-east-1a"\n size=1\n encrypted=false\n}\n'
            (before/'main.tf').write_text(source)
            for label,content,expected,verdict in [('repaired',source.replace('false','true'),0,'VERIFIED'),
                ('negative',source+'# unchanged failing property\n',1,'FAILED'),('missing','# target removed\n',3,'INCONCLUSIVE')]:
                after=tmp/label;after.mkdir();(after/'main.tf').write_text(content)
                report=out/(label+'.json')
                run(label,[guard,'verify','--before',before,'--after',after,'--target','CKV_AWS_3=aws_ebs_volume.target',
                    '--framework','terraform','--local-trusted','--checkov-executable',args.controlled,'--format','json','--output',report,'--quiet'],expected=(expected,))
                assert json.loads(report.read_text())['verdict']==verdict
            result['repair_exit_controls']={'positive':0,'unchanged_failing_property':1,'missing_target':3}
    result['result']='PASS'
    result['commands']=commands
    (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
