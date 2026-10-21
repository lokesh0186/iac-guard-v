"""Small synthetic, offline Checkov authority fixtures; no research corpus inputs."""
from pathlib import Path
import json


def create(root: Path) -> None:
    terraform = root / 'terraform'
    kubernetes = root / 'kubernetes'
    terraform.mkdir(parents=True)
    kubernetes.mkdir()
    for label, value in [('bad', 'false'), ('good', 'true'), ('unchanged', 'false')]:
        (terraform / (label + '.tf')).write_text(
            f'resource "aws_ebs_volume" "{label}" {{\n availability_zone = "us-east-1a"\n size = 1\n encrypted = {value}\n}}\n')
    (terraform / 'suppressed.tf').write_text('resource "aws_ebs_volume" "suppressed" {\n #checkov:skip=CKV_AWS_3:qualification suppression control\n availability_zone = "us-east-1a"\n encrypted = false\n}\n')
    (terraform / 'security_group.tf').write_text('resource "aws_security_group" "ssh" {\n ingress {\n from_port = 22\n to_port = 22\n protocol = "tcp"\n cidr_blocks = ["0.0.0.0/0"]\n }\n}\n')
    (terraform / 'security_group_positive.tf').write_text('resource "aws_security_group" "restricted" {\n ingress {\n description="restricted SSH"\n from_port=22\n to_port=22\n protocol="tcp"\n cidr_blocks=["10.0.0.0/8"]\n }\n ingress {\n description="restricted RDP"\n from_port=3389\n to_port=3389\n protocol="tcp"\n cidr_blocks=["10.0.0.0/8"]\n }\n}\n')
    (terraform / 'rdp_negative.tf').write_text('resource "aws_security_group" "rdp" {\n ingress {\n from_port=3389\n to_port=3389\n protocol="tcp"\n cidr_blocks=["0.0.0.0/0"]\n }\n}\n')
    (terraform / 's3_direct_positive.tf').write_text('resource "aws_s3_bucket" "direct_positive" {\n bucket="qualification-direct-positive"\n logging {\n target_bucket="qualification-logs"\n target_prefix="audit/"\n }\n server_side_encryption_configuration {\n rule {\n apply_server_side_encryption_by_default {\n sse_algorithm="AES256"\n }\n }\n }\n}\n')
    (terraform / 's3_direct_negative.tf').write_text((terraform / 's3_direct_positive.tf').read_text().replace('direct_positive','direct_negative').replace('AES256','not-a-supported-cipher'))
    for label, value in [('graph_bad', 'false'), ('graph_good', 'true')]:
        (terraform / (label + '.tf')).write_text(
            f'resource "aws_s3_bucket" "{label}" {{\n bucket = "qualification-{label.replace("_", "-")}"\n}}\n'
            f'resource "aws_s3_bucket_public_access_block" "{label}" {{\n bucket = aws_s3_bucket.{label}.id\n block_public_acls = {value}\n block_public_policy = {value}\n}}\n')
    (terraform / 'graph_missing.tf').write_text('resource "aws_s3_bucket" "graph_missing" {\n bucket = "qualification-missing"\n}\n')
    for label, secure in [('bad', False), ('good', True), ('suppressed', False), ('uid_namespace', False)]:
        spec = {'containers': [{'name': 'app', 'image': 'nginx:1.29.0',
            'securityContext': {'allowPrivilegeEscalation': not secure, 'readOnlyRootFilesystem': secure,
                'runAsUser': 10001 if secure else 0}, 'resources': {'requests': {'cpu': '100m','memory': '32Mi'},
                    'limits': {'cpu': '200m','memory': '64Mi'}}}]}
        if label == 'uid_namespace':
            spec['hostUsers'] = False
        doc = {'apiVersion': 'v1','kind': 'Pod','metadata': {'name': label.replace('_','-'),'namespace':'qualification'},'spec':spec}
        if label == 'suppressed':
            doc['metadata']['annotations'] = {'checkov.io/skip1':'CKV_K8S_20=qualification suppression control'}
        (kubernetes / (label + '.json')).write_text(json.dumps(doc,indent=2)+'\n')
    for label, policy in [('graph_good', True), ('graph_bad', False)]:
        name = label.replace('_','-')
        doc = {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'qualification','labels':{'case':name}},
            'spec':{'containers':[{'name':'app','image':'nginx:1.29.0'}]}}
        (kubernetes / (label + '.json')).write_text(json.dumps(doc)+'\n')
        if policy:
            (kubernetes / 'network-policy.json').write_text(json.dumps({'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
                'metadata':{'name':'selected','namespace':'qualification'},'spec':{'podSelector':{'matchLabels':{'case':name}},'policyTypes':['Ingress'],'ingress':[]}})+'\n')
    bad = root / 'parser_failure'
    bad.mkdir()
    (bad / 'invalid.tf').write_text('resource "aws_ebs_volume" "broken" { encrypted = [\n')
    (root/'safe-config.yml').write_text('quiet: false\n')


if __name__ == '__main__':
    import sys
    create(Path(sys.argv[1]))
