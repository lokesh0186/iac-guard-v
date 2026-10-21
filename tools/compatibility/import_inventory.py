"""Observe actual dependency resolution and registered built-in policies."""
import hashlib
import importlib
import importlib.metadata
import json
import sys
from pathlib import Path

import checkov.main
from checkov.terraform.checks.resource.registry import resource_registry
from checkov.kubernetes.checks.resource.registry import registry

modules={}
for name in ['checkov','checkov.main','hcl2','yaml','lark','regex','networkx','packaging']:
    module=importlib.import_module(name)
    p=Path(module.__file__).resolve()
    modules[name]={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
for name,module in sorted(sys.modules.copy().items()):
    if name.startswith("checkov.") and getattr(module,"__file__",None):
        p=Path(module.__file__).resolve()
        if p.is_file():
            modules[name]={"path":str(p),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
policies={}
for name,obj in [('terraform',resource_registry),('kubernetes',registry)]:
    rows=set()
    for mapping in (obj.checks,obj.wildcard_checks):
        for entity,checks in mapping.items():
            for check in checks:
                rows.add((check.id,type(check).__module__,type(check).__qualname__,entity))
    policies[name]=sorted(rows)
assert policies['terraform'] and policies['kubernetes']
distributions=sorted((d.metadata['Name'],d.version,str(d._path)) for d in importlib.metadata.distributions())
print(json.dumps({'modules':modules,'registered_policies':policies,'distributions':distributions},sort_keys=True))
