#!/usr/bin/env python3
"""Run only the public a7 bounded Helm materializer on sampled default charts."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
from pathlib import Path

from iac_guard_v.helm import HelmMaterializationError, HelmRenderSpec, materialize_helm

spec = importlib.util.spec_from_file_location("audit_inventory", Path(__file__).with_name("inventory.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

helm = Path(shutil.which("helm"))
results = []
for repo, root in module.HELM:
    row = {"repo": repo, "surface": root.as_posix(), "chart": root.name}
    try:
        request = HelmRenderSpec(
            chart_root=root,
            helm_executable=helm,
            release_name="a8-audit",
            namespace="default",
            kube_version="1.31.0",
        )
        with tempfile.TemporaryDirectory(prefix="iacgv-a8-audit-") as td:
            evidence = materialize_helm(request, Path(td) / "rendered")
            row.update({
                "status": "SUPPORTED",
                "reason": None,
                "resources": evidence.output["resource_count"],
                "materialization_identity": evidence.materialization_identity,
            })
    except HelmMaterializationError as exc:
        row.update({"status": "FAIL_CLOSED_PRODUCT_BOUNDARY", "reason": exc.reason_code, "detail": exc.safe_detail})
    except Exception as exc:
        row.update({"status": "NATIVE_RENDER_OR_INPUT_FAILURE", "reason": type(exc).__name__, "detail": str(exc)[:300]})
    results.append(row)
    print(row["repo"], row["chart"], row["status"], row.get("reason"), flush=True)

Path(__file__).with_name("a7_probe.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
