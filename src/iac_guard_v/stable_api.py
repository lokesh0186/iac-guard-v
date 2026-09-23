"""Executable compatibility snapshot for the Beta1 surface carried into 1.x."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .beta_api import public_api_snapshot
from .native_properties.model import canonical_digest


STABLE_API_FREEZE_VERSION = "stable-api-freeze-v1"
BETA1_PUBLIC_API_DIGEST = "08f27c6c286fc83b3a4e7e91068f39f29e633e892389992385ac251826e09060"
CLI_SURFACE_DIGEST = "3011471083014d9012adb73bdcd012e7371e62b83923eba6ff570de324cd429e"
SCHEMA_FILE_DIGESTS = {
    "config-v1.schema.json": "8116c90ab31cafcf7f2a22afd8d71debcdc2c2f5f4dfffc518ba638f9221b967",
    "helm-acceptance-v1.schema.json": "325a5c4d3c42c5571538c2f97185271472e011535de7656b55dcfdc1c4e54bd9",
    "infrastructure-contract-report-v1alpha1.schema.json": "9104c1604cd4985df418645954e71d053e5b965666aeb8a3d6990cc3f43dc857",
    "infrastructure-contract-v1alpha1.schema.json": "eb21630e90cf29f724fd6b0886d31a4004249c87d4af25fd698dbee5e90ce721",
    "native-property-report-v1.schema.json": "2c394f49f92fbe6e4380fe6a14f24b3b9829371b5b3c0c8313295f10e6241cd9",
    "native-property-request-v1.schema.json": "d3533b86036f3ca8833b3d301acaaf9f9f0c9c5f2bdf37a8d98a8a1ba9fd01e8",
    "report-v1.schema.json": "4a9c856638e342f9672c384f80530802827a58b2e0a2d8db128fc427e99eec42",
}


def _json_default(value: Any) -> Any:
    if value is argparse.SUPPRESS:
        return "ARGPARSE_SUPPRESS"
    if value is None or type(value) in (str, bool, int, float):
        return value
    if type(value) in (list, tuple):
        return [_json_default(item) for item in value]
    if isinstance(value, Path):
        return {"path": value.as_posix()}
    return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}


def _parser_surface(parser: argparse.ArgumentParser) -> dict[str, Any]:
    actions = []
    subcommands: dict[str, Any] = {}
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction):
            continue
        if isinstance(action, argparse._SubParsersAction):
            subcommands = {
                name: _parser_surface(child)
                for name, child in sorted(action.choices.items())
            }
            continue
        actions.append({
            "action": type(action).__name__,
            "choices": sorted(action.choices) if isinstance(action.choices, (list, tuple, set)) else _json_default(action.choices),
            "default": _json_default(action.default),
            "dest": action.dest,
            "nargs": _json_default(action.nargs),
            "option_strings": list(action.option_strings),
            "required": action.required,
            "type": None if action.type is None else getattr(action.type, "__name__", str(action.type)),
        })
    mutually_exclusive = [
        {
            "required": group.required,
            "destinations": sorted(action.dest for action in group._group_actions),
        }
        for group in parser._mutually_exclusive_groups
    ]
    return {
        "actions": sorted(actions, key=lambda item: (item["dest"], item["option_strings"])),
        "mutually_exclusive": sorted(mutually_exclusive, key=lambda item: item["destinations"]),
        "subcommands": subcommands,
    }


def cli_surface_snapshot() -> dict[str, Any]:
    from .cli import _parser

    return _parser_surface(_parser())


def cli_surface_digest() -> str:
    return canonical_digest(cli_surface_snapshot())


def validate_stable_api_freeze() -> None:
    if public_api_snapshot()["snapshot_digest"] != BETA1_PUBLIC_API_DIGEST:
        raise RuntimeError("Beta1 public API snapshot changed")
    if cli_surface_digest() != CLI_SURFACE_DIGEST:
        raise RuntimeError("Beta1 CLI surface changed")


__all__ = [
    "BETA1_PUBLIC_API_DIGEST", "CLI_SURFACE_DIGEST", "SCHEMA_FILE_DIGESTS",
    "STABLE_API_FREEZE_VERSION", "cli_surface_digest", "cli_surface_snapshot",
    "validate_stable_api_freeze",
]
