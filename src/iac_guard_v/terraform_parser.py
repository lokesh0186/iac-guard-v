"""Shared protected invocation boundary for Terraform structural discovery."""
from __future__ import annotations

import contextlib
import importlib
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

import hcl2


_HCL2_CACHE_LOCK = threading.Lock()
_HCL2_SECURE_CACHE_READY = False

SCAN_EVIDENCE_BEARING = "SCAN_EVIDENCE_BEARING"
STRUCTURAL_ONLY = "STRUCTURAL_ONLY"
UNSUPPORTED = "UNSUPPORTED"
AMBIGUOUS = "AMBIGUOUS"

_EVIDENCE_BLOCKS = frozenset({"resource", "data", "module", "provider"})
_STRUCTURAL_BLOCKS = frozenset({"terraform", "variable", "output", "locals"})
_SUPPORTED_TOP_LEVEL_BLOCKS = _EVIDENCE_BLOCKS | _STRUCTURAL_BLOCKS
TERRAFORM_PARSER_CONTRACT = (
    "terraform-structural-discovery-v1",
    tuple(sorted((SCAN_EVIDENCE_BEARING, STRUCTURAL_ONLY, UNSUPPORTED, AMBIGUOUS))),
    tuple(sorted(_EVIDENCE_BLOCKS)),
    tuple(sorted(_STRUCTURAL_BLOCKS)),
)


class TerraformParserError(ValueError):
    """Typed failure from the protected Terraform parser boundary."""


@dataclass(frozen=True, slots=True)
class TerraformStructure:
    """Native-parser-derived structure used by every product entrypoint."""

    document: dict
    resource_addresses: tuple[str, ...]
    top_level_blocks: tuple[str, ...]
    coverage_kind: str
    reason: str = ""


def _parse_error_detail(exc: Exception) -> str:
    token = getattr(exc, "token", None)
    token_type = getattr(token, "type", "")
    token_value = str(token) if token is not None else ""
    expected = getattr(exc, "expected", ())
    if token_type == "STRING_CHARS" and token_value.lstrip().startswith("/*"):
        return "unterminated Terraform block comment"
    if token_type == "$END" and "DBLQUOTE" in expected:
        return "unterminated Terraform string"
    return "Terraform HCL syntax is invalid"


@contextlib.contextmanager
def isolated_hcl2_parser_cache():
    """Keep python-hcl2's generated Lark cache outside its verified package tree."""
    global _HCL2_SECURE_CACHE_READY
    with _HCL2_CACHE_LOCK:
        parser_module = importlib.import_module("hcl2.parser")
        if _HCL2_SECURE_CACHE_READY:
            yield
            return
        if not hasattr(parser_module, "PARSER_FILE"):
            # bc-python-hcl2 0.4.3, which is embedded in the locked Checkov
            # 3.3.0 environment, constructs its parser at module import and lets
            # Lark place cache bytes in the operating-system cache directory. It
            # has no package-local cache path to redirect. Reject any other
            # unrecognised parser layout instead of silently assuming it is safe.
            legacy_parser = getattr(parser_module, "hcl2", None)
            if legacy_parser is None or not callable(
                getattr(legacy_parser, "parse", None)
            ):
                raise RuntimeError("unsupported python-hcl2 parser cache layout")
            yield
            _HCL2_SECURE_CACHE_READY = True
            return
        original = parser_module.PARSER_FILE
        parser_factory = getattr(parser_module, "parser", None)
        if parser_factory is None or not callable(
            getattr(parser_factory, "cache_clear", None)
        ):
            raise RuntimeError("unsupported python-hcl2 parser cache layout")
        parser_factory.cache_clear()
        with tempfile.TemporaryDirectory(prefix="iacgv-hcl2-cache-") as directory:
            parser_module.PARSER_FILE = Path(directory) / "lark-cache.bin"
            try:
                yield
                _HCL2_SECURE_CACHE_READY = True
            finally:
                parser_module.PARSER_FILE = original


def parse_terraform_structure(content: bytes) -> TerraformStructure:
    """Parse exact UTF-8 bytes and derive the closed file-coverage category."""
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise TerraformParserError("Terraform source must be UTF-8") from exc
    try:
        with isolated_hcl2_parser_cache():
            document = hcl2.loads(text)
    except Exception as exc:
        raise TerraformParserError(_parse_error_detail(exc)) from exc
    if type(document) is not dict:
        raise TerraformParserError("Terraform HCL parser returned an invalid document")
    if any(type(key) is not str for key in document):
        raise TerraformParserError("Terraform top-level block identity is invalid")

    resource_addresses: list[str] = []
    seen: set[str] = set()
    blocks = document.get("resource", [])
    if type(blocks) is not list:
        raise TerraformParserError("Terraform resource structure is invalid")
    for block in blocks:
        if type(block) is not dict:
            raise TerraformParserError("Terraform resource block is invalid")
        for resource_type, instances in block.items():
            if type(resource_type) is not str or type(instances) is not dict:
                raise TerraformParserError("Terraform resource identity is invalid")
            for resource_name in instances:
                if type(resource_name) is not str:
                    raise TerraformParserError("Terraform resource name is invalid")
                address = f"{resource_type}.{resource_name}"
                if address in seen:
                    raise TerraformParserError("duplicate Terraform resource identity")
                seen.add(address)
                resource_addresses.append(address)

    top_level = tuple(sorted(document))
    unknown = tuple(sorted(set(top_level) - _SUPPORTED_TOP_LEVEL_BLOCKS))
    if unknown:
        coverage_kind = AMBIGUOUS
        reason = "UNRECOGNIZED_TERRAFORM_TOP_LEVEL_BLOCK:" + ",".join(unknown)
    elif set(top_level).intersection(_EVIDENCE_BLOCKS):
        coverage_kind = SCAN_EVIDENCE_BEARING
        reason = ""
    else:
        coverage_kind = STRUCTURAL_ONLY
        reason = ""
    return TerraformStructure(
        document,
        tuple(sorted(resource_addresses)),
        top_level,
        coverage_kind,
        reason,
    )


__all__ = [
    "AMBIGUOUS",
    "SCAN_EVIDENCE_BEARING",
    "STRUCTURAL_ONLY",
    "UNSUPPORTED",
    "TerraformParserError",
    "TerraformStructure",
    "TERRAFORM_PARSER_CONTRACT",
    "isolated_hcl2_parser_cache",
    "parse_terraform_structure",
]
