"""Shared protected invocation boundary for the native Terraform parser."""
from __future__ import annotations

import contextlib
import importlib
import tempfile
import threading
from pathlib import Path


_HCL2_CACHE_LOCK = threading.Lock()
_HCL2_SECURE_CACHE_READY = False


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


__all__ = ["isolated_hcl2_parser_cache"]
