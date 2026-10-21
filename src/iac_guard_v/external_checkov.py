"""Opt-in source-only execution of an operator-owned, build-attested Checkov.

The ordinary scanner installation is never edited. The protected launcher and
manifest must be created by the trusted image build, outside candidate inputs.
This is a distinct contract; the legacy bytecode-free RECORD contract is intact.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import stat

from .models import DomainError

MARKER = "# iacgv-external-source-v1:"
SCHEMA = "iacgv-external-source-v1"
IMPORTABLE = {".py", ".pyi", ".so", ".pyd", ".dll", ".dylib"}

# -I -S and the private -X prefix apply before interpreter startup. -B alone
# would not exclude pre-existing caches. Source-less loaders are also removed.
BOOTSTRAP = '''import sys
if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and sys.pycache_prefix):
    raise SystemExit(3)
import importlib.machinery as m
sys.path_hooks[:] = [m.FileFinder.path_hook((m.ExtensionFileLoader,m.EXTENSION_SUFFIXES),(m.SourceFileLoader,m.SOURCE_SUFFIXES))]
sys.path_importer_cache.clear()
import json
roots=json.loads(sys.argv[1])
launcher=sys.argv[2]
sys.path[:]=roots
sys.argv=[launcher]+sys.argv[3:]
with open(launcher,'rb') as f:
    source=f.read()
exec(compile(source,launcher,'exec'),{'__name__':'__main__','__file__':launcher})
'''


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _regular(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode) or path.is_symlink():
                raise DomainError("external scanner file must be nonsymlink regular content")
            with os.fdopen(fd, "rb", closefd=False) as f:
                return f.read()
        finally:
            os.close(fd)
    except OSError as exc:
        raise DomainError("external scanner file cannot be read") from exc


def inventory(root: Path, *, exclude_sites: bool = False) -> dict[str, str]:
    """Caches are omitted only under the source-only invocation contract."""
    if root.is_symlink() or not root.is_dir():
        raise DomainError("external scanner root must be a regular directory")
    result = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        for entry in sorted(os.scandir(directory), key=lambda x: x.name):
            path = Path(entry.path)
            if entry.name == "__pycache__" or path.suffix.lower() in {".pyc", ".pyo"}:
                if entry.name == "__pycache__":
                    if not entry.is_dir(follow_symlinks=False):
                        raise DomainError("external cache directory must be nonsymlink directory")
                    for cached in path.iterdir():
                        if cached.is_symlink() or not cached.is_file() or cached.suffix.lower() not in {".pyc", ".pyo"}:
                            raise DomainError("external cache contains non-cache content")
                elif entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    raise DomainError("external cache must be regular derived bytecode")
                continue
            if exclude_sites and directory == root and entry.name == "site-packages":
                continue
            st = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                pending.append(path)
            elif stat.S_ISREG(st.st_mode):
                result[path.relative_to(root).as_posix()] = hashlib.sha256(_regular(path)).hexdigest()
            else:
                raise DomainError("external scanner inventory contains an unsafe entry")
    if not result:
        raise DomainError("external scanner source inventory is empty")
    return dict(sorted(result.items()))


def _source_records(sites: Path, files: dict[str, str]) -> dict:
    """Verify live importable files, not absent relocated console/doc assets.

    The build manifest binds *all* live data and metadata too. Duplicate unused
    installer metadata is not interpreted as a second executable installation;
    every live importable byte still needs a matching wheel RECORD digest.
    """
    records = {}
    manifests = sorted(sites.glob("*.dist-info/RECORD"))
    if not manifests:
        raise DomainError("external scanner requires wheel RECORD source provenance")
    for path in manifests:
        try:
            for row in csv.reader(io.StringIO(_regular(path).decode())):
                if len(row) != 3 or not row[0]:
                    raise DomainError("external scanner RECORD row is malformed")
                name = row[0].replace("\\", "/")
                if name not in files or Path(name).suffix.lower() not in IMPORTABLE:
                    continue
                algorithm, sep, encoded = row[1].partition("=")
                if algorithm != "sha256" or not sep:
                    continue
                h = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).hex()
                if files[name] == h:
                    records[name] = h
        except (UnicodeError, csv.Error, ValueError) as exc:
            raise DomainError("external scanner source RECORD cannot be verified") from exc
    missing = sorted(name for name in files if Path(name).suffix.lower() in IMPORTABLE and name not in records)
    if missing:
        raise DomainError("external scanner importable code lacks matching RECORD: " + missing[0])
    return records


def launcher_bytes(manifest: dict, manifest_bytes: bytes) -> bytes:
    roots = [manifest["stdlib"], str(Path(manifest["stdlib"]) / "lib-dynload"), manifest["site_packages"]]
    command = " ".join(shlex.quote(x) for x in [manifest["interpreter"], "-I", "-S", "-B", "-X"])
    command += ' "pycache_prefix=$cache" ' + " ".join(shlex.quote(x) for x in ["-c", BOOTSTRAP, json.dumps(roots), manifest["original_launcher"]])
    return ("#!/bin/sh\n" + MARKER + hashlib.sha256(manifest_bytes).hexdigest() + "\n"
        'cache="${TMPDIR:-/tmp}/iacgv-checkov-source-$$"\n'
        '/bin/mkdir -m 700 "$cache" || exit 3\n'
        'export TMPDIR="$cache" HOME="$cache" XDG_CACHE_HOME="$cache/cache" XDG_CONFIG_HOME="$cache/config" XDG_DATA_HOME="$cache/data"\n'
        'cd "$cache" || exit 3\n'
        + command + ' "$@"\nstatus=$?\ncd / || exit 3\n'
        + shlex.quote(manifest['interpreter']) + ' -I -S -B -X "pycache_prefix=$cache/cleanup" -c '
        + shlex.quote('import shutil,sys;shutil.rmtree(sys.argv[1])') + ' "$cache" || exit 3\nexit "$status"\n').encode()


def is_external(executable: Path) -> bool:
    return _marked(executable)


def _marked(executable: Path) -> bool:
    lines = _regular(executable).split(b"\n", 2)
    return len(lines) > 1 and lines[1].startswith(MARKER.encode())


def load_manifest(executable: Path, *, verify: bool = True) -> dict | None:
    if not _marked(executable):
        return None
    path = executable.with_name(executable.name + ".json")
    raw = _regular(path)
    try:
        d = json.loads(raw)
        required = {"schema", "version", "interpreter", "interpreter_sha256", "original_launcher", "launcher_sha256",
            "stdlib", "site_packages", "stdlib_files", "site_files", "source_records_digest"}
        if type(d) is not dict or set(d) != required or d["schema"] != SCHEMA:
            raise ValueError("invalid external manifest schema")
        for name in ("interpreter", "original_launcher", "stdlib", "site_packages"):
            p = Path(d[name])
            if not p.is_absolute() or p.resolve(strict=True) != p:
                raise ValueError("external manifest paths must be resolved absolute paths")
        if _regular(executable) != launcher_bytes(d, raw):
            raise ValueError("external launcher does not match protected manifest and bootstrap")
        if verify:
            if hashlib.sha256(_regular(Path(d["interpreter"]))).hexdigest() != d["interpreter_sha256"]:
                raise ValueError("external interpreter changed")
            if hashlib.sha256(_regular(Path(d["original_launcher"]))).hexdigest() != d["launcher_sha256"]:
                raise ValueError("external original launcher changed")
            if inventory(Path(d["stdlib"]), exclude_sites=True) != d["stdlib_files"]:
                raise ValueError("external standard library changed")
            if inventory(Path(d["site_packages"])) != d["site_files"]:
                raise ValueError("external dependency or policy source changed")
            if _digest(_source_records(Path(d["site_packages"]), d["site_files"])) != d["source_records_digest"]:
                raise ValueError("external executable source provenance changed")
            from .checkov_authority import require_published_launcher
            require_published_launcher(d['version'], _regular(Path(d['original_launcher'])))
        return d
    except (ValueError, TypeError, KeyError, OSError, RuntimeError) as exc:
        raise DomainError("external scanner build manifest failed validation: " + str(exc)) from exc


def prepare(executable: Path, destination: Path) -> Path:
    """Trusted build operation; no downloads, source edits or cache deletion."""
    executable = executable.resolve(strict=True)
    source = _regular(executable)
    first = source.splitlines()[0].decode()
    if not first.startswith("#!/"):
        raise DomainError("external Checkov needs an absolute Python shebang")
    interpreter = Path(first[2:].split()[0]).resolve(strict=True)
    _regular(interpreter)
    prefix = interpreter.parent.parent
    roots = sorted(prefix.glob("lib/python*/site-packages/checkov"))
    if len(roots) != 1:
        raise DomainError("external Checkov needs one unambiguous installed source root")
    sites = roots[0].parent
    metadata = sorted(sites.glob("checkov-*.dist-info/METADATA"))
    if len(metadata) != 1:
        raise DomainError("external Checkov distribution metadata is ambiguous")
    from email.parser import Parser
    version = Parser().parsestr(_regular(metadata[0]).decode())["Version"]
    if not version:
        raise DomainError("external Checkov version metadata is absent")
    from .checkov_authority import require_published_launcher
    require_published_launcher(version, source)
    files = inventory(sites)
    source_records = _source_records(sites, files)
    stdlib = sites.parent
    d = {"schema": SCHEMA, "version": version, "interpreter": str(interpreter),
        "interpreter_sha256": hashlib.sha256(_regular(interpreter)).hexdigest(),
        "original_launcher": str(executable), "launcher_sha256": hashlib.sha256(source).hexdigest(),
        "stdlib": str(stdlib), "site_packages": str(sites), "stdlib_files": inventory(stdlib, exclude_sites=True),
        "site_files": files, "source_records_digest": _digest(source_records)}
    raw = _canonical(d)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    launcher = destination / "checkov"
    with launcher.with_name("checkov.json").open("xb") as f:
        f.write(raw)
    with launcher.open("xb") as f:
        f.write(launcher_bytes(d, raw))
    launcher.chmod(0o755)
    return launcher


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare a protected, source-only external Checkov launcher during a trusted image build")
    parser.add_argument("--checkov", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(prepare(args.checkov, args.destination))
        return 0
    except (DomainError, OSError) as exc:
        parser.exit(3, str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
