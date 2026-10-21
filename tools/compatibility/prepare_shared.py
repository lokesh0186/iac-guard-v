"""CI/build helper: one scanner installation, separate small SSP product venv.

Run only in a disposable, trusted build environment after installing Checkov via
its normal packaging mechanism. This never installs, changes, or removes Checkov.
"""
from __future__ import annotations

import argparse
import importlib.metadata
from pathlib import Path
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--product', type=Path, default=Path.cwd())
    parser.add_argument('--venv', type=Path, required=True)
    parser.add_argument('--checkov', type=Path, required=True)
    parser.add_argument('--launcher-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.venv.exists() or args.launcher_dir.exists():
        parser.error('Use fresh output directories; existing installations are not edited')
    subprocess.run([sys.executable, '-m', 'venv', '--copies', '--without-pip',
                    '--system-site-packages', str(args.venv)], check=True)
    python = args.venv / 'bin/python'
    install = [sys.executable, '-m', 'pip', '--python', str(python), 'install', '--no-compile']
    subprocess.run([*install, str(args.product.resolve())], check=True)
    # Only the product parser closure is local. The scanner executes with the
    # original interpreter and original global dependency resolution.
    pins = [name + '==' + importlib.metadata.version(name)
            for name in ('PyYAML', 'lark', 'regex', 'packaging')]
    subprocess.run([*install, '--ignore-installed', '--no-deps', *pins], check=True)
    subprocess.run([sys.executable, '-m', 'pip', '--python', str(python), 'check'], check=True)
    subprocess.run([python, '-m', 'iac_guard_v.external_checkov', '--checkov',
                    args.checkov.resolve(), '--destination', args.launcher_dir], check=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
