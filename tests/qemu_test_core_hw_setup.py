#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_core_hw.py.
Usage: python3 tests/qemu_test_core_hw_setup.py <workdir>
Creates:
  blank.img — an empty nxtsFS: setup-mode boots (root shell)
     start here. The test copies it fresh before each
     blank-disk boot, since boots mutate it.
Boot 2 needs no disk (CD-ROM only).
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "blank.img")])
print("core_hw test fixtures ready in", WORK)
