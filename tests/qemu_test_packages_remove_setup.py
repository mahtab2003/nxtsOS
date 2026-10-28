#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_packages_remove.py.
Usage: python3 tests/qemu_test_packages_remove_setup.py <workdir>
Requires build/calc.nxpkg, build/term.nxpkg (from scripts/build.sh).
The disk holds only the two packages: boot 1 installs calc then
term (registry order calc, term), so the mode-11 script's row 1
is term. No users.txt: the test boots in setup mode (root, no
login), which is also the session the desktop Remove root check
allows.
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
     os.path.join(WORK, "disk.img"),
     "--add", f"calc.nxpkg:{os.path.join(ROOT, 'build', 'calc.nxpkg')}",
     "--add", f"term.nxpkg:{os.path.join(ROOT, 'build', 'term.nxpkg')}"])
print("Packages-remove disk ready in", WORK)
