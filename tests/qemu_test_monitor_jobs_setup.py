#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_monitor_jobs.py.
Usage: python3 tests/qemu_test_monitor_jobs_setup.py <workdir>
Requires build/calc.nxpkg (from scripts/build.sh).
The disk holds only calc.nxpkg, NOT installed: boot 1 installs
it (calc.elf + packages.txt follow it in slot order), so the
mode-14 script's Files row 1 is certainly calc.elf. No
users.txt: the test boots in setup mode (root, no login).
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
     "--add", f"calc.nxpkg:{os.path.join(ROOT, 'build', 'calc.nxpkg')}"])
print("Monitor-jobs disk ready in", WORK)
