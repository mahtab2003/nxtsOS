#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_desktop_reboot.py.
Usage: python3 tests/qemu_test_desktop_reboot_setup.py <workdir>
The disk is empty: the reboot test needs no package and no
file. No users.txt, so the test boots in setup mode (root,
no login) — and, crucially, boots straight back to the
shell prompt after the desktop-triggered reboot, which is
the second-boot proof.
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
     os.path.join(WORK, "disk.img")])
print("Desktop-reboot disk ready in", WORK)
