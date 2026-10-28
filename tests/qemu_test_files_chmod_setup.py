#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_files_chmod.py.
Usage: python3 tests/qemu_test_files_chmod_setup.py <workdir>
The disk holds only readme.txt, so the mode-26 script's row 0
is certainly it. No users.txt: the test boots in setup mode
(root, no login) — the non-owner branch is the shell's rule,
already proven by the shell chmod test, not re-proven here.
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

with open(os.path.join(WORK, "readme.txt"), "w") as f:
    f.write("nxtsOS files chmod test\nknown bytes\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"])
print("Files-chmod disk ready in", WORK)
