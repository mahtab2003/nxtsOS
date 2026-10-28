#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_files_hash.py.
Usage: python3 tests/qemu_test_files_hash_setup.py <workdir>
The disk holds only readme.txt, so the mode-23 script's row 0
is certainly it. The content is fixed and known: the test
computes its SHA-256 with hashlib and checks the kernel's
desktop hash marker against it. No users.txt: the test boots
in setup mode (root, no login).
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
    f.write("nxtsOS files hash test\nsecond line, known bytes\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"])
print("Files-hash disk ready in", WORK)
