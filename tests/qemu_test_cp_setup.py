#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_cp.py.
Usage: python3 tests/qemu_test_cp_setup.py <workdir>
Creates a disk.img holding alpha.txt (content "alpha content\\n"),
keep.txt, and bin.dat (all 256 byte values 0..255), for the shell
`cp` test.
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

with open(os.path.join(WORK, "alpha.txt"), "w") as f:
    f.write("alpha content\n")
with open(os.path.join(WORK, "keep.txt"), "w") as f:
    f.write("keep me\n")
with open(os.path.join(WORK, "bin.dat"), "wb") as f:
    f.write(bytes(range(256)))
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"alpha.txt:{os.path.join(WORK, 'alpha.txt')}",
     "--add", f"keep.txt:{os.path.join(WORK, 'keep.txt')}",
     "--add", f"bin.dat:{os.path.join(WORK, 'bin.dat')}"])
print("cp test fixtures ready in", WORK)
