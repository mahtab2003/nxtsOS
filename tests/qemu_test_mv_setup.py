#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_mv.py.
Usage: python3 tests/qemu_test_mv_setup.py <workdir>
Creates an (almost) empty disk.img holding alpha.txt (content
"alpha content\\n") and keep.txt, for the shell `mv` test.
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
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"alpha.txt:{os.path.join(WORK, 'alpha.txt')}",
     "--add", f"keep.txt:{os.path.join(WORK, 'keep.txt')}"])
print("mv test fixtures ready in", WORK)
