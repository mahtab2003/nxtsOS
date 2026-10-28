#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_web_save.py.
Usage: python3 tests/qemu_test_web_save_setup.py <workdir>
The disk holds only readme.txt (Files Hash pattern). The
test does not need fixed disk contents: it checks the
saved page bytes against the served page, so any disk
works. No users.txt: the test boots in setup mode (root,
no login).
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
    f.write("nxtsOS web save test disk\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"])
print("Web-save disk ready in", WORK)
