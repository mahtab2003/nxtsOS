#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_monitor_disk.py.
Usage: python3 tests/qemu_test_monitor_disk_setup.py <workdir>
The disk holds only readme.txt (Files Hash pattern). The
test does not need fixed contents: it checks the Monitor's
disk marker against the shell's own `fs` output for the
same disk, so any disk size works. No users.txt: the test
boots in setup mode (root, no login).
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
    f.write("nxtsOS monitor disk test\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"])
print("Monitor-disk disk ready in", WORK)
