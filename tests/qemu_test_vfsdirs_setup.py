#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_vfsdirs.py.
Usage: python3 tests/qemu_test_vfsdirs_setup.py <workdir>
Creates disk.img with:
  users.txt (admin uid 0, alice uid 1000),
  root.txt (an old-format root file: mkdisk writes reserved[1] = 0
  for every entry, exactly like a pre-VFS disk, so the whole disk
  IS the old-disk compatibility fixture — no migration step).
Requires tools/mkuser.py and tools/mkdisk.py.
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

def w(name, data):
    with open(os.path.join(WORK, name), "wb") as f:
        f.write(data)

w("root.txt", b"old disk root file\n")
run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "admin:0:pwadmin:aaad0000",
     "--user", "alice:1000:pwalice:bbbb1111"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"root.txt:{os.path.join(WORK, 'root.txt')}:644:0"])
print("vfsdirs test fixtures ready in", WORK)
