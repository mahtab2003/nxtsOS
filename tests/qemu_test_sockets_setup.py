#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_sockets.py.
Usage: python3 tests/qemu_test_sockets_setup.py <workdir>
Creates disk.img with users.txt (admin uid 0, alice uid 1000)
and sockprog.elf (the §15.2 user-program socket test).
Requires tools/mkuser.py and tools/mkdisk.py, plus
build/sockprog.elf (from scripts/build.sh).
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "admin:0:pwadmin:aaad0000",
     "--user", "alice:1000:pwalice:bbbb1111"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"sockprog.elf:{os.path.join(ROOT, 'build', 'sockprog.elf')}:644:0"])
print("sockets test fixtures ready in", WORK)
