#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_chmod.py.
Usage: python3 tests/qemu_test_chmod_setup.py <workdir>
Creates a disk.img holding ONLY users.txt (root-owned, mode 0600):
alice uid 1000 password pwalice, bob uid 1001 password pwbob,
fixed salts so the hashes are deterministic. No other files: the
test's secret.txt is created by the shell `write` command itself,
so nothing on the disk can mask a chmod failure.
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
     "--user", "alice:1000:pwalice:aaaa1111",
     "--user", "bob:1001:pwbob:bbbb2222"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0"])
print("chmod test fixtures ready in", WORK)
