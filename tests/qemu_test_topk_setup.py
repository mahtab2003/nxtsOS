#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_topk.py.
Usage: python3 tests/qemu_test_topk_setup.py <workdir>
Creates disk.img with users.txt (admin uid 0, alice uid 1000)
and longrun.elf (60 s background job, so the top-k refusal
test never races the job's natural exit).
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
     "--user", "alice:1000:pwalice:aaaa1111"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"longrun.elf:{os.path.join(ROOT, 'build', 'longrun.elf')}:644:0"])
print("topk test fixtures ready in", WORK)
