#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_parity_fg.py.
Usage: python3 tests/qemu_test_parity_fg_setup.py <workdir>
Creates:
  fg.img — slow10.elf + longrun.elf (from build/,
     root-owned 644) for the fg/wait checks (slow10 is
     the natural-finish job; slow.elf is NOT used here:
     its per-second prints break verified sends).
  fgusers.img — users.txt (admin uid 0 / pwadmin, alice uid
     1000 / pwalice) + longrun.elf for the cross-user
     fg/wait refusal checks (via su, since logout would
     kill the session's own jobs).
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "fg.img"),
     "--add", f"slow10.elf:{os.path.join(ROOT, 'build', 'slow10.elf')}:644:0",
     "--add", f"longrun.elf:{os.path.join(ROOT, 'build', 'longrun.elf')}:644:0"])
run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "admin:0:pwadmin:aaad0000",
     "--user", "alice:1000:pwalice:aaaa1111"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "fgusers.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"longrun.elf:{os.path.join(ROOT, 'build', 'longrun.elf')}:644:0"])
print("parity_fg test fixtures ready in", WORK)
