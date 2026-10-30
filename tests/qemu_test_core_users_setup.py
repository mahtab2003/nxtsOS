#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_core_users.py.
Usage: python3 tests/qemu_test_core_users_setup.py <workdir>
Creates two disks:
  blank.img — an empty nxtsFS (no files): setup-mode boots
     (root shell, no login) start here; useradd creates
     users.txt on it. The test copies it fresh before each
     blank-disk boot, since boots mutate it.
  admin.img — users.txt with admin uid 0 (password pwadmin,
     fixed salt) + alice uid 1000 (password pwalice, fixed
     salt): the uid-0 named session + lockout/drop boot. The
     test copies it once to admin_work.img and reuses that
     copy across the two lockout boots (the second boot must
     see the first boot's fails.txt).
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
     os.path.join(WORK, "blank.img")])
run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "admin:0:pwadmin:aaad0000",
     "--user", "alice:1000:pwalice:aaaa1111"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "admin.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0"])
print("core_users test fixtures ready in", WORK)
