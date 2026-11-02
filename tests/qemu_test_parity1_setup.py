#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_parity1.py.
Usage: python3 tests/qemu_test_parity1_setup.py <workdir>
Creates:
  blank.img — an empty nxtsFS: setup-mode boots (root shell)
     start here.
  a.img — a fresh copy of blank.img for the date boot.
  users.img — users.txt (admin uid 0, password pwadmin;
     alice uid 1000, password pwalice; bob uid 1001, password
     pwbob, all fixed salts) + pub.txt ("public data",
     root-owned 644: mkdisk writes reserved[0] = 0, so this
     is the old-format file for the no-group checks).
  top.img — longrun.elf (from build/, root-owned 644)
     for the runbg jobs the top-k tests kill (60 s life,
     so the kill never races the job exit).
"""
import os, shutil, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "blank.img")])
shutil.copyfile(os.path.join(WORK, "blank.img"),
                os.path.join(WORK, "a.img"))
run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "admin:0:pwadmin:aaad0000",
     "--user", "alice:1000:pwalice:aaaa1111",
     "--user", "bob:1001:pwbob:aaaa2222"])
with open(os.path.join(WORK, "pub.txt"), "wb") as f:
    f.write(b"public data\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "users.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"pub.txt:{os.path.join(WORK, 'pub.txt')}:644:0"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "top.img"),
     "--add", f"longrun.elf:{os.path.join(ROOT, 'build', 'longrun.elf')}:644:0"])
print("parity1 test fixtures ready in", WORK)
