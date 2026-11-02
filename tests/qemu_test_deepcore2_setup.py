#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_deepcore2.py.
Usage: python3 tests/qemu_test_deepcore2_setup.py <workdir>
Creates disk.img with:
  users.txt (admin uid 0, bob uid 1000),
  secret.txt (admin-owned, mode 600, for the fd perm test),
  fdtest.elf, fifowriter.elf, fiforeader.elf,
  flocklock.elf, flocktry.elf, permtest.elf.
Requires the build/*.elf files (from scripts/build.sh).
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
     "--user", "bob:1000:pwbob:bbbb1111"])
with open(os.path.join(WORK, "secret.txt"), "wb") as f:
    f.write(b"admin secret\n")
adds = [
    f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
    f"secret.txt:{os.path.join(WORK, 'secret.txt')}:600:0",
]
for prog in ("fdtest", "fifowriter", "fiforeader", "flocklock", "flocktry", "permtest"):
    adds.append(f"{prog}.elf:{os.path.join(ROOT, 'build', prog + '.elf')}:644:0")
cmd = ["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
       os.path.join(WORK, "disk.img")]
for a in adds:
    cmd += ["--add", a]
run(cmd)
print("deepcore2 test fixtures ready in", WORK)
