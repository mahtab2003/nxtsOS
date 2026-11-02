#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_parity2.py.
Usage: python3 tests/qemu_test_parity2_setup.py <workdir>
Creates:
  files.img — a.txt ("alpha\\n", 6 bytes) + b.txt
     ("beta beta\\n", 10 bytes), root-owned 644, for the
     df/du/find/touch/cat-multi checks.
  users2.img — users.txt (admin uid 0, password pwadmin;
     alice uid 1000, password pwalice; bob uid 1001,
     password pwbob, all fixed salts) + own.txt ("mine\\n",
     alice-owned 644) + sec.txt ("secret\\n", root-owned
     600) for the su + touch-permission checks.
  top2.img — longrun.elf (from build/, root-owned 644)
     for
     the killall checks.
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

with open(os.path.join(WORK, "a.txt"), "wb") as f:
    f.write(b"alpha\n")
with open(os.path.join(WORK, "b.txt"), "wb") as f:
    f.write(b"beta beta\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "files.img"),
     "--add", f"a.txt:{os.path.join(WORK, 'a.txt')}:644:0",
     "--add", f"b.txt:{os.path.join(WORK, 'b.txt')}:644:0"])
run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "admin:0:pwadmin:aaad0000",
     "--user", "alice:1000:pwalice:aaaa1111",
     "--user", "bob:1001:pwbob:aaaa2222"])
with open(os.path.join(WORK, "own.txt"), "wb") as f:
    f.write(b"mine\n")
with open(os.path.join(WORK, "sec.txt"), "wb") as f:
    f.write(b"secret\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "users2.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"own.txt:{os.path.join(WORK, 'own.txt')}:644:1000",
     "--add", f"sec.txt:{os.path.join(WORK, 'sec.txt')}:600:0"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "top2.img"),
     "--add", f"longrun.elf:{os.path.join(ROOT, 'build', 'longrun.elf')}:644:0"])
print("parity2 test fixtures ready in", WORK)
