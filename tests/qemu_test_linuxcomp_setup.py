#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_linuxcomp.py.
Usage: python3 tests/qemu_test_linuxcomp_setup.py <workdir>
Creates disk.img with:
  users.txt (admin uid 0, bob uid 1000, carol uid 1001),
  groups.txt (sudo:1000:bob),
  a.txt, g1.txt, g2.txt (glob/link fixtures),
  hosts.txt (10.0.2.99 testbox),
  repo_index.txt + repo_index.sig (signed calc 1.0 + term 1.0,
  the exact files `pkg update` writes, so `pkg search` works
  without a network fetch),
  longrun.elf (60 s background job for sched/nice tests).
Requires build/calc.nxpkg, build/term.nxpkg, build/longrun.elf
(from scripts/build.sh) and build/signing.key.
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.path.join(ROOT, "build", "signing.key")

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

def w(name, data):
    with open(os.path.join(WORK, name), "wb") as f:
        f.write(data)

w("a.txt", b"alpha content\n")
w("g1.txt", b"g-one\n")
w("g2.txt", b"g-two\n")
w("hosts.txt", b"10.0.2.99 testbox\n")
w("groups.txt", b"sudo:1000:bob\n")
run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "admin:0:pwadmin:aaad0000",
     "--user", "bob:1000:pwbob:bbbb1111",
     "--user", "carol:1001:pwcarol:cccc2222"])
run(["python3", os.path.join(ROOT, "tools", "mkrepo.py"),
     "--key", KEY, "--out", os.path.join(WORK, "repo"), "--version", "2",
     os.path.join(ROOT, "build", "calc.nxpkg"),
     os.path.join(ROOT, "build", "term.nxpkg")])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"groups.txt:{os.path.join(WORK, 'groups.txt')}:644:0",
     "--add", f"a.txt:{os.path.join(WORK, 'a.txt')}:644:0",
     "--add", f"g1.txt:{os.path.join(WORK, 'g1.txt')}:644:0",
     "--add", f"g2.txt:{os.path.join(WORK, 'g2.txt')}:644:0",
     "--add", f"hosts.txt:{os.path.join(WORK, 'hosts.txt')}:644:0",
     "--add", f"repo_index.txt:{os.path.join(WORK, 'repo', 'index.txt')}:644:0",
     "--add", f"repo_index.sig:{os.path.join(WORK, 'repo', 'index.txt.sig')}:644:0",
     "--add", f"longrun.elf:{os.path.join(ROOT, 'build', 'longrun.elf')}:644:0"])
print("linuxcomp test fixtures ready in", WORK)
