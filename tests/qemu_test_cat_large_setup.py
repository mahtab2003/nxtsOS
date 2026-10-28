#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_cat_large.py.
Usage: python3 tests/qemu_test_cat_large_setup.py <workdir>
Creates one disk holding users.txt (root-owned, mode 0600:
root uid 0 password pwroot, alice uid 1000 password pwalice,
fixed salts) plus:
- big.txt (mode 0644, uid 0): 120 lines of 26 bytes each
  (3120 bytes total), so it spans four 1023-byte cat windows
  and no single window holds the whole file.
- small.txt (mode 0644, uid 0): one short line, the control
  that small files still print exactly as before.
- audit.log (mode 0600, uid 0): pre-seeded to exactly 4000
  bytes ("SEED-HEAD" + "seed-line" filler + "SEED-TAIL"),
  the motivating case from AUTONOMOUS.md — a near-full log
  the old 1023-byte cat refused outright. The boot's own
  login-ok entry appends after the seed tail, so the cat
  read-back must show head, tail, and the appended entry,
  in that order.
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
     "--user", "root:0:pwroot:cccc3333",
     "--user", "alice:1000:pwalice:dddd4444"])
big = b"".join(f"BIG-{i:04d} ----------------\n".encode() for i in range(120))
assert len(big) == 3120, len(big)
with open(os.path.join(WORK, "big.txt"), "wb") as f:
    f.write(big)
with open(os.path.join(WORK, "small.txt"), "wb") as f:
    f.write(b"SMALL-FILE-OK\n")
head, tail, fill = b"SEED-HEAD\n", b"SEED-TAIL\n", b"seed-line\n"
n = (4000 - len(head) - len(tail)) // len(fill)
seed = head + fill * n + tail
assert len(seed) == 4000, len(seed)
with open(os.path.join(WORK, "audit.log"), "wb") as f:
    f.write(seed)
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"big.txt:{os.path.join(WORK, 'big.txt')}:644:0",
     "--add", f"small.txt:{os.path.join(WORK, 'small.txt')}:644:0",
     "--add", f"audit.log:{os.path.join(WORK, 'audit.log')}:600:0"])
print("Cat-large test fixtures ready in", WORK)
