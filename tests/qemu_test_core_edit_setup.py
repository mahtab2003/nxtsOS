#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_core_edit.py.
Usage: python3 tests/qemu_test_core_edit_setup.py <workdir>
Creates:
  blank.img — an empty nxtsFS: setup-mode boots (root shell)
     start here. The test copies it fresh before each
     blank-disk boot, since boots mutate it.
  seed.img — users.txt (alice uid 1000, password pwalice,
     fixed salt) + tab.txt ("a<TAB>b", alice-owned 644) +
     big.txt (33000 bytes, root-owned 644: readable, so the
     size refusal is reached) + long.txt (one 1100-char line,
     alice-owned 644: over the 1024-byte cut cap) +
     secret.txt (root-owned 600: alice cannot read it).
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
     "--user", "alice:1000:pwalice:aaaa1111"])
with open(os.path.join(WORK, "tab.txt"), "wb") as f:
    f.write(b"a\tb\n")
with open(os.path.join(WORK, "big.txt"), "wb") as f:
    f.write(b"x" * 33000)
with open(os.path.join(WORK, "long.txt"), "wb") as f:
    f.write(b"L" * 1100 + b"\n")
with open(os.path.join(WORK, "secret.txt"), "wb") as f:
    f.write(b"top secret\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "seed.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"tab.txt:{os.path.join(WORK, 'tab.txt')}:644:1000",
     "--add", f"big.txt:{os.path.join(WORK, 'big.txt')}:644:0",
     "--add", f"long.txt:{os.path.join(WORK, 'long.txt')}:644:1000",
     "--add", f"secret.txt:{os.path.join(WORK, 'secret.txt')}:600:0"])
print("core_edit test fixtures ready in", WORK)
