#!/usr/bin/env python3
"""Build the disk for tests/security_test_desktop.py.
Usage: python3 tests/security_test_desktop_setup.py <workdir>
Requires build/calc.elf, build/guibad.elf (from scripts/build.sh).
Disk: users root/user, a root-owned settings.txt (0600, uid 0),
guibad.elf, and calc.nxpkg (not pre-installed; the test installs it
as root in its tamper boot, so a pre-seeded calc.elf must NOT be
on the disk or the install would be refused as "file already exists
on disk")."""
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
     "--user", "root:0:rootpass", "--user", "user:1000:userpass"])
open(os.path.join(WORK, "settings.txt"), "w").write("idle=120\nmouse=1\nclock=1\nicons=1\n")
run(["python3", os.path.join(ROOT, "tools", "mkpkg.py"),
     os.path.join(WORK, "calc.nxpkg"), "--name", "calc", "--version", "1.0",
     "--file", f"calc.elf:{os.path.join(ROOT, 'build', 'calc.elf')}",
     "--sign-key", os.path.join(ROOT, "build", "signing.key")])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"settings.txt:{os.path.join(WORK, 'settings.txt')}:600:0",
     "--add", f"guibad.elf:{os.path.join(ROOT, 'build', 'guibad.elf')}",
     "--add", f"calc.nxpkg:{os.path.join(WORK, 'calc.nxpkg')}"])
print("Desktop security disk ready in", WORK)
