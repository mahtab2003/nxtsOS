#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_shell_idle_lock.py.
Usage: python3 tests/qemu_test_shell_idle_lock_setup.py <workdir>
Creates a disk.img holding ONLY users.txt (root-owned, mode 0600):
root uid 0 password pwroot, alice uid 1000 password pwalice,
fixed salts so the hashes are deterministic. The shell-prompt
test needs no settings.txt: the timeout the test waits out is
the shell's own `idle 1` setting, and no desktop is ever entered.
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
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0"])
print("Shell idle lock test fixtures ready in", WORK)
