#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_parity_shell.py.
Usage: python3 tests/qemu_test_parity_shell_setup.py <workdir>
Creates:
  shell.img — alpha.txt ("alpha-content", root-owned 644)
     for the file-completion check. No other fixture is
     needed: history/editing tests write nothing to disk, so
     the same image is reused across all three boots.
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

with open(os.path.join(WORK, "alpha.txt"), "wb") as f:
    f.write(b"alpha-content\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "shell.img"),
     "--add", f"alpha.txt:{os.path.join(WORK, 'alpha.txt')}:644:0"])
print("parity_shell test fixtures ready in", WORK)
