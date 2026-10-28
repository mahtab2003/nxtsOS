#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_repo_set.py.
Usage: python3 tests/qemu_test_repo_set_setup.py <workdir>
Requires build/sysinfo.nxpkg and build/signing.key (from scripts/build.sh).
Creates: repo_v1 (index v1, exactly 1 package: sysinfo 1.0 — so the
Repo window's row 0 is certainly sysinfo, no index-order guessing)
and an (almost) empty disk.img for the guest. No repo.txt is seeded:
the desktop Set repo step is what configures the repository.
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

pkg = os.path.join(ROOT, "build", "sysinfo.nxpkg")
if not os.path.isfile(pkg):
    print(f"missing {pkg} — run scripts/build.sh first"); raise SystemExit(1)
run(["python3", os.path.join(ROOT, "tools", "mkrepo.py"),
     "--key", KEY, "--out", os.path.join(WORK, "repo_v1"),
     "--version", "1", pkg])
with open(os.path.join(WORK, "readme.txt"), "w") as f:
    f.write("nxtsOS repo set test disk\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"])
print("Repo set test fixtures ready in", WORK)
