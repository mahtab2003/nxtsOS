#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_repo_bench.py.
Usage: python3 tests/qemu_test_repo_bench_setup.py <workdir>
Requires build/calc.nxpkg, build/term.nxpkg, build/bench.nxpkg
and build/signing.key (from scripts/build.sh).
Creates: repo_v1 (index v1: calc 1.0, term 1.0, bench 1.0 —
the published repo's contents plus the new bench package)
and an (almost) empty disk.img for the guest.
Unlike tests/qemu_test_repo_setup.py this fixture is about
one thing only: the new package must flow through the real
repo path (repo set, update, install by name, list, run).
Tamper/signature mechanics are already covered by the repo
test and are not re-proven here.
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

pkgs = [os.path.join(ROOT, "build", n) for n in
        ("calc.nxpkg", "term.nxpkg", "bench.nxpkg")]
for p in pkgs:
    if not os.path.isfile(p):
        print(f"missing {p} — run scripts/build.sh first"); raise SystemExit(1)
run(["python3", os.path.join(ROOT, "tools", "mkrepo.py"),
     "--key", KEY, "--out", os.path.join(WORK, "repo_v1"),
     "--version", "1"] + pkgs)
with open(os.path.join(WORK, "readme.txt"), "w") as f:
    f.write("nxtsOS repo bench test disk\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"])
print("Repo bench test fixtures ready in", WORK)
