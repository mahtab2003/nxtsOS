#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_repo_scroll.py.
Usage: python3 tests/qemu_test_repo_scroll_setup.py <workdir>
Requires build/calc.nxpkg, build/term.nxpkg, build/bench.nxpkg, build/sysinfo.nxpkg
and build/signing.key (from scripts/build.sh).
Creates: repo_v1 (index v1, 10 packages: the 4 real ones plus 6 tiny
scroll-a..scroll-f packages, each a signed NXPKG002 wrapping a small
text payload — enough entries that the Repo window's 8-row view must
scroll to show them all) and an (almost) empty disk.img for the guest.
Only the scroll behaviour is under test here; signature/tamper mechanics
are already covered by the repo test, and install-by-name by the avail test.
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
        ("calc.nxpkg", "term.nxpkg", "bench.nxpkg", "sysinfo.nxpkg")]
for p in pkgs:
    if not os.path.isfile(p):
        print(f"missing {p} — run scripts/build.sh first"); raise SystemExit(1)
payload = os.path.join(WORK, "payload.txt")
with open(payload, "w") as f:
    f.write("repo scroll test payload\n")
for suffix in "abcdef":
    out = os.path.join(WORK, f"scroll-{suffix}.nxpkg")
    run(["python3", os.path.join(ROOT, "tools", "mkpkg.py"), out,
         "--name", f"scroll-{suffix}", "--version", "1.0",
         "--file", f"note.txt:{payload}", "--sign-key", KEY])
    pkgs.append(out)
run(["python3", os.path.join(ROOT, "tools", "mkrepo.py"),
     "--key", KEY, "--out", os.path.join(WORK, "repo_v1"),
     "--version", "1"] + pkgs)
with open(os.path.join(WORK, "readme.txt"), "w") as f:
    f.write("nxtsOS repo scroll test disk\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"])
print("Repo scroll test fixtures ready in", WORK)
