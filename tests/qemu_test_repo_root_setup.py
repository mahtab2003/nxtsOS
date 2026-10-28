#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_repo_root.py.
Usage: python3 tests/qemu_test_repo_root_setup.py <workdir>
Requires build/sysinfo.nxpkg and build/signing.key (from scripts/build.sh).
Creates: repo_v1 (index v1, exactly 1 package: sysinfo 1.0 — so the
Repo window's row 0 is certainly sysinfo, no index-order guessing)
and a disk.img holding ONLY users.txt (root-owned, mode 0600):
root uid 0 password pwroot, alice uid 1000 password pwalice,
fixed salts so the hashes are deterministic. Root's shell `pkg
update` stores the index before the desktop test runs, so no
index file is pre-seeded on the disk: the stored index the
non-root desktop reads is one a real root update wrote.
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
run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "root:0:pwroot:cccc3333",
     "--user", "alice:1000:pwalice:dddd4444"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0"])
print("Repo root test fixtures ready in", WORK)
