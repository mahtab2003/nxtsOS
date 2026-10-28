#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_packages_rollback.py.
Usage: python3 tests/qemu_test_packages_rollback_setup.py <workdir>
Requires build/hello.elf, build/greet.elf, build/signing.key
(from scripts/build.sh).
The disk holds only bundle_good.nxupd (greet 1.0 FIRST, hello
1.0 second — the bundle's dependency, greet needs hello>=1.0,
must resolve from the bundle itself, as in the shell sysupdate
test), nothing pre-installed: boot 1's shell sysupdate installs
both and leaves the rollback snapshot the mode-18 script then
undoes from the desktop.
No users.txt: the test boots in setup mode (root, no login),
which is also the session the desktop Rollback root check
allows.
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

def mkpkg(out, name, version, depends, files):
    args = ["python3", os.path.join(ROOT, "tools", "mkpkg.py"), out,
            "--name", name, "--version", version, "--sign-key", KEY]
    if depends: args += ["--depends", depends]
    for fname, path in files:
        args += [f"--file", f"{fname}:{path}"]
    run(args)

mkpkg(os.path.join(WORK, "hello.nxpkg"), "hello", "1.0", "",
      [("hello.elf", os.path.join(ROOT, "build", "hello.elf"))])
mkpkg(os.path.join(WORK, "greet.nxpkg"), "greet", "1.0", "hello>=1.0",
      [("greet.elf", os.path.join(ROOT, "build", "greet.elf"))])
run(["python3", os.path.join(ROOT, "tools", "mkupdate.py"),
     os.path.join(WORK, "bundle_good.nxupd"),
     os.path.join(WORK, "greet.nxpkg"), os.path.join(WORK, "hello.nxpkg")])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"bundle_good.nxupd:{os.path.join(WORK, 'bundle_good.nxupd')}"])
print("Packages-rollback disk ready in", WORK)
