#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_sysupdate.py.
Usage: python3 tests/qemu_test_sysupdate_setup.py <workdir>
Requires build/hello.elf, build/hello2.elf, build/greet.elf,
build/signing.key (from scripts/build.sh).
Disk: three update bundles, no plain ELFs, nothing pre-installed.
- bundle_good.nxupd: greet 1.0 FIRST, hello 1.0 second — the
  bundle's dependency (greet needs hello>=1.0) must resolve from
  the bundle itself, regardless of order.
- bundle_bad.nxupd: hello 1.1 (good) + a wrong-key-signed package
  — the whole update must be refused, hello must stay out.
- bundle_up.nxupd: hello 1.1 alone — upgrades hello 1.0 to 1.1,
  which sysrollback then undoes.
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

def mkpkg(out, name, version, depends, files, key=KEY):
    args = ["python3", os.path.join(ROOT, "tools", "mkpkg.py"), out,
            "--name", name, "--version", version, "--sign-key", key]
    if depends: args += ["--depends", depends]
    for fname, path in files:
        args += ["--file", f"{fname}:{path}"]
    run(args)

def mkupd(out, pkgs):
    run(["python3", os.path.join(ROOT, "tools", "mkupdate.py"), out] + pkgs)

hello = os.path.join(ROOT, "build", "hello.elf")
hello2 = os.path.join(ROOT, "build", "hello2.elf")
greet = os.path.join(ROOT, "build", "greet.elf")
mkpkg(os.path.join(WORK, "hello.nxpkg"), "hello", "1.0", "", [("hello.elf", hello)])
mkpkg(os.path.join(WORK, "hello11.nxpkg"), "hello", "1.1", "", [("hello.elf", hello2)])
mkpkg(os.path.join(WORK, "greet.nxpkg"), "greet", "1.0", "hello>=1.0", [("greet.elf", greet)])
wrong_key = os.path.join(WORK, "wrong.key")
run(["openssl", "genrsa", "-out", wrong_key, "2048"])
mkpkg(os.path.join(WORK, "badsig.nxpkg"), "badsig", "1.0", "", [("bad.elf", hello)], key=wrong_key)
mkupd(os.path.join(WORK, "bundle_good.nxupd"),
      [os.path.join(WORK, "greet.nxpkg"), os.path.join(WORK, "hello.nxpkg")])
mkupd(os.path.join(WORK, "bundle_bad.nxupd"),
      [os.path.join(WORK, "hello11.nxpkg"), os.path.join(WORK, "badsig.nxpkg")])
mkupd(os.path.join(WORK, "bundle_up.nxupd"), [os.path.join(WORK, "hello11.nxpkg")])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"bundle_good.nxupd:{os.path.join(WORK, 'bundle_good.nxupd')}",
     "--add", f"bundle_bad.nxupd:{os.path.join(WORK, 'bundle_bad.nxupd')}",
     "--add", f"bundle_up.nxupd:{os.path.join(WORK, 'bundle_up.nxupd')}"])
print("Sysupdate test disk ready in", WORK)
