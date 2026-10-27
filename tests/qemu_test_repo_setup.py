#!/usr/bin/env python3
"""Build the repo fixtures for tests/qemu_test_repo.py.
Usage: python3 tests/qemu_test_repo_setup.py <workdir>
Requires build/hello.elf, build/hello2.elf, build/greet.elf,
build/signing.key (from scripts/build.sh).
Creates: repo_v1 (index v1: hello 1.0, greet 1.0, badsig 1.0),
repo_v2 (index v2: hello 1.1, greet 1.0, badsig 1.0),
repo_tampered (v2 index with one byte flipped, same signature),
and an (almost) empty disk.img for the guest.
The test serves these dirs over HTTP, rewriting the served dir
between boots.
"""
import os, shutil, subprocess, sys
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

def mkrepo(outdir, version, pkgs):
    run(["python3", os.path.join(ROOT, "tools", "mkrepo.py"),
         "--key", KEY, "--out", outdir, "--version", str(version)] + pkgs)

hello = os.path.join(ROOT, "build", "hello.elf")
hello2 = os.path.join(ROOT, "build", "hello2.elf")
greet = os.path.join(ROOT, "build", "greet.elf")
mkpkg(os.path.join(WORK, "hello10.nxpkg"), "hello", "1.0", "", [("hello.elf", hello)])
mkpkg(os.path.join(WORK, "hello11.nxpkg"), "hello", "1.1", "", [("hello.elf", hello2)])
mkpkg(os.path.join(WORK, "greet10.nxpkg"), "greet", "1.0", "hello>=1.0", [("greet.elf", greet)])
wrong_key = os.path.join(WORK, "wrong.key")
run(["openssl", "genrsa", "-out", wrong_key, "2048"])
mkpkg(os.path.join(WORK, "badsig10.nxpkg"), "badsig", "1.0", "", [("bad.elf", hello)], key=wrong_key)
mkrepo(os.path.join(WORK, "repo_v1"), 1,
       [os.path.join(WORK, "hello10.nxpkg"), os.path.join(WORK, "greet10.nxpkg"),
        os.path.join(WORK, "badsig10.nxpkg")])
mkrepo(os.path.join(WORK, "repo_v2"), 2,
       [os.path.join(WORK, "hello11.nxpkg"), os.path.join(WORK, "greet10.nxpkg"),
        os.path.join(WORK, "badsig10.nxpkg")])
if os.path.isdir(os.path.join(WORK, "repo_tampered")):
    shutil.rmtree(os.path.join(WORK, "repo_tampered"))
shutil.copytree(os.path.join(WORK, "repo_v2"), os.path.join(WORK, "repo_tampered"))
idx = os.path.join(WORK, "repo_tampered", "index.txt")
data = open(idx, "rb").read()
# Flip a version digit inside an entry (same length, signature
# now invalid, content otherwise parseable) — the refusal must
# come from the signature check, not from malformed syntax.
assert b"hello|1.1|" in data
open(idx, "wb").write(data.replace(b"hello|1.1|", b"hello|1.9|", 1))
with open(os.path.join(WORK, "readme.txt"), "w") as f:
    f.write("nxtsOS repo test disk\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"])
print("Repo test fixtures ready in", WORK)
