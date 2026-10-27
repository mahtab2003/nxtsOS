#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_pkgsig.py.
Usage: python3 tests/qemu_test_pkgsig_setup.py <workdir>
Creates in <workdir>: a keyring key (kr.key, NOT shipped — the test
only needs its modulus), pubkeys.txt (one 512-hex-char modulus line),
krhello.nxpkg (hello 1.0 signed with the keyring key, NOT the vendor
key), and disk.img carrying pubkeys.txt + krhello.nxpkg.
Requires build/hello.elf (from scripts/build.sh). The point of the
test: the kernel must install this package ONLY because the keyring
lists the key — the compiled-in vendor key does not sign it.
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"failed: {' '.join(cmd)}\n{r.stderr}")

kr_key = os.path.join(WORK, "kr.key")
run(["openssl", "genrsa", "-out", kr_key, "2048"])
r = subprocess.run(["openssl", "rsa", "-in", kr_key, "-modulus", "-noout"],
                   capture_output=True, text=True)
mod = r.stdout.strip().split("=", 1)[1].lower()
assert len(mod) == 512, f"expected 512-hex-char modulus, got {len(mod)}"
with open(os.path.join(WORK, "pubkeys.txt"), "w") as f:
    f.write(mod + "\n")
run(["python3", os.path.join(ROOT, "tools", "mkpkg.py"),
     os.path.join(WORK, "krhello.nxpkg"),
     "--name", "hello", "--version", "1.0",
     "--file", f"hello.elf:{os.path.join(ROOT, 'build', 'hello.elf')}",
     "--sign-key", kr_key])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"pubkeys.txt:{os.path.join(WORK, 'pubkeys.txt')}",
     "--add", f"krhello.nxpkg:{os.path.join(WORK, 'krhello.nxpkg')}"])
print("Keyring test disk ready in", WORK)
