#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_repo_httpsa.py.
Usage: python3 tests/qemu_test_repo_httpsa_setup.py <workdir>
Requires build/calc.nxpkg, build/sysinfo.nxpkg and
build/signing.key (from scripts/build.sh).
Creates: repo_httpsa_v1 (index v1: calc 1.0, sysinfo 1.0),
an intermediate anchor CA + a leaf for repo.test signed by
it (chain.pem = leaf + intermediate), a self-signed cert
for repo.test (the BAD case: TOFU would accept it, anchored
mode must refuse it), tlsanchors.txt holding the
intermediate's RSA modulus, and disk.img carrying readme +
tlsanchors.txt for the guest. The test serves the repo
directory over TLS through the peer harness; nothing here
is served over plain HTTP.
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

def modhex(cert):
    out = subprocess.run(["openssl", "x509", "-in", cert, "-modulus",
                          "-noout"], check=True, capture_output=True,
                         text=True).stdout
    return out.strip().split("=", 1)[1].strip()

pkgs = [os.path.join(ROOT, "build", n) for n in
        ("calc.nxpkg", "sysinfo.nxpkg")]
for p in pkgs:
    if not os.path.isfile(p):
        print(f"missing {p} — run scripts/build.sh first"); raise SystemExit(1)
run(["python3", os.path.join(ROOT, "tools", "mkrepo.py"),
     "--key", KEY, "--out", os.path.join(WORK, "repo_httpsa_v1"),
     "--version", "1"] + pkgs)
# Intermediate anchor CA (CA:TRUE).
run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/int-key.pem", "-out", f"{WORK}/int-cert.pem",
     "-days", "2", "-nodes", "-subj", "/CN=Test Anchor CA",
     "-addext", "basicConstraints=critical,CA:TRUE"])
# Leaf for repo.test, signed by the intermediate.
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/leaf-key.pem", "-out", f"{WORK}/leaf.csr",
     "-nodes", "-subj", "/CN=repo.test",
     "-addext", "subjectAltName=DNS:repo.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/leaf.csr",
     "-CA", f"{WORK}/int-cert.pem", "-CAkey", f"{WORK}/int-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/leaf-cert.pem", "-days", "2"])
with open(f"{WORK}/chain.pem", "w") as f:
    f.write(open(f"{WORK}/leaf-cert.pem").read())
    f.write(open(f"{WORK}/int-cert.pem").read())
# Self-signed repo.test cert (BAD case server cert).
run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/selfsigned.key", "-out", f"{WORK}/selfsigned.crt",
     "-days", "2", "-nodes", "-subj", "/CN=repo.test",
     "-addext", "subjectAltName=DNS:repo.test",
     "-addext", "basicConstraints=critical,CA:TRUE"])
with open(f"{WORK}/tlsanchors.txt", "w") as f:
    f.write(modhex(f"{WORK}/int-cert.pem") + "\n")
with open(f"{WORK}/readme.txt", "w") as f:
    f.write("nxtsOS repo httpsa test disk\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}",
     "--add", f"tlsanchors.txt:{os.path.join(WORK, 'tlsanchors.txt')}"])
print("Repo httpsa test fixtures ready in", WORK)
