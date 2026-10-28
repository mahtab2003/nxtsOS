#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_castore.py (web/SSL
Phase 1: CA store + TOFU prints + signed-bundle update).

Usage: python3 tests/qemu_test_castore_setup.py <workdir>
Requires build/signing.key (from scripts/build.sh) for the
store-bundle signature (tools/mksig.py, same signature shape
as NXPKG002 packages).

Chains (all RSA/SHA-256, the only kind the kernel verifies):
  root4096 (CN=Test Root 4096, CA:TRUE, 4096-bit) ->
  store-int (CN=Test Store CA, 2048, CA:TRUE) ->
  leaf (CN=store.test, SAN store.test + update.test).
  chain-store.pem = leaf + int + root (the 4096 tail is the
  Vercel shape: store mode must accept it, ending at the
  store member).
  badsig: leaf signed by intB (same subject, different key),
  presented intermediate is store-int -> refused.
  oversize-path: store-root (2048 CA, in the store) ->
  int4096 (4096-bit CA) -> leaf. The leaf->int4096 link
  cannot verify, so the chain must refuse EVEN THOUGH trust
  (store-root) exists further up: trust beyond an
  unverifiable link is never accepted.
  tofuA / tofuB: two different self-signed certs for
  tofu.test (first-use accept + pin, second-use mismatch).
Files: castore-store.txt (store-int modulus),
castore-oversize.txt (store-root modulus),
wrongstore.txt (unrelated modulus), castore-bundle.txt
(store-int modulus + a comment line) + .sig via mksig.py,
tampered-bundle.txt (one hex char changed, original .sig).
Disks (mkdisk.py): disk-store.img, disk-nostore.img,
disk-wrong.img, disk-oversize.img, disk-anchor.img
(tlsanchors.txt = store-int, for the anchored update fetch),
disk-tofu.img.
"""
import hashlib
import os
import subprocess
import sys

WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.path.join(ROOT, "build", "signing.key")


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        raise SystemExit(1)


def modhex(cert):
    out = subprocess.run(["openssl", "x509", "-in", cert, "-modulus",
                          "-noout"], check=True, capture_output=True,
                         text=True).stdout
    return out.strip().split("=", 1)[1].strip()


if not os.path.isfile(KEY):
    print(f"missing {KEY} — run scripts/build.sh first")
    raise SystemExit(1)

EXT_CA_TRUE = os.path.join(WORK, "ca_true.cnf")
open(EXT_CA_TRUE, "w").write("basicConstraints=critical,CA:TRUE\n")
# NOTE (fixture bug, found by the first castore run): `-addext`
# on `openssl req` puts the SAN into the CSR only, and
# `openssl x509 -req` does NOT copy requested extensions into
# the issued cert without `-copy_extensions copy`. The first
# run's leaves therefore had NO SANs at all, so the
# `castore update update.test` fetch failed hostname matching
# (CN is store.test) — a fixture bug, not a kernel bug. Leaves
# below are signed with an explicit -extfile so the SANs are
# really in the issued certificate.
EXT_SAN_DUAL = os.path.join(WORK, "san_dual.cnf")
open(EXT_SAN_DUAL, "w").write(
    "subjectAltName=DNS:store.test,DNS:update.test\n")
EXT_SAN_STORE = os.path.join(WORK, "san_store.cnf")
open(EXT_SAN_STORE, "w").write("subjectAltName=DNS:store.test\n")

# 4096-bit root.
run(["openssl", "req", "-x509", "-newkey", "rsa:4096",
     "-keyout", f"{WORK}/root-key.pem", "-out", f"{WORK}/root-cert.pem",
     "-days", "2", "-nodes", "-subj", "/CN=Test Root 4096",
     "-addext", "basicConstraints=critical,CA:TRUE"])
# 2048-bit store intermediate, signed by the root.
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/int-key.pem", "-out", f"{WORK}/int.csr",
     "-nodes", "-subj", "/CN=Test Store CA"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/int.csr",
     "-CA", f"{WORK}/root-cert.pem", "-CAkey", f"{WORK}/root-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/int-cert.pem", "-days", "2",
     "-extfile", EXT_CA_TRUE])
# Leaf for store.test + update.test, signed by the intermediate.
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/leaf-key.pem", "-out", f"{WORK}/leaf.csr",
     "-nodes", "-subj", "/CN=store.test",
     "-addext", "subjectAltName=DNS:store.test,DNS:update.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/leaf.csr",
     "-CA", f"{WORK}/int-cert.pem", "-CAkey", f"{WORK}/int-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/leaf-cert.pem", "-days", "2",
     "-extfile", EXT_SAN_DUAL])
with open(f"{WORK}/chain-store.pem", "w") as f:
    f.write(open(f"{WORK}/leaf-cert.pem").read())
    f.write(open(f"{WORK}/int-cert.pem").read())
    f.write(open(f"{WORK}/root-cert.pem").read())
# Badsig variant.
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/intB-key.pem", "-out", f"{WORK}/intB.csr",
     "-nodes", "-subj", "/CN=Test Store CA"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/intB.csr",
     "-CA", f"{WORK}/root-cert.pem", "-CAkey", f"{WORK}/root-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/intB-cert.pem", "-days", "2",
     "-extfile", EXT_CA_TRUE])
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/badsig-leaf-key.pem",
     "-out", f"{WORK}/badsig-leaf.csr",
     "-nodes", "-subj", "/CN=store.test",
     "-addext", "subjectAltName=DNS:store.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/badsig-leaf.csr",
     "-CA", f"{WORK}/intB-cert.pem", "-CAkey", f"{WORK}/intB-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/badsig-leaf-cert.pem",
     "-days", "2", "-extfile", EXT_SAN_STORE])
with open(f"{WORK}/chain-badsig.pem", "w") as f:
    f.write(open(f"{WORK}/badsig-leaf-cert.pem").read())
    f.write(open(f"{WORK}/int-cert.pem").read())
    f.write(open(f"{WORK}/root-cert.pem").read())
# Oversize-path: store-root (2048) -> int4096 (4096) -> leaf.
run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/storeroot-key.pem",
     "-out", f"{WORK}/storeroot-cert.pem",
     "-days", "2", "-nodes", "-subj", "/CN=Test Store Root",
     "-addext", "basicConstraints=critical,CA:TRUE"])
run(["openssl", "req", "-newkey", "rsa:4096",
     "-keyout", f"{WORK}/int4096-key.pem", "-out", f"{WORK}/int4096.csr",
     "-nodes", "-subj", "/CN=Test Big Intermediate"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/int4096.csr",
     "-CA", f"{WORK}/storeroot-cert.pem",
     "-CAkey", f"{WORK}/storeroot-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/int4096-cert.pem", "-days", "2",
     "-extfile", EXT_CA_TRUE])
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/ov-leaf-key.pem", "-out", f"{WORK}/ov-leaf.csr",
     "-nodes", "-subj", "/CN=store.test",
     "-addext", "subjectAltName=DNS:store.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/ov-leaf.csr",
     "-CA", f"{WORK}/int4096-cert.pem",
     "-CAkey", f"{WORK}/int4096-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/ov-leaf-cert.pem", "-days", "2",
     "-extfile", EXT_SAN_STORE])
with open(f"{WORK}/chain-oversize.pem", "w") as f:
    f.write(open(f"{WORK}/ov-leaf-cert.pem").read())
    f.write(open(f"{WORK}/int4096-cert.pem").read())
    f.write(open(f"{WORK}/storeroot-cert.pem").read())
# TOFU self-signed pair for tofu.test.
for tag in ("A", "B"):
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", f"{WORK}/tofu{tag}-key.pem",
         "-out", f"{WORK}/tofu{tag}-cert.pem",
         "-days", "2", "-nodes", "-subj", "/CN=tofu.test",
         "-addext", "subjectAltName=DNS:tofu.test"])
# Store files.
with open(f"{WORK}/castore-store.txt", "w") as f:
    f.write(modhex(f"{WORK}/int-cert.pem") + "\n")
with open(f"{WORK}/castore-oversize.txt", "w") as f:
    f.write(modhex(f"{WORK}/storeroot-cert.pem") + "\n")
run(["openssl", "genrsa", "-out", f"{WORK}/wrong-key.pem", "2048"])
wrong_mod = subprocess.run(["openssl", "rsa", "-in",
                            f"{WORK}/wrong-key.pem", "-modulus", "-noout"],
                           check=True, capture_output=True,
                           text=True).stdout
with open(f"{WORK}/wrongstore.txt", "w") as f:
    f.write(wrong_mod.strip().split("=", 1)[1].strip() + "\n")
with open(f"{WORK}/tlsanchors.txt", "w") as f:
    f.write(modhex(f"{WORK}/int-cert.pem") + "\n")
# Signed bundle (store-int root + a comment line, proving
# comments are skipped) + tampered twin (original signature).
with open(f"{WORK}/castore-bundle.txt", "w") as f:
    f.write("# test bundle: one root\n")
    f.write(modhex(f"{WORK}/int-cert.pem") + "\n")
run(["python3", os.path.join(ROOT, "tools", "mksig.py"),
     "--key", KEY, f"{WORK}/castore-bundle.txt"])
with open(f"{WORK}/castore-bundle.txt") as f:
    bundle = f.read()
bad = list(bundle)
for i, ch in enumerate(bad):
    if ch in "0123456789abcdef":
        bad[i] = "0" if ch != "0" else "1"
        break
with open(f"{WORK}/tampered-bundle.txt", "w") as f:
    f.write("".join(bad))
# TOFU-A leaf fingerprint (sha256 of DER), for the test's
# cat assertion.
der = subprocess.run(["openssl", "x509", "-in",
                      f"{WORK}/tofuA-cert.pem", "-outform", "DER"],
                     check=True, capture_output=True).stdout
with open(f"{WORK}/tofuA.sha256", "w") as f:
    f.write(hashlib.sha256(der).hexdigest() + "\n")
# Big store: 19 dummy 512-hex lines + the real store-int
# modulus LAST (20 lines, 10260 bytes — past the old 8192
# whole-file read, so only the windowed scan finds it).
with open(f"{WORK}/castore-big.txt", "w") as f:
    for i in range(19):
        f.write(("%064x" % i) * 8 + "\n")
    f.write(open(f"{WORK}/castore-store.txt").read())
# Disks.
with open(f"{WORK}/readme.txt", "w") as f:
    f.write("nxtsOS castore test disk\n")
with open(f"{WORK}/newroot.txt", "w") as f:
    f.write(open(f"{WORK}/wrongstore.txt").read())
for disk, adds in (
        ("disk-store.img", ["castore.txt:castore-store.txt",
                            "newroot.txt:newroot.txt"]),
        ("disk-nostore.img", []),
        ("disk-wrong.img", ["castore.txt:wrongstore.txt"]),
        ("disk-oversize.img", ["castore.txt:castore-oversize.txt"]),
        ("disk-anchor.img", ["tlsanchors.txt:tlsanchors.txt"]),
        ("disk-big.img", ["castore.txt:castore-big.txt"]),
        ("disk-tofu.img", [])):
    args = ["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
            os.path.join(WORK, disk),
            "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"]
    for a in adds:
        name, src = a.split(":")
        args += ["--add", f"{name}:{os.path.join(WORK, src)}"]
    run(args)
print("Castore test fixtures ready in", WORK)
