#!/usr/bin/env python3
"""Build a nxtsOS package repository directory.

Usage: mkrepo.py --key KEY.PEM --out DIR [--version N]
                 PACKAGE.NXPKG [PACKAGE.NXPKG ...]

Copies the packages into DIR, writes index.txt:
    NXREPO1
    version:<N>
    name|version|file|sha256hex
and index.txt.sig: 512 hex chars = RSA PKCS#1 v1.5 signature
over SHA-256 of the exact index.txt bytes (openssl dgst
-sha256 -sign). The kernel verifies the index signature with
the vendor key or keyring before trusting any entry, and
verifies each package's hash + signature again at install.
Transport is plain HTTP by design (see docs/PACKAGES.md):
signatures, not TLS, carry authenticity.
"""
import argparse, hashlib, os, struct, subprocess, sys

def fail(msg):
    sys.exit(f"mkrepo: {msg}")

def parse_manifest(data):
    if len(data) < 12 or data[:8] != b"NXPKG002":
        fail("package is not a signed NXPKG002")
    mlen = struct.unpack("<I", data[8:12])[0]
    man = data[12:12 + mlen].decode()
    name = version = None
    for line in man.splitlines():
        if line.startswith("name:"): name = line[5:]
        elif line.startswith("version:"): version = line[8:]
    if not name or not version:
        fail("package manifest lacks name/version")
    return name, version

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--version", type=int, default=1)
    ap.add_argument("packages", nargs="+")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    entries = []
    for path in a.packages:
        data = open(path, "rb").read()
        name, version = parse_manifest(data)
        fname = os.path.basename(path)
        with open(os.path.join(a.out, fname), "wb") as f:
            f.write(data)
        entries.append((name, version, fname, hashlib.sha256(data).hexdigest()))
    names = [e[0] for e in entries]
    if len(set(names)) != len(names):
        fail("duplicate package name in repo")
    lines = ["NXREPO1", f"version:{a.version}"]
    for name, version, fname, h in entries:
        lines.append(f"{name}|{version}|{fname}|{h}")
    index = ("\n".join(lines) + "\n").encode()
    with open(os.path.join(a.out, "index.txt"), "wb") as f:
        f.write(index)
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", a.key],
                         input=index, capture_output=True)
    if sig.returncode != 0:
        fail(f"openssl sign failed: {sig.stderr.decode()}")
    if len(sig.stdout) != 256:
        fail(f"unexpected signature length {len(sig.stdout)}")
    with open(os.path.join(a.out, "index.txt.sig"), "w") as f:
        f.write(sig.stdout.hex())
    print(f"Wrote {a.out}: repo, {len(entries)} package(s), index version {a.version}")

if __name__ == "__main__":
    main()
