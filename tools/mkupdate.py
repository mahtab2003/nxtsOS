#!/usr/bin/env python3
"""Bundle signed packages into a nxtsOS system update file (.nxupd).

Usage: mkupdate.py OUTPUT.NXUPD PACKAGE.NXPKG [PACKAGE.NXPKG ...]

Format: magic "NXUPD001", then the packages concatenated unchanged.
Each package must already be a signed NXPKG002 (mkpkg.py
--sign-key); the kernel's sysupdate verifies every package's
signature, hashes, dependencies, and file conflicts BEFORE writing
anything, snapshots the previous versions, and rolls back on any
failure. The bundle itself carries no separate signature — the
per-package signatures are the trust anchors.

Limits (mirroring the kernel): at most 8 packages, bundle at most
512 KiB total.
"""
import os, sys

def fail(msg):
    sys.exit(f"mkupdate: {msg}")

def main():
    if len(sys.argv) < 3:
        fail("usage: mkupdate.py OUTPUT.NXUPD PACKAGE.NXPKG [...]")
    out = sys.argv[1]
    pkgs = sys.argv[2:]
    if len(pkgs) > 8:
        fail(f"at most 8 packages per bundle, got {len(pkgs)}")
    blobs = []
    total = 8
    for path in pkgs:
        if not os.path.isfile(path):
            fail(f"no such file {path!r}")
        data = open(path, "rb").read()
        if len(data) < 12 or data[:8] != b"NXPKG002":
            fail(f"{path!r} is not a signed NXPKG002 package")
        blobs.append(data)
        total += len(data)
    if total > 524288:
        fail(f"bundle too large ({total} > 524288)")
    with open(out, "wb") as f:
        f.write(b"NXUPD001")
        for data in blobs:
            f.write(data)
    print(f"Wrote {out}: update bundle, {len(blobs)} package(s), {total} bytes")

if __name__ == "__main__":
    main()
