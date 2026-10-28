#!/usr/bin/env python3
"""Sign an arbitrary file with an RSA private key, producing a
detached 256-byte PKCS#1 v1.5 SHA-256 signature — the same
signature shape as NXPKG002 package signatures (tools/mkpkg.py
uses `openssl dgst -sha256 -sign` the same way), so the kernel
verifies it with the same trust anchors (compiled-in vendor
key, then pubkeys.txt).

Used for CA-store bundles: `castore update` fetches
/castore.txt and /castore.txt.sig over anchored HTTPS and
installs the bundle only if this signature verifies.

Usage: python3 tools/mksig.py --key PRIVATE_KEY.PEM FILE
  [--out FILE.sig]   (default: FILE + ".sig")
"""
import argparse
import subprocess
import sys


def fail(msg):
    print(f"mksig: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--key", required=True, help="RSA private key (PEM)")
    p.add_argument("file", help="file to sign")
    p.add_argument("--out", default=None, help="signature output path")
    a = p.parse_args()
    out = a.out or (a.file + ".sig")
    r = subprocess.run(["openssl", "dgst", "-sha256", "-sign", a.key,
                        "-out", out, a.file],
                       capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"openssl sign failed: {r.stderr.strip()}")
    import os
    n = os.path.getsize(out)
    if n != 256:
        fail(f"expected a 256-byte RSA-2048 signature, got {n}")
    print(f"signed {a.file} -> {out} (256 bytes)")


if __name__ == "__main__":
    main()
