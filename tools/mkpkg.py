#!/usr/bin/env python3
"""Create a nxtsOS package file (.nxpkg), see docs/PACKAGES.md.
Usage: mkpkg.py OUTPUT --name NAME --version VER [--depends DEP,DEP]
       --file FILENAME:PATH [--file ...] [--sign-key PRIVATE_KEY.PEM]
DEP is NAME, NAME>=VERSION, or NAME==VERSION.
The manifest lists each file's size and SHA-256 (hashlib), which the
kernel installer verifies before writing anything. This tool validates
names/versions/filenames the same way the kernel does, so a package it
creates should install — a package crafted by hand that breaks those
rules must be rejected by the kernel (see the security tests).
With --sign-key, the package is written as NXPKG002: the same layout
plus a trailing signature block (magic "NXSG", u16 LE length, the
256-byte RSA PKCS#1 v1.5 signature over SHA-256 of the manifest
bytes, made with `openssl dgst -sha256 -sign`). The v1.0 kernel
installer REQUIRES a valid signature, so unsigned (NXPKG001)
packages are refused. Without --sign-key the legacy NXPKG001
format is written (rejected by the v1.0 installer, kept only so
the security tests can craft an unsigned package on purpose).
"""
import argparse, hashlib, os, re, sys

def fail(msg):
    sys.exit(f"mkpkg: {msg}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("output")
    p.add_argument("--name", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--depends", default="")
    p.add_argument("--file", action="append", required=True, metavar="FILENAME:PATH")
    p.add_argument("--sign-key", default=None, metavar="PRIVATE_KEY.PEM",
                   help="sign the manifest with this RSA private key (NXPKG002)")
    a = p.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", a.name):
        fail("bad package name")
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)*", a.version) or len(a.version) > 15:
        fail("bad version (digits and dots only, e.g. 1.0)")
    deps = []
    if a.depends:
        for d in a.depends.split(","):
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}((>=|==)[0-9]+(\.[0-9]+)*)?", d):
                fail(f"bad dependency {d!r}")
            deps.append(d)
    if a.name in [d.split(">")[0].split("=")[0] for d in deps]:
        fail("package depends on itself")
    files = []
    seen = set()
    for spec in a.file:
        if ":" not in spec:
            fail(f"bad --file {spec!r}, expected FILENAME:PATH")
        fname, path = spec.split(":", 1)
        if not fname or len(fname) > 31 or "/" in fname or fname in (".", ".."):
            fail(f"bad filename {fname!r}")
        if fname in ("packages.txt", "users.txt", "audit.log", "fails.txt") or fname.endswith(".nxpkg"):
            fail(f"reserved filename {fname!r}")
        if fname in seen:
            fail(f"duplicate file {fname!r}")
        seen.add(fname)
        if not os.path.isfile(path):
            fail(f"no such file {path!r}")
        data = open(path, "rb").read()
        if not (1 <= len(data) <= 65536):
            fail(f"file {fname!r} size {len(data)} out of range 1..65536")
        files.append((fname, data))
    if not (1 <= len(files) <= 8):
        fail("package must contain 1..8 files")
    manifest = f"name:{a.name}\nversion:{a.version}\ndepends:{','.join(deps)}\n"
    for fname, data in files:
        manifest += f"file:{fname}:{len(data)}:{hashlib.sha256(data).hexdigest()}\n"
    mbytes = manifest.encode()
    if len(mbytes) > 2048:
        fail("manifest too large")
    total = 12 + len(mbytes) + sum(len(d) for _, d in files)
    if total > 131072:
        fail(f"package too large ({total} > 131072)")
    sig = None
    if a.sign_key:
        import subprocess, tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(mbytes); man_path = tf.name
        r = subprocess.run(["openssl", "dgst", "-sha256", "-sign", a.sign_key, man_path],
                           capture_output=True)
        os.unlink(man_path)
        if r.returncode != 0:
            fail(f"openssl sign failed: {r.stderr.decode(errors='replace').strip()}")
        sig = r.stdout
        if len(sig) != 256:
            fail(f"expected a 256-byte RSA-2048 signature, got {len(sig)} bytes")
        total += 4 + 2 + 256
        if total > 132096:
            fail(f"signed package too large ({total} > 132096)")
    with open(a.output, "wb") as f:
        f.write(b"NXPKG002" if sig is not None else b"NXPKG001")
        f.write(len(mbytes).to_bytes(4, "little"))
        f.write(mbytes)
        for _, data in files:
            f.write(data)
        if sig is not None:
            f.write(b"NXSG")
            f.write(len(sig).to_bytes(2, "little"))
            f.write(sig)
    print(f"Wrote {a.output}: package {a.name} {a.version}, {len(files)} file(s), {total} bytes"
          + (", signed" if sig is not None else ", UNSIGNED (legacy)"))

if __name__ == "__main__":
    main()
