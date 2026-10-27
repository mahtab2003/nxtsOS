#!/usr/bin/env python3
"""Create a nxtsOS package file (.nxpkg), see docs/PACKAGES.md.
Usage: mkpkg.py OUTPUT --name NAME --version VER [--depends DEP,DEP]
       --file FILENAME:PATH [--file ...]
DEP is NAME, NAME>=VERSION, or NAME==VERSION.
The manifest lists each file's size and SHA-256 (hashlib), which the
kernel installer verifies before writing anything. This tool validates
names/versions/filenames the same way the kernel does, so a package it
creates should install — a package crafted by hand that breaks those
rules must be rejected by the kernel (see the security tests).
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
    with open(a.output, "wb") as f:
        f.write(b"NXPKG001")
        f.write(len(mbytes).to_bytes(4, "little"))
        f.write(mbytes)
        for _, data in files:
            f.write(data)
    print(f"Wrote {a.output}: package {a.name} {a.version}, {len(files)} file(s), {total} bytes")

if __name__ == "__main__":
    main()
