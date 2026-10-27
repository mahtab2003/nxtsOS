#!/usr/bin/env python3
"""Build malicious package files for tests/security_test_pkg.py.
Usage: python3 tests/security_test_pkg_setup.py <workdir>
Requires build/hello.elf, build/greet.elf, build/signing.key (from
scripts/build.sh). Malicious packages that attack the MANIFEST or
the blobs are SIGNED with the vendor key on purpose: a valid
signature must NOT save a package whose hashes, sizes, names, or
dependencies are wrong (defense in depth — signature passes, the
specific check still refuses). The signature attacks get their own
files: unsigned (legacy v1), wrong-key signed, and tampered-after-
signing, all of which must be refused for the signature reason."""
import hashlib, os, struct, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.path.join(ROOT, "build", "signing.key")

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

def mkpkg(out, name, version, depends, files):
    args = ["python3", os.path.join(ROOT, "tools", "mkpkg.py"), out,
            "--name", name, "--version", version,
            "--sign-key", KEY]
    if depends: args += ["--depends", depends]
    for fname, path in files:
        args += ["--file", f"{fname}:{path}"]
    run(args)

def sign_manifest(mb, key):
    man_path = os.path.join(WORK, "tmp_man.txt")
    with open(man_path, "wb") as f: f.write(mb)
    r = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key, man_path],
                       capture_output=True)
    os.unlink(man_path)
    if r.returncode != 0 or len(r.stdout) != 256:
        raise SystemExit("signing failed")
    return r.stdout

def read_pkg(path):
    data = open(path, "rb").read()
    mlen = struct.unpack("<I", data[8:12])[0]
    return data, mlen, data[12:12+mlen].decode()

def write_pkg(path, manifest, blobs, sign_key=None):
    mb = manifest.encode()
    with open(path, "wb") as f:
        f.write(b"NXPKG002" if sign_key else b"NXPKG001")
        f.write(struct.pack("<I", len(mb))); f.write(mb)
        for b in blobs: f.write(b)
        if sign_key:
            sig = sign_manifest(mb, sign_key)
            f.write(b"NXSG"); f.write(struct.pack("<H", len(sig))); f.write(sig)

hello = os.path.join(ROOT, "build", "hello.elf")
hello_data = open(hello, "rb").read()
# Good packages for the security disk.
mkpkg(os.path.join(WORK, "hello.nxpkg"), "hello", "1.0", "", [("hello.elf", hello)])
mkpkg(os.path.join(WORK, "greet.nxpkg"), "greet", "1.0", "hello>=1.0",
      [("greet.elf", os.path.join(ROOT, "build", "greet.elf"))])
# Bad hash: same package, manifest hash replaced with zeros (same length).
data, mlen, man = read_pkg(os.path.join(WORK, "hello.nxpkg"))
h = hashlib.sha256(hello_data).hexdigest()
man_bad = man.replace(h, "0" * 64)
write_pkg(os.path.join(WORK, "badhash.nxpkg"), man_bad, [hello_data], KEY)
# Lying size: file size 6208 -> 6209 (same digit length, same manifest length).
# The blob layout then does not add up to the package size.
man_size = man.replace(f"file:hello.elf:{len(hello_data)}:", f"file:hello.elf:{len(hello_data)+1}:")
assert man_size != man
write_pkg(os.path.join(WORK, "badsize.nxpkg"), man_size, [hello_data], KEY)
# Path traversal and absolute path, crafted by hand (mkpkg refuses these).
for fname, out in [("../evil.elf", "badpath.nxpkg"), ("/etc/passwd", "badabs.nxpkg")]:
    blob = b"hello"
    man_c = f"name:evil\nversion:1.0\ndepends:\nfile:{fname}:{len(blob)}:{hashlib.sha256(blob).hexdigest()}\n"
    write_pkg(os.path.join(WORK, out), man_c, [blob], KEY)
# Self-dependency and a dependency cycle, crafted by hand (mkpkg refuses self-dep).
man_self = f"name:self\nversion:1.0\ndepends:self\nfile:self.elf:{len(hello_data)}:{h}\n"
write_pkg(os.path.join(WORK, "selfdep.nxpkg"), man_self, [hello_data], KEY)
man_a = f"name:cyc_a\nversion:1.0\ndepends:cyc_b\nfile:a.elf:{len(hello_data)}:{h}\n"
man_b = f"name:cyc_b\nversion:1.0\ndepends:cyc_a\nfile:b.elf:{len(hello_data)}:{h}\n"
write_pkg(os.path.join(WORK, "cyc_a.nxpkg"), man_a, [hello_data], KEY)
write_pkg(os.path.join(WORK, "cyc_b.nxpkg"), man_b, [hello_data], KEY)
# Conflicting version dependency: needs hello>=9.9, only 1.0 is available.
mkpkg(os.path.join(WORK, "need99.nxpkg"), "need99", "1.0", "hello>=9.9",
      [("need.elf", hello)])
# Huge package: a single file over the 64 KiB per-file cap, and a total
# package over the 128 KiB buffer cap (the installer must refuse both).
big = b"A" * 70000
man_big = f"name:big\nversion:1.0\ndepends:\nfile:big.elf:{len(big)}:{hashlib.sha256(big).hexdigest()}\n"
write_pkg(os.path.join(WORK, "huge.nxpkg"), man_big, [big], KEY)
with open(os.path.join(WORK, "huge2.nxpkg"), "wb") as f:
    f.write(b"NXPKG001" + b"\x00" * 200000)
# Signature attacks (new in v1.0): an unsigned legacy package, a
# package signed with a key the kernel does not trust, and a
# properly signed package whose manifest was tampered with after
# signing (version 1.0 -> 1.1, same length, so only the signature
# check can catch it).
write_pkg(os.path.join(WORK, "unsigned.nxpkg"), man, [hello_data])
wrong_key = os.path.join(WORK, "wrong.key")
run(["openssl", "genrsa", "-out", wrong_key, "2048"])
write_pkg(os.path.join(WORK, "wrongkey.nxpkg"), man, [hello_data], wrong_key)
data, mlen, man = read_pkg(os.path.join(WORK, "hello.nxpkg"))
tampered = bytearray(data)
idx = data.index(b"version:1.0")
tampered[idx:idx + len(b"version:1.0")] = b"version:1.1"
with open(os.path.join(WORK, "tampered.nxpkg"), "wb") as f:
    f.write(tampered)
print("Malicious packages ready in", WORK)
