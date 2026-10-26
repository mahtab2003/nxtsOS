#!/usr/bin/env python3
"""Build the three security-test disks for tests/security_test_phase5.py.
Usage: python3 tests/security_test_phase5_setup.py <workdir>
Requires build/hello.elf, build/evil.elf (from scripts/build.sh)."""
import os, struct, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)
    return r.stdout

def patch_elf(src, dst, fn):
    data = bytearray(open(src, "rb").read())
    fn(data)
    open(dst, "wb").write(data)

def w32(d, off, val): d[off:off+4] = struct.pack("<I", val)
def w16(d, off, val): d[off:off+2] = struct.pack("<H", val)

good = os.path.join(ROOT, "build", "hello.elf")
hdr = open(good, "rb").read()
phoff = struct.unpack_from("<I", hdr, 28)[0]
# Bad variants, each breaking exactly one validation.
patch_elf(good, os.path.join(WORK, "badmagic.elf"), lambda d: d.__setitem__(slice(0, 4), b"XXXX"))
patch_elf(good, os.path.join(WORK, "badtrunc.elf"), lambda d: d.__delitem__(slice(10, None)))
patch_elf(good, os.path.join(WORK, "badphnum.elf"), lambda d: w16(d, 44, 1000))
patch_elf(good, os.path.join(WORK, "badoffset.elf"), lambda d: w32(d, phoff+4, 0xFFFFFF00))
patch_elf(good, os.path.join(WORK, "badkaddr.elf"), lambda d: w32(d, phoff+8, 0x00100000))
patch_elf(good, os.path.join(WORK, "badstack.elf"), lambda d: w32(d, phoff+8, 0x0BFFF000))
patch_elf(good, os.path.join(WORK, "badentry.elf"), lambda d: w32(d, 24, 0x08049000))
def badmemsz(d):
    w32(d, phoff+20, 0x10000000)
patch_elf(good, os.path.join(WORK, "badmemsz.elf"), badmemsz)

run(["python3", os.path.join(ROOT, "tools", "mkuser.py"), os.path.join(WORK, "users.txt"),
     "--user", "root:0:rootpass", "--user", "user:1000:userpass"])
open(os.path.join(WORK, "public.txt"), "w").write("public data\n")

def mkdisk(out, adds):
    args = ["python3", os.path.join(ROOT, "tools", "mkdisk.py"), out]
    for a in adds:
        args += ["--add", a]
    run(args)

# Disk A: good + evil + all bad ELFs, root+user accounts.
adds_a = [f"hello.elf:{good}", f"evil.elf:{ROOT}/build/evil.elf",
          f"users.txt:{WORK}/users.txt", f"public.txt:{WORK}/public.txt"]
for n in ["badmagic", "badtrunc", "badphnum", "badoffset", "badkaddr", "badstack", "badentry", "badmemsz"]:
    adds_a.append(f"{n}.elf:{WORK}/{n}.elf")
mkdisk(os.path.join(WORK, "disk_a.img"), adds_a)
# Disk B: same accounts, no ELFs needed (login only).
mkdisk(os.path.join(WORK, "disk_b.img"),
       [f"users.txt:{WORK}/users.txt", f"public.txt:{WORK}/public.txt"])
# Disk C: malformed users.txt (bad first line, then a valid root line).
with open(os.path.join(WORK, "users_bad.txt"), "w") as f:
    f.write("thislinehasnocolons\n")
    f.write(open(os.path.join(WORK, "users.txt")).read())
mkdisk(os.path.join(WORK, "disk_c.img"),
       [f"users.txt:{WORK}/users_bad.txt", f"public.txt:{WORK}/public.txt"])
print("Security disks ready in", WORK)
