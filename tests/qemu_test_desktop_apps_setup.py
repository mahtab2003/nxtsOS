#!/usr/bin/env python3
"""Build the disk for tests/qemu_test_desktop_apps.py.
Usage: python3 tests/qemu_test_desktop_apps_setup.py <workdir>
Requires build/calc.nxpkg, build/term.nxpkg (from scripts/build.sh).
Disk order matters: the mode-5 script clicks Files row 0 for
notes.txt and row 1 for pic.bmp, so those two are added first.
No users.txt: the test boots in setup mode (root, no login).
The test installs calc + term in boot 1, so no plain calc.elf or
term.elf is pre-seeded (the installer refuses an already-existing
plain file)."""
import os, struct, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def bmp(path, w, h, fill):
    row = w * 3
    pad = (4 - row % 4) % 4
    pixels = b""
    for y in range(h):
        pixels += bytes(fill) * w + b"\x00" * pad
    size = 54 + len(pixels)
    hdr = b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
    hdr += struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(pixels), 0, 0, 0, 0)
    open(path, "wb").write(hdr + pixels)

open(os.path.join(WORK, "notes.txt"), "w").write(
    "Hello, this is a test note.\nSecond line.\n")
bmp(os.path.join(WORK, "pic.bmp"), 64, 64, (0x20, 0x60, 0xA0))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"notes.txt:{os.path.join(WORK, 'notes.txt')}",
     "--add", f"pic.bmp:{os.path.join(WORK, 'pic.bmp')}",
     "--add", f"calc.nxpkg:{os.path.join(ROOT, 'build', 'calc.nxpkg')}",
     "--add", f"term.nxpkg:{os.path.join(ROOT, 'build', 'term.nxpkg')}"])
print("Desktop apps disk ready in", WORK)
