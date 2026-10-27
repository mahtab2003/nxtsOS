#!/usr/bin/env python3
"""Build the disk for tests/security_test_desktop10.py.
Usage: python3 tests/qemu_test_desktop10sec_setup.py <workdir>
Disk order matters: the mode-6 script clicks Files rows 0-3 for
evil.txt, empty.txt, big.bmp, good.bmp, so they are added in that
order, then the garbage settings.txt. No users.txt: setup mode.
evil.txt carries control bytes and high bytes (must be sanitised
to '?' on load); big.bmp claims 200x200 but carries no pixel data
(must be refused as oversize before any pixel read); good.bmp is a
valid 64x64 24-bit BMP. settings.txt is garbage: theme=99 and
wallpaper=5 are out of range, accent/idle are non-numeric."""
import os, struct, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def bmp(path, w, h, pixels):
    hdr = b"BM" + struct.pack("<IHHI", 54 + len(pixels), 0, 0, 54)
    hdr += struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(pixels), 0, 0, 0, 0)
    open(path, "wb").write(hdr + pixels)

open(os.path.join(WORK, "evil.txt"), "wb").write(
    b"Hello\x01\x02\xffWorld\nSecond\x7fline\n")
open(os.path.join(WORK, "empty.txt"), "wb").write(b"")
bmp(os.path.join(WORK, "big.bmp"), 200, 200, b"")
bmp(os.path.join(WORK, "good.bmp"), 64, 64, bytes((0x20, 0x60, 0xA0)) * 64 * 64)
open(os.path.join(WORK, "settings.txt"), "w").write(
    "theme=99\nwallpaper=5\naccent=xx\nidle=abc\n")

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"evil.txt:{os.path.join(WORK, 'evil.txt')}",
     "--add", f"empty.txt:{os.path.join(WORK, 'empty.txt')}",
     "--add", f"big.bmp:{os.path.join(WORK, 'big.bmp')}",
     "--add", f"good.bmp:{os.path.join(WORK, 'good.bmp')}",
     "--add", f"settings.txt:{os.path.join(WORK, 'settings.txt')}"])
print("Desktop10 security disk ready in", WORK)
