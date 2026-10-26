#!/usr/bin/env python3
"""Create a formatted nxtsFS disk image (see docs/FILESYSTEM.md).
Usage: mkdisk.py OUTPUT [--size-mb N] [--add NAME:PATH]...
A disk is only formatted by this explicit host tool -- the kernel never
formats a disk on its own.
"""
import argparse, os, struct, sys

SECTOR = 512
MAGIC = b"NXTSFS01"

def main():
    p = argparse.ArgumentParser()
    p.add_argument("output")
    p.add_argument("--size-mb", type=int, default=16)
    p.add_argument("--add", action="append", default=[], metavar="NAME:PATH")
    a = p.parse_args()
    if a.size_mb < 1 or a.size_mb > 128:
        sys.exit("size must be 1..128 MiB")
    total = (a.size_mb * 1024 * 1024) // SECTOR
    bitmap_sectors = (total + 4095) // 4096
    dir_sector = 1 + bitmap_sectors
    dir_sectors = 4
    data_start = dir_sector + dir_sectors
    max_files = dir_sectors * 8
    if data_start >= total:
        sys.exit("disk too small")
    disk = bytearray(total * SECTOR)
    sb = struct.pack("<8s7I", MAGIC, 1, total, bitmap_sectors,
                     dir_sector, dir_sectors, data_start, max_files)
    disk[0:len(sb)] = sb
    # Bitmap: system sectors marked used.
    for s in range(data_start):
        disk[SECTOR + s // 8] |= (1 << (s % 8))
    entries = []
    nxt = data_start
    for spec in a.add:
        # NAME:PATH[:MODE[:UID]] — MODE is octal (e.g. 600), UID decimal.
        parts = spec.split(":")
        if len(parts) < 2 or len(parts) > 4:
            sys.exit(f"bad --add {spec!r}, expected NAME:PATH[:MODE[:UID]]")
        name, path = parts[0], parts[1]
        mode = int(parts[2], 8) if len(parts) >= 3 else 0o644
        uid = int(parts[3]) if len(parts) == 4 else 0
        if not name or len(name) > 31 or "/" in name:
            sys.exit(f"bad file name {name!r}")
        if any(e[0] == name for e in entries):
            sys.exit(f"duplicate file {name!r}")
        data = open(path, "rb").read()
        need = max(1, (len(data) + SECTOR - 1) // SECTOR)
        if nxt + need > total:
            sys.exit(f"disk full adding {name!r}")
        for s in range(nxt, nxt + need):
            disk[SECTOR + s // 8] |= (1 << (s % 8))
        disk[nxt * SECTOR:(nxt + need) * SECTOR] = data.ljust(need * SECTOR, b"\0")
        entries.append((name, len(data), nxt, need, uid, mode))
        nxt += need
    for i, (name, size, start, count, uid, mode) in enumerate(entries):
        off = dir_sector * SECTOR + i * 64
        disk[off:off + 32] = name.encode()[:31].ljust(32, b"\0")
        disk[off + 32:off + 56] = struct.pack("<6I", size, start, count, uid, mode, 1)
    with open(a.output, "wb") as f:
        f.write(disk)
    print(f"Created {a.output}: {a.size_mb} MiB, {total} sectors, "
          f"{len(entries)} file(s), data starts at sector {data_start}")

if __name__ == "__main__":
    main()
