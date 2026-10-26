#!/usr/bin/env python3
"""Generate a nxtsOS users.txt file (see docs/SECURITY.md).
Usage: mkuser.py OUTPUT --user NAME:UID:PASSWORD[:SALT] ...
The password hash is salted FNV-1a iterated 10000 times, matching
kernel/users.c exactly (v0.4.1, BREAKING change vs v0.4.0 single-round
hashes — regenerate old users.txt files). It is still NOT a production
KDF (no memory hardness) — see the kernel comment and release notes.
If SALT is omitted, a random 8-hex-char salt is generated, so two
users with the same password do not get the same hash.
"""
import argparse, sys, os

def _fnv_step(h, data):
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h

def fnv(salt, password):
    h = _fnv_step(2166136261, salt.encode() + password.encode())
    for _ in range(10000):
        buf = salt.encode()[:16] + bytes([h & 0xFF, (h >> 8) & 0xFF, (h >> 16) & 0xFF, (h >> 24) & 0xFF])
        h = _fnv_step(2166136261, buf)
    return h

def main():
    p = argparse.ArgumentParser()
    p.add_argument("output")
    p.add_argument("--user", action="append", required=True, metavar="NAME:UID:PASSWORD[:SALT]")
    a = p.parse_args()
    lines = []
    for spec in a.user:
        parts = spec.split(":")
        if len(parts) not in (3, 4):
            sys.exit(f"bad --user {spec!r}, expected NAME:UID:PASSWORD[:SALT]")
        name, uid_s, password = parts[0], parts[1], parts[2]
        salt = parts[3] if len(parts) == 4 else os.urandom(4).hex()
        if not name or len(name) > 31 or ":" in name or len(salt) > 15 or not (1 <= len(password) <= 64):
            sys.exit(f"bad user spec {spec!r}")
        try:
            uid = int(uid_s)
        except ValueError:
            sys.exit(f"bad uid {uid_s!r}")
        if not (0 <= uid <= 100000):
            sys.exit("uid out of range")
        lines.append(f"{name}:{uid}:{salt}:{fnv(salt, password):08x}")
    with open(a.output, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {a.output}: {len(lines)} user(s)")

if __name__ == "__main__":
    main()
