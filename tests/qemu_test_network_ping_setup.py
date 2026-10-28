#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_network_ping.py.
Usage: python3 tests/qemu_test_network_ping_setup.py <workdir>
Creates an (almost) empty disk.img for the guest. No network state
is seeded beyond what DHCP provides: the desktop Ping steps are
what probe the hosts.
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

with open(os.path.join(WORK, "readme.txt"), "w") as f:
    f.write("nxtsOS network ping test disk\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"])
print("Network ping test fixtures ready in", WORK)
