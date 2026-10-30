#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_core_fw.py.
Usage: python3 tests/qemu_test_core_fw_setup.py <workdir>
Creates:
  blank.img — an empty nxtsFS: setup-mode boots (root shell)
     start here. The test copies it fresh before each
     blank-disk boot, since boots mutate it.
  malformed.img — fw.txt only (no users.txt, so setup-mode
     root): headers "#fw enabled=1" + "#fw default=deny",
     one good rule, and three malformed lines (wrong word
     count, bad port 99999, 8 words). The loader must keep
     exactly the one good rule and the header values.
  admin.img — users.txt with admin uid 0 (password pwadmin)
     + alice uid 1000 (password pwalice): the non-root
     refusal boot logs in as alice, then as admin to prove
     the refusals changed nothing.
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "blank.img")])
with open(os.path.join(WORK, "fw.txt"), "w") as f:
    f.write("#fw enabled=1\n")
    f.write("#fw default=deny\n")
    f.write("in deny tcp any any any 80\n")
    f.write("this is not a rule\n")
    f.write("out allow udp any any any 99999\n")
    f.write("in deny icmp any any any any extra\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "malformed.img"),
     "--add", f"fw.txt:{os.path.join(WORK, 'fw.txt')}:600:0"])
run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "admin:0:pwadmin:aaad0000",
     "--user", "alice:1000:pwalice:aaaa1111"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "admin.img"),
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0"])
print("core_fw test fixtures ready in", WORK)
