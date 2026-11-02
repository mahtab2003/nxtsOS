#!/usr/bin/env python3
"""Setup for qemu_test_parity_pipe.py (parity run step 9).

Creates, in OUTDIR:
  pipe.img  — in.txt (fruit lines), big.txt (300000 x bytes, for
              the capture-cap test), root-owned 644.
  users2.img — users.txt (admin uid 0 / pwadmin, alice uid 1000 /
              pwalice) + rootfile.txt ("original\\n", root 644)
              for the capture-failed test.

Recreate fresh before each run: earlier runs mutate the images
(redirects create files, alice creates newfile.txt).
"""
import os, subprocess, sys

ROOT = os.path.expanduser("~/workspace/nxtsOS")
MK = os.path.join(ROOT, "tools", "mkdisk.py")

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    work = os.path.join(outdir, "gen")
    os.makedirs(work, exist_ok=True)
    in_txt = os.path.join(work, "in.txt")
    with open(in_txt, "w") as f:
        f.write("banana\napple\navocado\nberry\napple\n")
    big_txt = os.path.join(work, "big.txt")
    with open(big_txt, "w") as f:
        f.write("x" * 300000)
    users_txt = os.path.join(work, "users.txt")
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "mkuser.py"),
                    users_txt,
                    "--user", "admin:0:pwadmin:aaad0000",
                    "--user", "alice:1000:pwalice:aaaa1111"], check=True)
    rootfile = os.path.join(work, "rootfile.txt")
    with open(rootfile, "w") as f:
        f.write("original\n")
    subprocess.run([sys.executable, MK, os.path.join(outdir, "pipe.img"),
                    "--add", f"in.txt:{in_txt}:644:0",
                    "--add", f"big.txt:{big_txt}:644:0"], check=True)
    subprocess.run([sys.executable, MK, os.path.join(outdir, "users2.img"),
                    "--add", f"users.txt:{users_txt}:600:0",
                    "--add", f"rootfile.txt:{rootfile}:644:0"], check=True)
    print(f"parity_pipe test fixtures ready in {outdir}")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/ppwork")
