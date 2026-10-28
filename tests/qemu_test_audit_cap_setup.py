#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_audit_cap.py.
Usage: python3 tests/qemu_test_audit_cap_setup.py <workdir>
Creates two disks, each holding users.txt (root-owned, mode 0600:
root uid 0 password pwroot, alice uid 1000 password pwalice,
fixed salts) plus a pre-seeded audit.log (root-owned, mode 0600):
- disk_cap.img: audit.log seeded to exactly 4080 bytes. A login-ok
  entry is at least 17 bytes ("login-ok root 0\\n"), so 4080 + 17
  = 4097 > 4096 and the login event CANNOT fit: the cap path must
  refuse it, warn, and leave the seed untouched. This holds for any
  tick width, so the test does not depend on boot timing.
- disk_room.img: audit.log seeded to exactly 4000 bytes. A login-ok
  entry is at most ~22 bytes for any plausible boot tick count, so
  4000 + 22 = 4022 <= 4096 and the login event MUST fit: the
  positive control that the cap disk's refusal is about the cap,
  not about pre-seeded logs being unreadable or unappendable.
Seeds are "SEED-HEAD\\n" + "seed-line\\n" filler + "SEED-TAIL\\n",
so a truncated or overwritten log is visible in the read-back:
the head/tail markers and their order prove the seed survived
intact (cap disk) or was appended to, not replaced (room disk).
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

def seed(total):
    head, tail, fill = b"SEED-HEAD\n", b"SEED-TAIL\n", b"seed-line\n"
    n = (total - len(head) - len(tail)) // len(fill)
    assert len(head) + n * len(fill) + len(tail) == total
    return head + fill * n + tail

run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "root:0:pwroot:cccc3333",
     "--user", "alice:1000:pwalice:dddd4444"])
for name, total in (("cap", 4080), ("room", 4000)):
    with open(os.path.join(WORK, f"audit_{name}.log"), "wb") as f:
        f.write(seed(total))
    run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
         os.path.join(WORK, f"disk_{name}.img"),
         "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
         "--add", f"audit.log:{os.path.join(WORK, f'audit_{name}.log')}:600:0"])
print("Audit-cap test fixtures ready in", WORK)
