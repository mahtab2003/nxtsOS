#!/usr/bin/env python3
"""`cat` must display a file of any size, not refuse it over
1023 bytes. The old cat read the whole file into a 1024-byte
stack buffer via fs_read_as, which refuses a file larger than
the buffer — so `cat audit.log` on a near-full log printed
"cat: cannot read audit.log" even as root (a display limit
recorded in AUTONOMOUS.md by the audit-cap chunk, not a
logging failure). The fix walks the file in 1023-byte windows
with fs_read_range_as, keeping the same 1024-byte stack buffer
(the kernel stack is 16 KiB) and the same permission check on
every window.
Single boot, root then alice (via logout):
- root `cat big.txt` (3120 bytes, four windows): the slice
  must contain the first line, a middle line from the second
  window, and the last line, in that order, and no
  "cannot read" / "read error".
- root `cat small.txt`: the single line, unchanged behaviour.
- root `cat nosuch.txt`: still "cat: cannot read nosuch.txt".
- root `cat audit.log` (4000-byte seed): SEED-HEAD, SEED-TAIL,
  and the boot's appended "login-ok root" entry, in order —
  the motivating case, now displayed in full.
- alice `cat audit.log`: still refused (root-only file), so
  the per-window permission check is intact, not bypassed
  by the new range API.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_cat_large.py <iso> <workdir>
<workdir> is created by tests/qemu_test_cat_large_setup.py.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
MON = os.path.join(WORK, "mon.sock")

def make_log_reader(path):
    def log_text():
        try: return open(path, errors="replace").read()
        except FileNotFoundError: return ""
    return log_text
POS = [0]
log_text = None

def wait_from(needle, timeout, label):
    for _ in range(int(timeout * 10)):
        t = log_text()
        i = t.find(needle, POS[0])
        if i >= 0:
            POS[0] = i + len(needle)
            return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

def wait_either(needles, timeout, label):
    for _ in range(int(timeout * 10)):
        t = log_text()
        best = None
        for n in needles:
            i = t.find(n, POS[0])
            if i >= 0 and (best is None or i < best[1]):
                best = (n, i)
        if best:
            POS[0] = best[1] + len(best[0])
            return best[0]
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return None

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus", ":": "shift-semicolon"}
ok = True
SOCK = [None]

def send_text(txt):
    s = SOCK[0]
    for _attempt in range(2):
        before = len(log_text())
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(1)
        if "Unknown command" not in log_text()[before:]:
            break

def boot(serial, disk):
    global log_text
    log_text = make_log_reader(serial)
    POS[0] = 0
    try: os.unlink(serial)
    except FileNotFoundError: pass
    try: os.unlink(MON)
    except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:27", "-serial", f"file:{serial}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={disk},format=raw,if=ide,index=0",
    ])
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    SOCK[0] = s
    return qemu, s

def end_boot(qemu, s):
    s.close()
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

def login(user, pw):
    for _attempt in range(3):
        if not wait_from("login: ", 60, f"login prompt {user}"): return False
        send_text(user)
        if not wait_from("Password: ", 30, f"password prompt {user}"): return False
        send_text(pw)
        got = wait_either([f"Welcome, {user}.", "Login incorrect",
                           "Account locked. Contact root to unlock."],
                          30, f"login result {user}")
        if got == f"Welcome, {user}.":
            return wait_from(f"{user}@nxts> ", 30, f"shell prompt {user}")
    return False

def step(name, cond):
    global ok
    print(f"STEP {'PASS' if cond else 'FAIL'} {name}")
    ok = ok and cond

def cat_slice(cmd, prompt):
    before = len(log_text())
    send_text(cmd)
    step(f"shell prompt after {cmd}", wait_from(prompt, 30, f"prompt after {cmd}"))
    return log_text()[before:]

def ordered(slice_text, needles):
    idx = [-1] * len(needles)
    pos = 0
    for i, n in enumerate(needles):
        j = slice_text.find(n, pos)
        if j < 0: return False
        idx[i] = j; pos = j + len(n)
    return True

def check(cond, label):
    global ok
    print(f"{'PASS' if cond else 'FAIL'} {label}"); ok = ok and cond

serial = os.path.join(WORK, "serial.log")
qemu, s = boot(serial, os.path.join(WORK, "disk.img"))
try:
    step("login root", login("root", "pwroot"))
    big_slice = cat_slice("cat big.txt", "root@nxts> ")
    check(ordered(big_slice, ["BIG-0000", "BIG-0060", "BIG-0119"]),
          "big.txt: first, middle (2nd window) and last lines in order")
    check("cannot read" not in big_slice and "read error" not in big_slice,
          "big.txt: no refusal or read error")
    small_slice = cat_slice("cat small.txt", "root@nxts> ")
    check("SMALL-FILE-OK" in small_slice, "small.txt: single line printed")
    nosuch_slice = cat_slice("cat nosuch.txt", "root@nxts> ")
    check("cat: cannot read nosuch.txt" in nosuch_slice,
          "nosuch.txt: still refused with the old message")
    audit_slice = cat_slice("cat audit.log", "root@nxts> ")
    check(ordered(audit_slice, ["SEED-HEAD", "SEED-TAIL", "login-ok root"]),
          "audit.log: seed head, seed tail, appended login-ok entry in order")
    check("cannot read" not in audit_slice and "read error" not in audit_slice,
          "audit.log: no refusal or read error")
    send_text("logout")
    step("logout waited on Logged out.", wait_from("Logged out.", 30, "logout"))
    step("login alice", login("alice", "pwalice"))
    alice_slice = cat_slice("cat audit.log", "alice@nxts> ")
    check("cat: cannot read audit.log" in alice_slice,
          "alice cat audit.log: still refused (per-window permission check intact)")
finally:
    end_boot(qemu, s)
full_log = open(serial, errors="replace").read()
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in full_log, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
