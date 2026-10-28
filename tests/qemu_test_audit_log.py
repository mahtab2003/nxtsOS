#!/usr/bin/env python3
"""The audit log must record real unlocks and no false ones, and
stay root-only to read. The unlock-of-unknown-name chunk proved
by code path only that a refused `unlock ghost` audits nothing;
this test proves it by reading audit.log back. Single boot on
the unlock-no-user fixtures disk (users.txt only: root/pwroot,
alice/pwalice): as root, `unlock ghost` (refusal), `unlock
alice` (success), then `cat audit.log` — the slice after the
cat command must contain "login-ok root" (the positive control
that cat really printed the log) and "unlock alice" (the real
unlock was audited), and must NOT contain "unlock ghost" (no
false entry for the refused name). The slice scope matters: the
echoed `unlock ghost` command line itself is in the serial log
from typing, so the absence check runs only on the cat output,
not the whole log. Then logout, login as alice, and `cat
audit.log` must print "cat: cannot read audit.log" — the
root-only read rule for audit.log, which the phase-5 test
proves for secret.txt but never for audit.log itself.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_audit_log.py <iso> <workdir>
<workdir> is created by tests/qemu_test_audit_log_setup.py.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
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

def boot(serial):
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
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
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
        if got != "Login incorrect":
            return False
    return False

def step(name, cond):
    global ok
    print(f"STEP {'PASS' if cond else 'FAIL'} {name}")
    ok = ok and cond

qemu, s = boot(os.path.join(WORK, "serial.log"))
cat_slice = ""
try:
    step("login root", login("root", "pwroot"))
    send_text("unlock ghost")
    step("shell unlock ghost refused",
         wait_from("unlock: no such user ghost", 30, "shell no-such-user marker"))
    step("shell prompt after ghost",
         wait_from("root@nxts> ", 30, "shell prompt after ghost"))
    send_text("unlock alice")
    step("shell unlock alice succeeds",
         wait_from("Unlocked alice", 30, "shell unlock alice marker"))
    step("shell prompt after alice",
         wait_from("root@nxts> ", 30, "shell prompt after alice"))
    before = len(log_text())
    send_text("cat audit.log")
    step("shell prompt after cat",
         wait_from("root@nxts> ", 30, "shell prompt after cat"))
    cat_slice = log_text()[before:]
    # Logout returns to the login prompt, not a shell prompt:
    # wait for "Logged out.", never for a prompt (the chmod
    # test's logout trap).
    send_text("logout")
    step("logout",
         wait_from("Logged out.", 30, "logout marker"))
    step("login alice", login("alice", "pwalice"))
    send_text("cat audit.log")
    step("non-root audit read refused",
         wait_from("cat: cannot read audit.log", 30, "non-root audit refusal"))
finally:
    end_boot(qemu, s)
log = open(os.path.join(WORK, "serial.log"), errors="replace").read()

def check(cond, label):
    global ok
    print(f"{'PASS' if cond else 'FAIL'} {label}"); ok = ok and cond
check("login-ok root" in cat_slice, "cat printed the log (login-ok root present)")
check("unlock alice" in cat_slice, "real unlock audited (unlock alice present)")
check("unlock ghost" not in cat_slice, "no false audit entry for refused ghost unlock")
check("unlock: no such user ghost" in log, "shell no-such-user refused")
check("Unlocked alice" in log, "shell unlock of a real account still succeeds")
check("Unlocked ghost" not in log, "no false shell success for ghost")
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in log, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
