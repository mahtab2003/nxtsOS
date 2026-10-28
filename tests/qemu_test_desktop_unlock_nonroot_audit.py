#!/usr/bin/env python3
"""A non-root desktop Settings Unlock refusal must audit nothing.
The desktop-unlock-audit chunk proved by read-back that a root
desktop unlock audits "unlock alice" and that the empty-field
refusal in the same script audits nothing, but the non-root
refusal's absence from audit.log rested on the code path only:
the Settings handler returns "settings: unlock needs root"
before calling shell_unlock_user, and a non-root session cannot
read audit.log at all, so no test had ever read the log back
after a non-root desktop unlock refusal. This test closes that
gap by crossing sessions: one boot, first as alice (non-root)
running desktopsettingsunlocktest — the kernel autotest mode 28
script: Settings icon, Unlock press with an empty field
("settings: unlock needs user"), field click, type "alice",
Unlock press ("settings: unlock needs root"), Terminal icon
(desktop exits) — then logout, login as root, and `cat
audit.log`. The slice after the cat command must contain
"login-ok alice" and "login-ok root" (the positive controls
that cat really printed the log) and must contain ZERO
"unlock " occurrences: neither refusal in the mode-28 script
may have written an entry, and no real unlock happened in
this boot at all. The slice scope matters: the echoed mode-28
markers sit in the serial log from before the cat, so the
count check runs only on the cat output, not the whole log.
Fixtures are the settings-unlock fixtures (ONLY users.txt,
root/pwroot, alice/pwalice, no audit.log pre-seeded), so
every entry read back is one the kernel itself wrote.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_desktop_unlock_nonroot_audit.py <iso> <workdir>
<workdir> is created by tests/qemu_test_desktop_unlock_nonroot_audit_setup.py.
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
        "-display", "vnc=:28", "-serial", f"file:{serial}",
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
    step("login alice", login("alice", "pwalice"))
    send_text("desktopsettingsunlocktest")
    step("non-root desktop test returned",
         wait_from("desktopsettingsunlocktest returned", 120, "non-root desktop test returned"))
    # The desktop exit prints a fresh shell prompt BEFORE the next
    # command is typed: consume it first, or a later wait for
    # "alice@nxts> " matches the pre-command prompt (the repo-root
    # test's first-run failure class).
    step("shell prompt after desktop",
         wait_from("alice@nxts> ", 30, "shell prompt after desktop"))
    send_text("logout")
    # Wait for "Logged out.", never for a shell prompt (the chmod
    # test's logout trap).
    step("logout alice",
         wait_from("Logged out.", 30, "logout marker"))
    step("login root", login("root", "pwroot"))
    before = len(log_text())
    send_text("cat audit.log")
    step("shell prompt after cat",
         wait_from("root@nxts> ", 30, "shell prompt after cat"))
    cat_slice = log_text()[before:]
finally:
    end_boot(qemu, s)
log = open(os.path.join(WORK, "serial.log"), errors="replace").read()

def check(cond, label):
    global ok
    print(f"{'PASS' if cond else 'FAIL'} {label}"); ok = ok and cond
check("Desktop: Settings opened" in log, "settings opened (non-root)")
check("settings: unlock needs user" in log, "empty-field refusal in mode 28")
check("settings: unlock needs root" in log, "non-root refusal in mode 28")
check("settings: unlocked alice" not in log, "no desktop unlock happened in this boot")
check("login-ok alice" in cat_slice, "cat printed the log (login-ok alice present)")
check("login-ok root" in cat_slice, "cat printed the log (login-ok root present)")
check(cat_slice.count("unlock ") == 0, "zero unlock entries: neither refusal audited anything")
check("unlock alice" not in cat_slice, "no unlock entry for the refused name")
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in log, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
