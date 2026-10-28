#!/usr/bin/env python3
"""The desktop Settings Unlock path must audit the unlock it
performs. The audit-log chunk proved by read-back that the SHELL
`unlock` audits a real unlock and audits nothing for a refused
unknown name, but the desktop path was only proven by code path:
both call shell_unlock_user, yet no test had ever read audit.log
back after a desktop unlock. This test closes that gap. Two
boots on one persistent disk (the settings-unlock fixtures: ONLY
users.txt, root/pwroot, alice/pwalice, no audit.log pre-seeded,
so every entry read back is one the kernel itself wrote).
Boot 1: fail alice's login 3 times with a wrong password — the
kernel records the lock and halts ("Too many failed attempts.
System halted." is expected, not a failure), so the unlock in
boot 2 clears a genuinely locked account, not an already-open
one. Boot 2 as root: desktopsettingsunlocktest — the kernel
autotest mode 28 script: Settings icon, Unlock press with an
empty field ("settings: unlock needs user"), field click, type
"alice", Unlock press ("settings: unlocked alice"), Terminal
icon (desktop exits). Then `cat audit.log` — the slice after
the cat command must contain "login-ok root" (the positive
control that cat really printed the log) and "unlock alice"
(the desktop unlock was audited), and must contain exactly ONE
"unlock " occurrence: the empty-field refusal in the same
script must have audited nothing, so a second unlock entry
would prove a false audit. The slice scope matters: the echoed
mode-28 markers sit in the serial log from before the cat, so
the count check runs only on the cat output, not the whole
log. Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_desktop_unlock_audit.py <iso> <workdir>
<workdir> is created by tests/qemu_test_desktop_unlock_audit_setup.py.
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

def fail_login(user, pw):
    # Deliberate failure: exactly one recorded failure, no retry —
    # a retry helper must never be used here, since 3 failures lock.
    if not wait_from("login: ", 60, f"login prompt {user}"): return False
    send_text(user)
    if not wait_from("Password: ", 30, f"password prompt {user}"): return False
    send_text(pw)
    return wait_from("Login incorrect", 30, f"failed login {user}")

def step(name, cond):
    global ok
    print(f"STEP {'PASS' if cond else 'FAIL'} {name}")
    ok = ok and cond

# ---- Boot 1: lock alice with 3 real failed logins. ----
qemu, s = boot(os.path.join(WORK, "serial1.log"))
try:
    step("fail login 1", fail_login("alice", "wrongpw"))
    step("fail login 2", fail_login("alice", "wrongpw"))
    step("fail login 3", fail_login("alice", "wrongpw"))
    step("system halts after 3 failures",
         wait_from("Too many failed attempts. System halted.", 30, "halt marker"))
finally:
    end_boot(qemu, s)
log1 = open(os.path.join(WORK, "serial1.log"), errors="replace").read()

# ---- Boot 2: root desktop-unlocks alice, then reads audit.log back. ----
qemu, s = boot(os.path.join(WORK, "serial2.log"))
cat_slice = ""
try:
    step("login root", login("root", "pwroot"))
    send_text("desktopsettingsunlocktest")
    step("root desktop test returned",
         wait_from("desktopsettingsunlocktest returned", 120, "root desktop test returned"))
    # The desktop exit prints a fresh shell prompt BEFORE the next
    # command is typed: consume it first, or a later wait for
    # "root@nxts> " matches the pre-command prompt (the repo-root
    # test's first-run failure class).
    step("shell prompt after desktop",
         wait_from("root@nxts> ", 30, "shell prompt after desktop"))
    before = len(log_text())
    send_text("cat audit.log")
    step("shell prompt after cat",
         wait_from("root@nxts> ", 30, "shell prompt after cat"))
    cat_slice = log_text()[before:]
finally:
    end_boot(qemu, s)
log2 = open(os.path.join(WORK, "serial2.log"), errors="replace").read()

def check(cond, label):
    global ok
    print(f"{'PASS' if cond else 'FAIL'} {label}"); ok = ok and cond
check(log1.count("Login incorrect") >= 3, "boot 1: three failed logins recorded")
check("Too many failed attempts. System halted." in log1, "boot 1: halt after 3 failures")
check("Desktop: Settings opened" in log2, "boot 2: settings opened")
check("settings: unlock needs user" in log2, "boot 2: empty-field refusal in mode 28")
check("settings: unlocked alice" in log2, "boot 2: desktop unlock succeeds")
check("login-ok root" in cat_slice, "cat printed the log (login-ok root present)")
check("unlock alice" in cat_slice, "desktop unlock audited (unlock alice present)")
check(cat_slice.count("unlock ") == 1, "exactly one unlock entry: empty refusal audited nothing")
check("unlock ghost" not in cat_slice, "no false audit entry for any refused name")
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in log1 and bad not in log2, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
