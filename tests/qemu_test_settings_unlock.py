#!/usr/bin/env python3
"""Settings-window Unlock: a root desktop session must be able to
clear a locked account, and a non-root desktop session must not.
Two boots on one persistent disk (the login loop halts the system
after 3 failed attempts, so the lock and the unlock cannot share a
boot). Boot 1: fail alice's login 3 times with a wrong password —
the kernel records fails.txt alice:3 and halts ("Too many failed
attempts. System halted." is expected, not a failure). Boot 2 as
root: desktopsettingsunlocktest — the kernel autotest mode 28
script: Settings icon, Unlock press with an empty field
("settings: unlock needs user"), field click, type "alice",
Unlock press ("settings: unlocked alice"), Terminal icon
(desktop exits). Then logout, login as alice with the correct
password — success is the behavioural proof the unlock landed,
not just the marker. Then as alice the same mode 28 script must
refuse: empty field ("settings: unlock needs user" again),
type "alice", Unlock press ("settings: unlock needs root").
The QEMU sendkey doubling flake is the only expected cause of a
login retry, and login() refuses a third recorded failure for any
user, since a third locks the account (the lock in boot 1 is
deliberate and uses a separate helper, not login()).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_settings_unlock.py <iso> <workdir>
<workdir> is created by tests/qemu_test_settings_unlock_setup.py.
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
        "-display", "vnc=:26", "-serial", f"file:{serial}",
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

FAILS = {}
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
        FAILS[user] = FAILS.get(user, 0) + 1
        print(f"NOTE: login retry {user} (recorded failures {FAILS[user]})")
        if FAILS[user] >= 2:
            print(f"FAIL: too many login failures for {user}, refusing a third")
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

def logout(user):
    # Logout returns to the login prompt, not to a shell prompt:
    # waiting for f"{user}@nxts> " here would time out even on
    # success (the chmod test's first-run failure class).
    send_text("logout")
    return wait_from("Logged out.", 30, f"logout {user}")

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

# ---- Boot 2: root unlocks, alice proves it, alice is refused. ----
qemu, s = boot(os.path.join(WORK, "serial2.log"))
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
    step("logout root", logout("root"))
    step("login alice after unlock", login("alice", "pwalice"))
    send_text("desktopsettingsunlocktest")
    step("alice desktop test returned",
         wait_from("desktopsettingsunlocktest returned", 120, "alice desktop test returned"))
    step("shell prompt after alice desktop",
         wait_from("alice@nxts> ", 30, "shell prompt after alice desktop"))
finally:
    end_boot(qemu, s)
log2 = open(os.path.join(WORK, "serial2.log"), errors="replace").read()

def check(cond, label):
    global ok
    print(f"{'PASS' if cond else 'FAIL'} {label}"); ok = ok and cond
check(log1.count("Login incorrect") >= 3, "boot 1: three failed logins recorded")
check("Too many failed attempts. System halted." in log1, "boot 1: halt after 3 failures")
check(log2.count("Desktop: Settings opened") >= 2, "boot 2: settings opened in both phases")
check(log2.count("settings: unlock needs user") >= 2, "empty unlock refused in both phases")
check("settings: unlocked alice" in log2, "root unlock succeeds")
check("Welcome, alice." in log2, "alice logs in after unlock (behavioural proof)")
check("settings: unlock needs root" in log2, "non-root unlock refused")
check("Account locked. Contact root to unlock." not in log2, "no locked-account refusal in boot 2")
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in log1 and bad not in log2, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
