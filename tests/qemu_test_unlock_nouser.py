#!/usr/bin/env python3
"""Unlock of a user that does not exist must refuse, in both
paths that share the primitive. Before this fix, shell `unlock
ghost` printed "Unlocked ghost" and the desktop Settings Unlock
row printed "settings: unlocked ghost" for a name that is not
an account, and both wrote a false "unlock" audit entry for it
(fails_clear silently does nothing for an unknown name).
Single boot as root on the settings-unlock fixtures disk:
shell `unlock ghost` must report "unlock: no such user ghost";
shell `unlock alice` must still succeed ("Unlocked alice",
the positive control that the existence check refuses only
unknown names); then desktopunlocknousertest (autotest mode
29: Settings icon, field click, type "ghost", Unlock press
twice, Terminal icon) must report "settings: no such user
ghost" twice — the second press proves the field survived
the refusal — and no "unlocked ghost" line may appear in
either path. No "Unlocked ghost" / "settings: unlocked ghost"
line may appear anywhere.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_unlock_nouser.py <iso> <workdir>
<workdir> is created by tests/qemu_test_unlock_nouser_setup.py.
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
    send_text("desktopunlocknousertest")
    step("desktop test returned",
         wait_from("desktopunlocknousertest returned", 120, "desktop test returned"))
finally:
    end_boot(qemu, s)
log = open(os.path.join(WORK, "serial.log"), errors="replace").read()

def check(cond, label):
    global ok
    print(f"{'PASS' if cond else 'FAIL'} {label}"); ok = ok and cond
check("Desktop: Settings opened" in log, "settings opened")
check(log.count("settings: no such user ghost") >= 2, "desktop no-such-user refused twice (field kept)")
check("unlock: no such user ghost" in log, "shell no-such-user refused")
check("Unlocked alice" in log, "shell unlock of a real account still succeeds")
check("Unlocked ghost" not in log, "no false shell success for ghost")
check("settings: unlocked ghost" not in log, "no false desktop success for ghost")
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in log, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
