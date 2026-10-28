#!/usr/bin/env python3
"""Desktop idle-lock trigger: the first QEMU proof that the idle
timeout actually locks the desktop (until now only "no early lock
after 30 s" and the `idle` command setting were tested; the
trigger itself was documented as NOT QEMU-tested because waiting
out the 120-minute default is not feasible — but `idle 1` makes
the wait 60 seconds, which is feasible).
Single boot as alice: login, `idle 1`, `desktop`. Phase A: for
30 s after desktop entry the lock screen must NOT appear (the
no-early-lock property, now for the desktop path too). Phase B:
within a further 90 s the lock screen MUST appear ("Desktop: lock
screen shown", about 60 s after desktop entry). Then type the
session password and expect "Desktop: unlocked" — the behavioural
proof that the idle lock is the real session lock, not a stuck
screen. A doubled sendkey on the password is retried once (the
QEMU sendkey doubling flake class); a third attempt would halt
the system, so no third attempt is ever made.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_idle_lock.py <iso> <workdir>
<workdir> is created by tests/qemu_test_idle_lock_setup.py.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
MON = os.path.join(WORK, "mon.sock")
SERIAL = os.path.join(WORK, "serial.log")

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
POS = [0]

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

def boot():
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:27", "-serial", f"file:{SERIAL}",
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
    fails = 0
    for _attempt in range(3):
        if not wait_from("login: ", 60, f"login prompt {user}"): return False
        send_text(user)
        if not wait_from("Password: ", 30, f"password prompt {user}"): return False
        send_text(pw)
        got = wait_either([f"Welcome, {user}.", "Login incorrect"], 30, f"login result {user}")
        if got == f"Welcome, {user}.":
            return wait_from(f"{user}@nxts> ", 30, f"shell prompt {user}")
        if got != "Login incorrect":
            return False
        fails += 1
        print(f"NOTE: login retry {user} (recorded failures {fails})")
        if fails >= 2:
            print(f"FAIL: too many login failures for {user}, refusing a third")
            return False
    return False

def cmd(text, marker):
    send_text(text)
    if not wait_from(marker, 30, f"marker for {text}"): return False
    return wait_from("alice@nxts> ", 30, f"prompt after {text}")

ok = True
def step(name, cond):
    global ok
    print(f"STEP {'PASS' if cond else 'FAIL'} {name}")
    ok = ok and cond

qemu, s = boot()
try:
    step("login alice", login("alice", "pwalice"))
    step("idle 1 set", cmd("idle 1", "Idle timeout set to 1 minutes for this session."))
    send_text("desktop")
    step("desktop entered",
         wait_from("Desktop notification: Welcome to nxtsOS desktop", 60, "desktop welcome"))
    # Phase A: no early lock for 30 s after desktop entry.
    before = log_text()
    early = False
    for _ in range(300):
        time.sleep(0.1)
        if "Desktop: lock screen shown" in log_text()[len(before):]:
            early = True
            break
    step("no lock screen in first 30 s (no early lock)", not early)
    # Phase B: the lock must arrive within a further 90 s (~60 s
    # after desktop entry in total).
    step("lock screen appears on idle timeout",
         wait_from("Desktop: lock screen shown", 90, "idle lock screen"))
    # Unlock with the session password (one retry for a doubled
    # sendkey; never a third attempt — it would halt the system).
    send_text("pwalice")
    got = wait_either(["Desktop: unlocked", "Desktop: lock password failed"], 30, "unlock result")
    if got == "Desktop: lock password failed":
        print("NOTE: password retry after doubled sendkey")
        send_text("pwalice")
        got = wait_either(["Desktop: unlocked", "Desktop: lock password failed"], 30, "unlock retry")
    step("idle lock unlocks with session password", got == "Desktop: unlocked")
finally:
    end_boot(qemu, s)
log = open(SERIAL, errors="replace").read()

def check(cond, label):
    global ok
    print(f"{'PASS' if cond else 'FAIL'} {label}"); ok = ok and cond
check(log.count("Desktop: lock screen shown") == 1, "exactly one lock screen shown")
check("Desktop: unlocked" in log, "unlock marker present")
check("Desktop: lock password failed" not in log or got == "Desktop: unlocked",
      "no unexplained lock password failure")
check("System halted" not in log, "system did not halt")
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in log, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
