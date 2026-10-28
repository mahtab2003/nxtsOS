#!/usr/bin/env python3
"""Shell-prompt idle-lock trigger: the first QEMU proof that the
shell loop's own idle check locks the session (until now the
trigger was proven only for the desktop loop by
tests/qemu_test_idle_lock.py, and for the shell path only via
the `lock` command, which calls the same do_lock() but not the
timer-driven shell-loop check itself — docs/SECURITY.md recorded
the shell-prompt-side trigger as not waited out in a test).
Single boot as alice: login, `idle 1`. Phase A: for 30 s after
the setting the lock must NOT fire (the no-early-lock property,
now for the shell path too). Phase B: within a further 90 s the
shell MUST print "Session locked due to inactivity." and the
lock prompt (about 60 s after the last keypress). Then type the
session password and expect "Session unlocked." plus the shell
prompt, then `whoami` prints "alice uid 1000" — the proof the
session continued, not logged out. A failed unlock only logs
the session out (it cannot halt, unlike the desktop lock's
3-strike halt), so a doubled-sendkey failure is recovered by
re-login, `idle 1` again, and one more waited-out cycle; a
second unlock failure fails the test.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_shell_idle_lock.py <iso> <workdir>
<workdir> is created by tests/qemu_test_shell_idle_lock_setup.py.
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
        "-display", "vnc=:28", "-serial", f"file:{SERIAL}",
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

def wait_for_lock():
    if not wait_from("Session locked due to inactivity.", 90, "idle lock notice"):
        return False
    return wait_from("Session locked. Enter password: ", 30, "lock prompt")

def unlock_attempt():
    send_text("pwalice")
    return wait_either(["Session unlocked.", "Unlock failed. Logging out."], 30, "unlock result")

ok = True
def step(name, cond):
    global ok
    print(f"STEP {'PASS' if cond else 'FAIL'} {name}")
    ok = ok and cond

got = None
retried = False
qemu, s = boot()
try:
    step("login alice", login("alice", "pwalice"))
    step("idle 1 set", cmd("idle 1", "Idle timeout set to 1 minutes for this session."))
    # Phase A: no early lock for 30 s after the setting. No keys
    # are sent during this window: any keypress would refresh
    # last_activity and restart the 60-second countdown.
    before = log_text()
    early = False
    for _ in range(300):
        time.sleep(0.1)
        if "Session locked due to inactivity." in log_text()[len(before):]:
            early = True
            break
    step("no lock in first 30 s (no early lock)", not early)
    # Phase B: the lock must arrive within a further 90 s (~60 s
    # after the last keypress in total).
    step("lock fires on idle timeout", wait_for_lock())
    got = unlock_attempt()
    if got == "Unlock failed. Logging out.":
        # A doubled sendkey on the password only logs this session
        # out (no halt risk, unlike the desktop lock): recover by
        # re-login and one more waited-out cycle, then fail the
        # test if the second unlock also fails.
        print("NOTE: unlock retry after doubled sendkey (session logged out, re-login)")
        retried = True
        step("re-login after unlock failure", login("alice", "pwalice"))
        step("idle 1 set again", cmd("idle 1", "Idle timeout set to 1 minutes for this session."))
        step("lock fires again on idle timeout", wait_for_lock())
        got = unlock_attempt()
    step("idle lock unlocks with session password", got == "Session unlocked.")
    step("shell prompt returns after unlock",
         wait_from("alice@nxts> ", 30, "prompt after unlock"))
    step("whoami proves session continued", cmd("whoami", "alice uid 1000"))
finally:
    end_boot(qemu, s)
log = open(SERIAL, errors="replace").read()

def check(cond, label):
    global ok
    print(f"{'PASS' if cond else 'FAIL'} {label}"); ok = ok and cond
check("Session unlocked." in log, "unlock marker present")
check(log.count("Session locked due to inactivity.") == (2 if retried else 1),
      "lock fired exactly once per cycle")
check("Unlock failed. Logging out." not in log or retried,
      "no unexplained unlock failure")
check("System halted" not in log, "system did not halt")
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in log, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
