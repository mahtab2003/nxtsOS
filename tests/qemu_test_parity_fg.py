#!/usr/bin/env python3
"""Parity run, family 5: fg/wait job control.

Boots (all on the same ISO):
  1 (fg disk, setup root): fg %1 on a slow job waits for
     its natural finish ("fg: job <pid> done"); wait %1
     likewise; wait with no argument waits for two slow
     jobs (two done messages); fg by numeric pid (parsed
     from jobs); fg %1 / wait %1 on a longrun job +
     Ctrl-C kills it ("killed (Ctrl-C)") and jobs empties;
     wait with no argument + Ctrl-C kills the first job
     and stops (the second job is then killed explicitly);
     bad specs (fg %9, fg 9999, wait %9) and bare fg usage.
  2 (users disk): admin starts a longrun job, su to alice;
     alice's fg %1 and wait %1 are refused (same permission
     rule as kill); su back to admin, killall cleans up.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_parity_fg.py <iso> <workdir>
<workdir> is created by tests/qemu_test_parity_fg_setup.py.
"""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
FG = os.path.join(WORK, "fg.img")
USERS = os.path.join(WORK, "fgusers.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5"}
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEYMAP[_c] = "shift-" + _c.lower()
KEYMAP.update({"$": "shift-4", "!": "shift-1", "'": "apostrophe",
               '"': "shift-apostrophe", "=": "equal"})

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

def boot(disk):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    POS[0] = 0
    qemu = subprocess.Popen(["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
            "-display", "none", "-serial", f"file:{SERIAL}",
            "-monitor", f"unix:{MON},server,nowait",
            "-drive", f"file={disk},format=raw,if=ide"])
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    return qemu, s

def stop(qemu, s):
    try: s.close()
    except Exception: pass
    if qemu.poll() is None:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()

def _current_line(t):
    # Job-aware: a background job's print between the prompt
    # and the typed echo must not blind the check (parity1
    # Boot C lesson); the current line follows the last newline.
    idx = t.rfind("@nxts> ")
    raw = t[idx + len("@nxts> "):] if idx >= 0 else ""
    out = []
    for ch in raw:
        if ch == "\b":
            if out: out.pop()
        elif ch == "\n" or ch == "\r":
            out = []
        else:
            out.append(ch)
    return "".join(out)

def send_verified(s, txt):
    for _attempt in range(3):
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        time.sleep(0.5)
        if _current_line(log_text()) == txt:
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            return True
        if _attempt < 2:
            for _ in range(len(txt) + 2):
                s.sendall(b"sendkey backspace\n"); time.sleep(0.1)
            time.sleep(0.5)
    # Final attempt: no erase after it, so Enter submits the
    # typed text even when echo verification was blind.
    s.sendall(b"sendkey ret\n"); time.sleep(1)
    return False

def sh(s, txt, user):
    before = POS[0]
    send_verified(s, txt)
    seg = None
    for _ in range(3):
        if not wait_from(f"{user}@nxts> ", 90, f"prompt after {txt}"):
            return None
        seg = log_text()[before:POS[0]]
        if f"{txt}\n" in seg:
            break
    return seg

def send_raw(s, txt):
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    time.sleep(0.4)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def send_key(s, key, delay=0.5):
    s.sendall(f"sendkey {key}\n".encode()); time.sleep(delay)

def wait_either(needles, timeout):
    for _ in range(int(timeout * 10)):
        t = log_text()
        for nd in needles:
            i = t.find(nd, POS[0])
            if i >= 0:
                POS[0] = i + len(nd)
                return nd
        time.sleep(0.1)
    return None

def send_login_user(s, user):
    for _attempt in range(3):
        for ch in user:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        time.sleep(0.5)
        t = log_text()
        idx = t.rfind("login: ")
        raw = t[idx + len("login: "):] if idx >= 0 else ""
        echo = []
        for ch in raw:
            if ch == "\b":
                if echo: echo.pop()
            elif ch == "\n" or ch == "\r":
                break
            else:
                echo.append(ch)
        if "".join(echo) == user:
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            return True
        for _ in range(len(user) + 2):
            s.sendall(b"sendkey backspace\n"); time.sleep(0.1)
        time.sleep(0.5)
    s.sendall(b"sendkey ret\n"); time.sleep(1)
    return False

def login(s, user, pw):
    for _ in range(2):
        if not wait_from("login: ", 60, f"login prompt {user}"): return False
        send_login_user(s, user)
        if not wait_from("Password: ", 30, f"password prompt {user}"): return False
        send_raw(s, pw)
        got = wait_either([f"{user}@nxts> ", "Login incorrect"], 30)
        if got == f"{user}@nxts> ": return True
        if got is None: return False
    return False

def fg_ctrlc(s, cmd, user):
    """Run a fg/wait command, press Ctrl-C mid-wait, and
    return the slice from before the command to the prompt."""
    before = POS[0]
    send_verified(s, cmd)
    time.sleep(1.5)
    send_key(s, "ctrl-c", delay=1.0)
    if not wait_from(f"{user}@nxts> ", 30, f"prompt after Ctrl-C {cmd}"):
        return None
    return log_text()[before:POS[0]]

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

# ---- Boot 1: fg/wait semantics ----
qemu, s = boot(FG)
try:
    check(wait_from("root@nxts> ", 60, "boot 1 prompt"), "boot 1 prompt")
    seg = sh(s, "runbg slow10.elf", "root")
    seg = sh(s, "fg %1", "root")
    check(seg is not None and "fg: job " in seg and " done" in seg, "fg %1 waits for natural finish")
    seg = sh(s, "runbg slow10.elf", "root")
    seg = sh(s, "wait %1", "root")
    check(seg is not None and "wait: job " in seg and " done" in seg, "wait %1 waits for natural finish")
    sh(s, "runbg slow10.elf", "root")
    sh(s, "runbg slow10.elf", "root")
    seg = sh(s, "wait", "root")
    # D1 added an "exit status" line per waited job, so "wait: job "
    # appears 4x for 2 jobs (2 done + 2 status); " done" alone
    # cannot be counted because the programs themselves print
    # "slow10 done". 4 wait-lines minus 2 status lines = 2 done.
    check(seg is not None and seg.count("wait: job ") == 4 and seg.count("exit status") == 2, "wait with no argument waits for both jobs")
    seg = sh(s, "runbg slow10.elf", "root")
    seg = sh(s, "jobs", "root")
    m = re.search(r"pid (\d+)  slow10", seg or "")
    check(m is not None, "jobs shows slow10 pid for fg test")
    if m:
        seg = sh(s, f"fg {m.group(1)}", "root")
        check(seg is not None and "fg: job " in seg and " done" in seg, "fg by numeric pid waits for finish")
    sh(s, "runbg longrun.elf", "root")
    seg = fg_ctrlc(s, "fg %1", "root")
    check(seg is not None and "killed (Ctrl-C)" in seg, "fg %1 + Ctrl-C kills the job")
    seg = sh(s, "jobs", "root")
    check(seg is not None and "(no background jobs)" in seg, "jobs empty after fg Ctrl-C kill")
    sh(s, "runbg longrun.elf", "root")
    seg = fg_ctrlc(s, "wait %1", "root")
    check(seg is not None and "killed (Ctrl-C)" in seg, "wait %1 + Ctrl-C kills the job")
    sh(s, "runbg longrun.elf", "root")
    sh(s, "runbg slow10.elf", "root")
    seg = fg_ctrlc(s, "wait", "root")
    check(seg is not None and "killed (Ctrl-C)" in seg, "wait-all + Ctrl-C kills the first job and stops")
    seg = sh(s, "killall slow10.elf", "root")
    check(seg is not None and "killall: killed 1 job(s)" in seg, "wait-all leftover slow10 job killed explicitly")
    seg = sh(s, "jobs", "root")
    check(seg is not None and "(no background jobs)" in seg, "jobs empty after wait-all cleanup")
    seg = sh(s, "fg %9", "root")
    check(seg is not None and "fg: cannot wait for %9" in seg, "fg %9 refused")
    seg = sh(s, "fg 9999", "root")
    check(seg is not None and "fg: cannot wait for 9999" in seg, "fg bad pid refused")
    seg = sh(s, "wait %9", "root")
    check(seg is not None and "wait: cannot wait for %9" in seg, "wait %9 refused")
    seg = sh(s, "fg", "root")
    check(seg is not None and "Usage: fg <pid|%N>" in seg, "bare fg is usage")
finally:
    stop(qemu, s)

# ---- Boot 2: cross-user refusal via su ----
qemu, s = boot(USERS)
try:
    check(login(s, "admin", "pwadmin"), "boot 2 login admin")
    sh(s, "runbg longrun.elf", "admin")
    send_verified(s, "su alice")
    check(wait_from("alice@nxts> ", 30, "su alice prompt"), "boot 2 su alice")
    seg = sh(s, "fg %1", "alice")
    check(seg is not None and "fg: cannot wait for %1" in seg, "fg refuses another user's job")
    seg = sh(s, "wait %1", "alice")
    check(seg is not None and "wait: cannot wait for %1" in seg, "wait refuses another user's job")
    send_verified(s, "su admin")
    check(wait_from("Password: ", 30, "su admin password prompt"), "boot 2 su admin password prompt")
    send_raw(s, "pwadmin")
    check(wait_from("admin@nxts> ", 30, "su back to admin"), "boot 2 su back to admin")
    seg = sh(s, "killall longrun.elf", "admin")
    check(seg is not None and "killall: killed 1 job(s)" in seg, "admin cleans up the longrun job")
    seg = sh(s, "jobs", "admin")
    check(seg is not None and "(no background jobs)" in seg, "jobs empty after admin cleanup")
finally:
    stop(qemu, s)

print("PARITY_FG TEST PASS" if ok else "PARITY_FG TEST FAIL")
sys.exit(0 if ok else 1)
