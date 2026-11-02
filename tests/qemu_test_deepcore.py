#!/usr/bin/env python3
"""Deep-core suite 1: kmalloc boot self-test, exit status
(wait/fg reporting + consume-once), signals for background
jobs (STOP/CONT/TERM/KILL, name + number forms, bad signal,
unknown job, cross-user refusal).
One boot (disk from qemu_test_deepcore_setup.py): login as
admin, su bob for the refusal check.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_deepcore.py <iso> <workdir>
"""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5",
          ",": "comma", "(": "shift-9", ")": "shift-0"}
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEYMAP[_c] = "shift-" + _c.lower()

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
POS = [0]
NOK = [0]
NFAIL = [0]

def check(cond, label):
    if cond:
        NOK[0] += 1; print(f"ok: {label}")
    else:
        NFAIL[0] += 1; print(f"FAIL: {label}")

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
        for _ in range(len(txt) + 2):
            s.sendall(b"sendkey backspace\n"); time.sleep(0.1)
        time.sleep(0.5)
    s.sendall(b"sendkey ret\n"); time.sleep(1)
    return False

def send_blind(s, txt):
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def send_text(s, txt):
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def sh(s, txt, user):
    before = POS[0]
    send_verified(s, txt)
    seg = None
    for _ in range(3):
        if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt}"):
            return None
        seg = log_text()[before:POS[0]]
        if f"{txt}\n" in seg:
            break
    return seg

def login(s, user, pw):
    """Copied pattern from linuxcomp: up to 3 attempts, poll for
    Welcome vs Login incorrect. Callers must NOT pre-wait for
    "login: " — this consumes the only occurrence."""
    for attempt in range(3):
        if not wait_from("login: ", 60, f"login prompt {user}"):
            return False
        send_text(s, user)
        if not wait_from("Password: ", 30, f"password prompt {user}"):
            return False
        send_blind(s, pw)
        got = None
        for _ in range(300):
            t = log_text()
            if f"Welcome, {user}." in t[POS[0]:]:
                got = "ok"; break
            if "Login incorrect" in t[POS[0]:]:
                got = "bad"; break
            time.sleep(0.1)
        if got == "ok":
            return wait_from(f"{user}@nxts> ", 30, f"shell prompt {user}")
        if got != "bad":
            return False
        print(f"NOTE: login retry {user} (attempt {attempt + 1})")
    return False

def wait_either(needles, timeout, label):
    for _ in range(int(timeout * 10)):
        t = log_text()
        for nd in needles:
            i = t.find(nd, POS[0])
            if i >= 0:
                POS[0] = i + len(nd)
                return nd
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return None

def su_sh(s, target, pw):
    """su to target, answering a password prompt if one appears
    (root needs none; non-root needs the target's password).
    Mirrors linuxcomp's proven sudo_with_pw: wait_either
    advances POS past each matched needle, so a consumed
    password prompt is never re-seen (the previous version
    re-sent the password 100 times at the new prompt because
    it scanned from a stale offset)."""
    send_verified(s, f"su {target}")
    for _ in range(3):
        got = wait_either(["Password: ", f"{target}@nxts> "], 30, f"su {target}")
        if got == f"{target}@nxts> ":
            return True
        if got is None:
            return False
        send_blind(s, pw)
    return False

def parse_pid(seg, name):
    m = re.search(rf"Background job {re.escape(name)} started \(pid (\d+)", seg or "")
    return m.group(1) if m else None

def sched_runs(seg, pid):
    m = re.search(rf"pid {pid}\s+\S+.*runs (\d+)", seg or "")
    return int(m.group(1)) if m else None

def main():
    qemu, s = boot(DISK)
    try:
        if not login(s, "admin", "pwadmin"):
            print("FAIL: login admin"); return 1
        check(True, "login admin")
        # kmalloc self-test runs at boot; the line is on serial.
        check("kmalloc selftest: PASS" in log_text(), "kmalloc boot selftest PASS")
        seg = sh(s, "signals", "admin")
        for line in ("1 HUP hangup: terminate", "2 INT interrupt: terminate",
                     "9 KILL kill: terminate", "15 TERM terminate: terminate",
                     "18 CONT continue: resume a stopped job",
                     "19 STOP stop: pause a job"):
            check(seg is not None and line in seg, f"signals lists {line.split()[1]}")
        # Foreground exit status (non-zero appended, zero unchanged).
        seg = sh(s, "run exitcode.elf", "admin")
        check(seg is not None and "Program exitcode.elf finished (status 7)" in seg,
              "foreground exit status 7 reported")
        # Background exit status via wait, then consume-once.
        seg = sh(s, "runbg exitcode.elf", "admin")
        pid = parse_pid(seg, "exitcode.elf")
        check(pid is not None, "runbg exitcode starts")
        seg = sh(s, f"wait {pid}", "admin") if pid else None
        check(seg is not None and f"wait: job {pid} done" in seg,
              "wait reports job done")
        check(seg is not None and f"wait: job {pid} exit status 7" in seg,
              "wait reports exit status 7")
        seg = sh(s, f"wait {pid}", "admin") if pid else None
        check(seg is not None and f"wait: cannot wait for {pid}" in seg,
              "reaped status reported exactly once")
        # Signals: STOP parks, CONT resumes, TERM terminates.
        seg = sh(s, "runbg longrun.elf", "admin")
        pid = parse_pid(seg, "longrun.elf")
        check(pid is not None, "runbg longrun starts")
        seg = sh(s, f"kill -STOP {pid}", "admin") if pid else None
        check(seg is not None and f"kill: signal 19 sent to {pid}" in seg,
              "kill -STOP sends signal 19")
        time.sleep(2)
        seg1 = sh(s, "sched", "admin")
        r1 = sched_runs(seg1, pid) if pid else None
        time.sleep(2)
        seg2 = sh(s, "sched", "admin")
        r2 = sched_runs(seg2, pid) if pid else None
        check(r1 is not None and r1 == r2, "stopped job runs count frozen")
        seg = sh(s, "jobs", "admin")
        check(seg is not None and "longrun.elf" in seg, "stopped job still listed")
        seg = sh(s, f"kill -CONT {pid}", "admin") if pid else None
        check(seg is not None and f"kill: signal 18 sent to {pid}" in seg,
              "kill -CONT sends signal 18")
        time.sleep(2)
        seg3 = sh(s, "sched", "admin")
        r3 = sched_runs(seg3, pid) if pid else None
        check(r2 is not None and r3 is not None and r3 > r2, "continued job runs again")
        seg = sh(s, f"kill -15 {pid}", "admin") if pid else None
        check(seg is not None and f"kill: signal 15 sent to {pid}" in seg,
              "kill -15 sends signal 15")
        time.sleep(2)
        check(f"terminated by signal 15" in log_text(), "TERM termination printed")
        seg = sh(s, "jobs", "admin")
        # Row check, not bare substring: the async "terminated by
        # signal" line itself contains longrun.elf and can land
        # inside this segment (same race class as the linuxcomp
        # sched race). A jobs row is `pid N  longrun.elf  uid N`.
        check(seg is not None and re.search(r"pid \d+  longrun\.elf", seg) is None,
              "terminated job gone")
        # Bad signal, unknown job, name form KILL.
        seg = sh(s, "runbg longrun.elf", "admin")
        pid = parse_pid(seg, "longrun.elf")
        check(pid is not None, "second longrun starts")
        seg = sh(s, f"kill -99 {pid}", "admin") if pid else None
        check(seg is not None and "unknown signal" in seg, "bad signal refused")
        seg = sh(s, "kill -15 99999", "admin")
        check(seg is not None and "cannot kill 99999" in seg, "unknown job refused")
        seg = sh(s, f"kill -KILL {pid}", "admin") if pid else None
        check(seg is not None and f"kill: signal 9 sent to {pid}" in seg,
              "kill -KILL name form sends signal 9")
        time.sleep(2)
        check("terminated by signal 9" in log_text(), "KILL termination printed")
        # Cross-user: bob may not signal admin's job.
        seg = sh(s, "runbg longrun.elf", "admin")
        pid = parse_pid(seg, "longrun.elf")
        check(pid is not None, "third longrun starts")
        check(su_sh(s, "bob", "pwbob"), "su bob")
        seg = sh(s, f"kill -TERM {pid}", "bob") if pid else None
        check(seg is not None and f"cannot kill {pid}" in seg,
              "cross-user signal refused")
        check(su_sh(s, "admin", "pwadmin"), "su admin back")
        seg = sh(s, f"kill {pid}", "admin") if pid else None
        check(seg is not None and f"Killed background job pid {pid}" in seg,
              "cleanup kill works")
        print(f"DEEPCORE: {NOK[0]} checks passed, {NFAIL[0]} failed")
        if NFAIL[0] == 0:
            print("PASS")
            return 0
        print("FAIL")
        return 1
    finally:
        stop(qemu, s)

if __name__ == "__main__":
    sys.exit(main())
