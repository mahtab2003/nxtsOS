#!/usr/bin/env python3
"""Parity run, family 1: date set, group-enforced file
permissions + chgrp, top k kill + kill %N, dhcp/dnsset gates.

Boots (all on the same ISO):
  A (fresh blank disk, setup-mode root): date round-trip
     (set -> date shows the new time), bad-shape refusals
     (bad month, Feb 30, missing time, short year, trailing
     words), all with the Usage line.
  B (users disk: admin uid 0, alice 1000, bob 1001, plus a
     world-readable pub.txt seeded by mkdisk, so its gid is 0
     = old-format behaviour): as admin, groupadd dev +
     groupmod dev add alice + write/chgrp/chmod shared.txt
     640 (stat shows "group 1000 (dev)"); overwrite keeps the
     gid; chgrp unknown-group and missing-file refusals. As
     alice (member): cat shared.txt works; date/dhcp/dnsset/
     chgrp all refused "root only"; groups shows dev. As bob
     (non-member): cat shared.txt refused, stat refused, but
     pub.txt (old-format, mode 644) still reads and stats as
     "no group".
  C (top disk with longrun.elf): top k with a bad pid refuses
     and top resumes; top k %1 kills the job (retry the whole
     slow+top sequence up to 3 times: slow only runs ~5 s, so
     a slow scheduling slip must not read as a kill failure);
     kill %1 via the kill command; top k by numeric pid.
     The cross-user top-k case (non-root killing root's job)
     is NOT here: logout kills the session's jobs, so no root
     job can survive for alice to attempt — that case moves
     to the su test once su lands (same proc_bg_kill path).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_parity1.py <iso> <workdir>
<workdir> is created by tests/qemu_test_parity1_setup.py.
"""
import os, re, shutil, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
BLANK = os.path.join(WORK, "blank.img")
USERS = os.path.join(WORK, "users.img")
TOPD = os.path.join(WORK, "top.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5"}

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
    args = ["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
            "-display", "none", "-serial", f"file:{SERIAL}",
            "-monitor", f"unix:{MON},server,nowait"]
    if disk:
        args += ["-drive", f"file={disk},format=raw,if=ide"]
    qemu = subprocess.Popen(args)
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
            # A newline here is intervening output (a background
            # job's print, or a submitted line): the current line
            # is whatever follows it, not what precedes it.
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
    # Final attempt: the line still holds the typed text (no
    # erase after it), so Enter submits the command even when
    # echo verification was blind. A corrupted submit fails
    # loudly (Unknown command) instead of silently never running.
    s.sendall(b"sendkey ret\n"); time.sleep(1)
    return False

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
    """Type a username at the login prompt with echo
    verification. The generic send_verified() is blind here:
    it checks the current line after the last "@nxts> ",
    which never appears at a login prompt, so it always
    'fails' and retypes through 3 erase cycles — and any
    lost backspace in those cycles corrupts the name
    (proven 2026-10-30: raw single typing logs in, the
    verified sender produced "Login incorrect" + lockout).
    The kernel echoes the username, so the text after the
    last "login: " marker (backspaces interpreted) IS a
    real echo check."""
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

def send_raw(s, txt):
    """Send text + Enter with no echo verification (for
    echo-off prompts like Password:)."""
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    time.sleep(0.4)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def login(s, user, pw):
    """At most 2 attempts: a third recorded failure locks the account."""
    for _ in range(2):
        if not wait_from("login: ", 60, f"login prompt {user}"): return False
        send_login_user(s, user)
        if not wait_from("Password: ", 30, f"password prompt {user}"): return False
        send_raw(s, pw)
        got = wait_either([f"{user}@nxts> ", "Login incorrect"], 30)
        if got == f"{user}@nxts> ": return True
        if got is None: return False
    return False

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

# ---- Boot A: date set (setup root) ----
qemu, s = boot(os.path.join(WORK, "a.img"))
try:
    check(wait_from("root@nxts> ", 60, "boot A prompt"), "boot A prompt")
    seg = sh(s, "date", "root")
    check(seg is not None and re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", seg) is not None, "date prints a timestamp")
    seg = sh(s, "date set 2031-02-03 04:05:06", "root")
    check(seg is not None and "date: set" in seg, "date set accepted")
    seg = sh(s, "date", "root")
    check(seg is not None and "2031-02-03 04:05:0" in seg, "date shows the new time")
    for bad in ("date set 2031-13-01 00:00:00", "date set 2031-02-30 00:00:00",
                "date set 2031-02-03", "date set 99-02-03 04:05:06",
                "date set 2031-02-03 04:05:06 extra"):
        seg = sh(s, bad, "root")
        check(seg is not None and "Usage: date set" in seg, f"bad date refused: {bad}")
    seg = sh(s, "date", "root")
    check(seg is not None and "2031-02-03" in seg, "bad sets left the clock alone")
finally:
    stop(qemu, s)

# ---- Boot B: group permissions (admin/alice/bob) ----
qemu, s = boot(USERS)
try:
    check(login(s, "admin", "pwadmin"), "boot B login admin")
    seg = sh(s, "groupadd dev", "admin")
    check(seg is not None and "Added group dev (gid 1000)" in seg, "groupadd dev")
    seg = sh(s, "groupmod dev add alice", "admin")
    check(seg is not None and "Added alice to dev" in seg, "groupmod dev add alice")
    seg = sh(s, "write shared.txt shared data", "admin")
    check(seg is not None and "Wrote shared.txt" in seg, "admin writes shared.txt")
    seg = sh(s, "chgrp shared.txt dev", "admin")
    check(seg is not None and "chgrp: shared.txt group dev" in seg, "chgrp shared.txt dev")
    seg = sh(s, "chmod shared.txt 640", "admin")
    check(seg is not None and "chmod: shared.txt mode 640" in seg, "chmod shared.txt 640")
    seg = sh(s, "stat shared.txt", "admin")
    check(seg is not None and "group 1000 (dev)" in seg, "stat shows group dev")
    seg = sh(s, "write own2.txt v1", "admin")
    seg = sh(s, "chgrp own2.txt dev", "admin")
    seg = sh(s, "write own2.txt v2", "admin")
    seg = sh(s, "stat own2.txt", "admin")
    check(seg is not None and "group 1000 (dev)" in seg, "overwrite preserves gid")
    seg = sh(s, "chgrp shared.txt nosuchgroup", "admin")
    check(seg is not None and "chgrp: no such group nosuchgroup" in seg, "chgrp unknown group refused")
    seg = sh(s, "chgrp missing.txt dev", "admin")
    check(seg is not None and "chgrp: cannot chgrp missing.txt" in seg, "chgrp missing file refused")
    send_verified(s, "logout")
    wait_from("Logged out.", 30, "logged out after admin logout")
    check(login(s, "alice", "pwalice"), "boot B login alice")
    seg = sh(s, "cat shared.txt", "alice")
    check(seg is not None and "shared data" in seg, "group member reads 640 file")
    seg = sh(s, "date set 2032-01-01 00:00:00", "alice")
    check(seg is not None and "date: root only" in seg, "date set refused for non-root")
    seg = sh(s, "dhcp", "alice")
    check(seg is not None and "dhcp: root only" in seg, "dhcp refused for non-root")
    seg = sh(s, "dnsset 1.1.1.1", "alice")
    check(seg is not None and "dnsset: root only" in seg, "dnsset refused for non-root")
    seg = sh(s, "chgrp shared.txt dev", "alice")
    check(seg is not None and "chgrp: root only" in seg, "chgrp refused for non-root")
    seg = sh(s, "groups", "alice")
    check(seg is not None and "alice: dev" in seg, "groups shows alice in dev")
    seg = sh(s, "write alice1.txt data", "alice")
    check(seg is not None and "Wrote alice1.txt" in seg, "alice writes alice1.txt")
    seg = sh(s, "stat alice1.txt", "alice")
    check(seg is not None and "group 1000 (dev)" in seg, "create takes creator primary group")
    seg = sh(s, "cp alice1.txt alice2.txt", "alice")
    check(seg is not None and "alice2.txt" in seg, "alice copies alice1.txt")
    seg = sh(s, "stat alice2.txt", "alice")
    check(seg is not None and "group 1000 (dev)" in seg, "copy takes creator primary group")
    send_verified(s, "logout")
    wait_from("Logged out.", 30, "logged out after alice logout")
    check(login(s, "bob", "pwbob"), "boot B login bob")
    seg = sh(s, "cat shared.txt", "bob")
    check(seg is not None and "cat: cannot read shared.txt" in seg, "non-member cannot read 640 file")
    seg = sh(s, "stat shared.txt", "bob")
    check(seg is not None and "stat: cannot stat shared.txt" in seg, "non-member cannot stat 640 file")
    seg = sh(s, "cat pub.txt", "bob")
    check(seg is not None and "public data" in seg, "old-format world-readable file still reads")
    seg = sh(s, "stat pub.txt", "bob")
    check(seg is not None and "no group" in seg, "old-format file stats as no group")
finally:
    stop(qemu, s)

# ---- Boot C: top k + kill %N (setup root) ----
def top_kill(s, spec):
    """Enter top, press k, answer with spec, quit. Returns
    (killed_marker_found, quit_ok)."""
    send_verified(s, "top")
    time.sleep(1.5)
    s.sendall(b"sendkey k\n"); time.sleep(1.0)
    if not wait_from("top: kill pid (or %N): ", 15, "top kill prompt"):
        return False, False
    for ch in spec:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    s.sendall(b"sendkey ret\n"); time.sleep(1.0)
    # One combined wait: sequential waits burn 15 s on the
    # first branch whenever the marker is the second one.
    killed = wait_either(["top: killed job", "top: cannot kill"], 15) is not None
    s.sendall(b"sendkey q\n"); time.sleep(1.0)
    quit_ok = wait_from("top: quit", 15, "top quit")
    if quit_ok:
        quit_ok = wait_from("root@nxts> ", 30, "prompt after top")
    return killed, quit_ok

qemu, s = boot(TOPD)
try:
    check(wait_from("root@nxts> ", 60, "boot C prompt"), "boot C prompt")
    # Bad pid: refused, top resumes, q quits.
    killed, quit_ok = top_kill(s, "9999")
    seg = log_text()
    check("top: cannot kill 9999" in seg, "top k bad pid refused")
    check(quit_ok, "top resumes and quits after bad pid")
    # Kill %1 via top (longrun runs ~60 s, so the kill
    # never races the job exit; the retry stays as safety).
    killed_ok = False
    for _attempt in range(3):
        seg = sh(s, "runbg longrun.elf", "root")
        killed, quit_ok = top_kill(s, "%1")
        seg = log_text()
        if "top: killed job" in seg and quit_ok:
            killed_ok = True
            break
        # Slow may have exited before the kill; retry from a fresh job.
        time.sleep(0.5)
    check(killed_ok, "top k %1 kills the job")
    seg = sh(s, "jobs", "root")
    check(seg is not None and "(no background jobs)" in seg, "job gone after top k")
    # kill %1 via the kill command.
    seg = sh(s, "runbg longrun.elf", "root")
    seg = sh(s, "kill %1", "root")
    check(seg is not None and "Killed background job pid" in seg, "kill %1 kills the job")
    seg = sh(s, "jobs", "root")
    check(seg is not None and "(no background jobs)" in seg, "job gone after kill %1")
    # Top k by numeric pid (parsed from jobs).
    seg = sh(s, "runbg longrun.elf", "root")
    seg = sh(s, "jobs", "root")
    m = re.search(r"pid (\d+)  longrun", seg or "")
    check(m is not None, "jobs shows longrun pid")
    if m:
        pid = m.group(1)
        killed, quit_ok = top_kill(s, pid)
        seg = log_text()
        check(f"top: killed job {pid}" in seg and quit_ok, "top k numeric pid kills the job")
        seg = sh(s, "jobs", "root")
        check(seg is not None and "(no background jobs)" in seg, "job gone after top k pid")
finally:
    stop(qemu, s)

print("PARITY1 TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
