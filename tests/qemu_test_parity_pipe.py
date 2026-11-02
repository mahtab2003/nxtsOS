#!/usr/bin/env python3
"""Parity run, family 6: pipes + redirection (step 9).

Boots (all on the same ISO):
  1 (pipe disk, setup root): > create, >> append, no-space
     operators (echo hi>nospace.txt), pipe to grep/sort/wc,
     3- and 4-stage pipelines, 5-stage refusal, explicit <
     input, pipe + final redirect, cat - through a pipe,
     write-from-stdin through a pipe, env value piped to
     grep, first-stage alias through a pipe, interactive
     refusals (top | cat, echo hi | top, top > f, fs edit
     | cat), pipe-temp cleanup (ls shows no .nxpipe*),
     temp-collision refusal + recovery, 256 KiB capture
     cap (cat big.txt | wc -c -> truncated warning +
     262144), bare cat - (no stdin), missing-target /
     empty-stage / multiple-output / reserved-name errors.
  2 (users disk): alice's redirect onto a root-owned 644
     file fails visibly ("capture failed") and leaves the
     file unchanged; alice's own create + append work.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_parity_pipe.py <iso> <workdir>
<workdir> is created by tests/qemu_test_parity_pipe_setup.py.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
PIPE = os.path.join(WORK, "pipe.img")
USERS = os.path.join(WORK, "users2.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5",
          ">": "shift-dot", "<": "shift-comma", "|": "shift-backslash"}
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

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

# ---- Boot 1: pipes + redirection ----
qemu, s = boot(PIPE)
try:
    check(wait_from("root@nxts> ", 60, "boot 1 prompt"), "boot 1 prompt")
    sh(s, "echo hello > out.txt", "root")
    seg = sh(s, "cat out.txt", "root")
    check(seg is not None and "\nhello\n" in seg, "> creates file with output")
    sh(s, "echo first > app.txt", "root")
    sh(s, "echo second >> app.txt", "root")
    seg = sh(s, "cat app.txt", "root")
    check(seg is not None and "\nfirst\n" in seg and "second\n" in seg, ">> appends")
    sh(s, "echo hi>nospace.txt", "root")
    seg = sh(s, "cat nospace.txt", "root")
    check(seg is not None and "\nhi\n" in seg, "no-space > works")
    seg = sh(s, "cat in.txt | grep ap", "root")
    check(seg is not None and seg.count("apple\n") == 2, "pipe to grep")
    seg = sh(s, "cat in.txt | sort", "root")
    check(seg is not None and seg.find("apple") < seg.find("avocado") < seg.find("banana") < seg.find("berry"),
          "pipe to sort (byte order)")
    seg = sh(s, "cat in.txt | grep ap | wc -l", "root")
    check(seg is not None and "\n2\n" in seg, "3-stage pipe to wc -l")
    seg = sh(s, "cat in.txt | grep ap | sort | wc -l", "root")
    check(seg is not None and "\n2\n" in seg, "4-stage pipe (max)")
    seg = sh(s, "cat in.txt | grep ap | sort | cat | wc -l", "root")
    check(seg is not None and "pipeline too long" in seg, "5-stage pipe refused")
    seg = sh(s, "cat < in.txt | wc -l", "root")
    # 6, not 5: cat appends its trailing newline after each
    # file (documented shape), so 5 content lines + 1 = 6.
    check(seg is not None and "\n6\n" in seg, "explicit < on first stage")
    seg = sh(s, "echo hello | wc -c", "root")
    check(seg is not None and "\n6\n" in seg, "echo | wc -c counts newline")
    sh(s, "cat in.txt | grep ap > res.txt", "root")
    seg = sh(s, "cat res.txt", "root")
    check(seg is not None and seg.count("apple\n") == 2, "pipe + final redirect")
    sh(s, "cat in.txt | sort > s.txt", "root")
    seg = sh(s, "cat s.txt", "root")
    check(seg is not None and seg.find("apple") < seg.find("avocado") < seg.find("banana"),
          "pipe to sort + redirect")
    seg = sh(s, "cat in.txt | cat -", "root")
    check(seg is not None and "banana" in seg and "apple" in seg, "cat - reads pipe stdin")
    sh(s, "cat in.txt | write copy.txt", "root")
    seg = sh(s, "cat copy.txt", "root")
    check(seg is not None and "banana" in seg and "berry" in seg, "write from pipe stdin")
    sh(s, "echo abc | write w.txt", "root")
    seg = sh(s, "cat w.txt", "root")
    check(seg is not None and "\nabc\n" in seg, "write from echo stdin")
    sh(s, "export P=ap", "root")
    seg = sh(s, "cat in.txt | grep $P", "root")
    check(seg is not None and seg.count("apple\n") == 2, "env value piped to grep")
    sh(s, "alias gg grep ap", "root")
    seg = sh(s, "gg in.txt | wc -l", "root")
    check(seg is not None and "\n2\n" in seg, "first-stage alias through pipe")
    seg = sh(s, "top | cat", "root")
    check(seg is not None and "cannot redirect interactive command" in seg, "top | cat refused")
    seg = sh(s, "echo hi | top", "root")
    check(seg is not None and "cannot redirect interactive command" in seg, "echo | top refused")
    seg = sh(s, "top > f.txt", "root")
    check(seg is not None and "cannot redirect interactive command" in seg, "top > file refused")
    seg = sh(s, "fs edit foo.txt | cat", "root")
    check(seg is not None and "cannot redirect interactive command" in seg, "fs edit | cat refused (group-resolved)")
    seg = sh(s, "ls", "root")
    check(seg is not None and ".nxpipe" not in seg, "pipe temps cleaned up")
    sh(s, "touch .nxpipe0", "root")
    seg = sh(s, "echo hi | cat", "root")
    check(seg is not None and "pipeline temp file exists" in seg, "temp collision refused")
    sh(s, "rm .nxpipe0", "root")
    seg = sh(s, "echo hi | cat", "root")
    check(seg is not None and "\nhi\n" in seg, "pipe works after temp removed")
    seg = sh(s, "cat big.txt | wc -c", "root")
    check(seg is not None and "capture truncated" in seg and "262144" in seg,
          "capture cap: truncated warning + 262144 bytes")
    seg = sh(s, "cat -", "root")
    check(seg is not None and "cat: no stdin" in seg, "bare cat - reports no stdin")
    seg = sh(s, "echo hi >", "root")
    check(seg is not None and "missing redirection target" in seg, "missing redirect target")
    seg = sh(s, "echo hi |", "root")
    check(seg is not None and "empty pipeline stage" in seg, "trailing pipe refused")
    seg = sh(s, "echo hi > a.txt > b.txt", "root")
    check(seg is not None and "multiple output redirections" in seg, "double output refused")
    seg = sh(s, "echo hi > .nxpipe0", "root")
    check(seg is not None and "reserved pipeline name" in seg, "reserved temp name refused")
finally:
    stop(qemu, s)

# ---- Boot 2: capture failure is visible, file unchanged ----
qemu, s = boot(USERS)
try:
    check(login(s, "admin", "pwadmin"), "boot 2 login admin")
    send_verified(s, "su alice")
    check(wait_from("alice@nxts> ", 30, "su alice prompt"), "boot 2 su alice")
    seg = sh(s, "echo hi > rootfile.txt", "alice")
    check(seg is not None and "capture failed" in seg, "redirect onto unwritable file fails visibly")
    seg = sh(s, "cat rootfile.txt", "alice")
    check(seg is not None and "original" in seg and "\nhi\n" not in seg, "failed redirect leaves file unchanged")
    sh(s, "echo hi > newfile.txt", "alice")
    sh(s, "echo more >> newfile.txt", "alice")
    seg = sh(s, "cat newfile.txt", "alice")
    check(seg is not None and "\nhi\n" in seg and "more\n" in seg, "non-root create + append work")
finally:
    stop(qemu, s)

print("PARITY_PIPE TEST PASS" if ok else "PARITY_PIPE TEST FAIL")
sys.exit(0 if ok else 1)
