#!/usr/bin/env python3
"""Linux-comparability run, leftover cross-user top-k test:
as root, start longrun.elf; su alice (non-root); in top,
press k and type the root job's pid; top must refuse
("top: cannot kill ... (no such job or no permission)") via
the same proc_bg_kill rule as the covered fg/wait refusals;
q quits top and the session is still alive; the job is
still listed by jobs afterwards (it was refused, not killed).

One boot (disk from qemu_test_topk_setup.py).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_topk.py <iso> <workdir>
"""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
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
    # Job-aware (parity_fg lesson): a background job's print
    # between the prompt and the typed echo must not blind the
    # check, so the current line follows the LAST newline
    # (reset on newline) instead of stopping at the first.
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
    """Blind send for the login prompt: send_verified cannot work
    there (no @nxts> prompt exists yet to verify against), and
    its backspace retries would erase the typed username."""
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

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

def login(s, user, pw):
    """Up to 3 attempts (sendkey flakes can corrupt a password).
    Success is the "Welcome, <user>." line, as in core_users."""
    for attempt in range(3):
        if not wait_from("login: ", 60, f"login prompt {user}"):
            return False
        send_text(s, user)
        if not wait_from("Password: ", 30, f"password prompt {user}"):
            return False
        send_text(s, pw)
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

qemu, s = boot(DISK)
try:
    check(login(s, "admin", "pwadmin"), "login as admin")
    seg = sh(s, "runbg longrun.elf", "admin")
    check(seg is not None, "runbg longrun.elf")
    seg = sh(s, "jobs", "admin")
    # jobs rows are "pid %u  %s  uid %u" (two spaces, pinned format).
    m = re.search(r"pid (\d+)\s+longrun\.elf", seg or "")
    check(m is not None, "jobs lists the root longrun job")
    pid = m.group(1) if m else "1"
    # su alice: root needs no password.
    seg = sh(s, "su alice", "alice")
    check(seg is not None, "su alice")
    # Top: send "top", wait for its header, press k, type the pid.
    before = POS[0]
    send_verified(s, "top")
    check(wait_from("press q to quit, k to kill", 30, "top header"), "top header appears")
    s.sendall(b"sendkey k\n"); time.sleep(1)
    check(wait_from("top: kill pid (or %N): ", 30, "top kill prompt"), "top kill prompt after k")
    # The kill prompt is not a shell prompt, so send_verified's
    # current-line check cannot work here: send the pid blind
    # (per-char delays, as for passwords) and wait for the
    # refusal line naming exactly this pid.
    send_blind(s, pid)
    check(wait_from(f"top: cannot kill {pid} (no such job or no permission)", 30,
                   "top cross-user refusal"), "top refuses a non-root kill of a root job")
    s.sendall(b"sendkey q\n"); time.sleep(1)
    check(wait_from("top: quit", 30, "top quit"), "top quits on q")
    check(wait_from("alice@nxts> ", 30, "prompt after top"), "session alive after top")
    seg = sh(s, "jobs", "alice")
    # Alice's jobs view lists jobs regardless of owner (proc_bg_list
    # is not permission-filtered); the root job must still be there.
    check(seg is not None and f"pid {pid}" in seg, "root job still alive after refused top-k")
finally:
    stop(qemu, s)
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
