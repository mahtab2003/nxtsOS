#!/usr/bin/env python3
"""Shell `chmod` test: a user must be able to restrict their own
file to owner-only and to re-share it, and nobody else may change
its mode. Single boot with a users.txt disk (alice uid 1000, bob
uid 1001): alice writes secret.txt (0644 by every user path, so
world-readable until now), chmods it to 600, and bob must fail to
read it and fail to chmod it; alice then chmods it back to 644 and
bob can read it. Negative controls: a malformed mode (999) and a
missing file are refused, and `ls` must show the stored mode in
decimal (0600 -> 384, 0644 -> 420).
Login typing is not echoed for the password, so login() retries on
"Login incorrect" — but at most 2 recorded failures per user, since
a third locks the account (kernel fails_is_locked, count >= 3) and
no further login for that user could succeed. The QEMU sendkey
doubling flake is the only expected cause of a retry.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_chmod.py <iso> <workdir>
<workdir> is created by tests/qemu_test_chmod_setup.py.
"""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")

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

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}
ok = True
for p in (SERIAL, MON):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "vnc=:24", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    def send_text(txt):
        for _attempt in range(2):
            before = len(log_text())
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            if "Unknown command" not in log_text()[before:]:
                break
    FAILS = {}
    def login(user, pw):
        for _attempt in range(3):
            if not wait_from("login: ", 60, f"login prompt {user}"): return False
            send_text(user)
            if not wait_from("Password: ", 30, f"password prompt {user}"): return False
            send_text(pw)
            got = wait_either([f"Welcome, {user}.", "Login incorrect"],
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
    def cmd(txt, user):
        before = POS[0]
        send_text(txt)
        if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt}"):
            return None
        seg = log_text()[before:POS[0]]
        # send_text retries once when a doubled key produces "Unknown
        # command" (e.g. "cchmod"); the retry's output lands AFTER the
        # first prompt, so extend the segment to the next prompt in
        # that case instead of failing on the doubled attempt's text.
        if "Unknown command" in seg:
            if not wait_from(f"{user}@nxts> ", 30, f"retry prompt after {txt}"):
                return None
            seg = log_text()[before:POS[0]]
        return seg
    def logout(user):
        # Logout returns to the login prompt, not to a shell prompt:
        # waiting for f"{user}@nxts> " here would time out even on
        # success (the first-run failure class of this test).
        before = POS[0]
        send_text("logout")
        if not wait_from("Logged out.", 30, f"logout {user}"):
            return None
        return log_text()[before:POS[0]]

    ok &= login("alice", "pwalice")
    seg = cmd("write secret.txt my secret", "alice")
    ok &= seg is not None and "Wrote secret.txt" in seg
    seg = cmd("chmod secret.txt 600", "alice")
    ok &= seg is not None and "chmod: secret.txt mode 600" in seg
    seg = cmd("ls", "alice")
    ok &= seg is not None and re.search(r"secret\.txt\s+9 bytes\s+uid 1000\s+mode 384", seg) is not None
    if seg is None or re.search(r"secret\.txt\s+9 bytes\s+uid 1000\s+mode 384", seg or "") is None:
        print("FAIL: ls after chmod 600 did not show mode 384")
    seg = logout("alice")
    ok &= seg is not None and "Logged out." in seg
    ok &= login("bob", "pwbob")
    seg = cmd("cat secret.txt", "bob")
    ok &= seg is not None and "cat: cannot read secret.txt" in seg
    seg = cmd("chmod secret.txt 644", "bob")
    ok &= seg is not None and "chmod: cannot chmod secret.txt" in seg
    seg = logout("bob")
    ok &= seg is not None and "Logged out." in seg
    ok &= login("alice", "pwalice")
    seg = cmd("chmod secret.txt 644", "alice")
    ok &= seg is not None and "chmod: secret.txt mode 644" in seg
    seg = cmd("ls", "alice")
    ok &= seg is not None and re.search(r"secret\.txt\s+9 bytes\s+uid 1000\s+mode 420", seg) is not None
    if seg is None or re.search(r"secret\.txt\s+9 bytes\s+uid 1000\s+mode 420", seg or "") is None:
        print("FAIL: ls after chmod 644 did not show mode 420")
    seg = cmd("chmod secret.txt 999", "alice")
    ok &= seg is not None and "chmod: bad mode 999" in seg
    seg = cmd("chmod missing.txt 600", "alice")
    ok &= seg is not None and "chmod: cannot chmod missing.txt" in seg
    seg = logout("alice")
    ok &= seg is not None and "Logged out." in seg
    ok &= login("bob", "pwbob")
    seg = cmd("cat secret.txt", "bob")
    ok &= seg is not None and "my secret" in seg
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
print("CHMOD TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
