#!/usr/bin/env python3
"""Shell `passwd` test: passwords must be changeable at runtime, and
only by the right principal. Single boot with a users.txt disk (root
uid 0, alice uid 1000, fixed salts): root changes alice's password
without a current-password prompt; an empty new password, an unknown
user, and a non-root change of another user are refused; alice's old
password then fails and the new one logs in; alice changing her own
password needs the correct current password, a mismatched retype is
refused, and a matched retype changes it; the rewritten users.txt
stays root-owned 0600 and the change is audited; root changes his own
password without a current-password prompt and logs in with it.

Login typing is not echoed for the password, so login() retries on
"Login incorrect" — but at most 2 recorded failures per user, since
a third locks the account (kernel fails_is_locked, count >= 3) and
no further login for that user could succeed. A deliberately failed
old-password login therefore costs at most 2 failures, and the next
successful login clears them. The QEMU sendkey doubling flake is the
only expected cause of a retry.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_passwd.py <iso> <workdir>
<workdir> is created by tests/qemu_test_passwd_setup.py.
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
    "-display", "vnc=:25", "-serial", f"file:{SERIAL}",
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
                FAILS[user] = 0  # a successful login clears failures, as in the kernel
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
        return log_text()[before:POS[0]]
    def logout(user):
        before = POS[0]
        send_text("logout")
        if not wait_from("Logged out.", 30, f"logout {user}"):
            return None
        return log_text()[before:POS[0]]
    def passwd(args, inputs, user):
        # inputs: ordered (prompt needle, text to type at it). An empty
        # text types just Return, which is how an empty password is sent.
        before = POS[0]
        send_text("passwd" + (" " + args if args else ""))
        for needle, txt in inputs:
            if not wait_from(needle, 30, f"passwd prompt {needle}"):
                return None
            send_text(txt)
        if not wait_from(f"{user}@nxts> ", 30, "prompt after passwd"):
            return None
        return log_text()[before:POS[0]]

    def check(cond, msg):
        global ok
        if not cond:
            print(f"FAIL: {msg}")
        ok &= bool(cond)

    ok &= login("root", "pwroot")
    seg = passwd("alice", [("New password: ", "alice2"),
                           ("Retype new password: ", "alice2")], "root")
    check(seg is not None and "Password changed for alice" in seg,
          "root changing alice's password did not report success")
    seg = passwd("alice", [("New password: ", "")], "root")
    check(seg is not None and "passwd: empty password not allowed" in seg,
          "empty new password was not refused")
    seg = cmd("passwd ghost", "root")
    check(seg is not None and "passwd: no such user ghost" in seg,
          "unknown user was not refused")
    seg = logout("root")
    check(seg is not None and "Logged out." in seg, "root logout failed")
    check(not login("alice", "pwalice"),
          "alice's OLD password still logged in after root changed it")
    ok &= login("alice", "alice2")
    seg = passwd("root", [], "alice")
    check(seg is not None and "passwd: permission denied" in seg,
          "non-root changing another user was not refused")
    seg = passwd("", [("Current password: ", "wrongpw")], "alice")
    check(seg is not None and "passwd: incorrect password" in seg,
          "wrong current password was not refused")
    seg = passwd("", [("Current password: ", "alice2"),
                      ("New password: ", "alice3x"),
                      ("Retype new password: ", "alice3y")], "alice")
    check(seg is not None and "passwd: passwords do not match" in seg,
          "mismatched retype was not refused")
    seg = passwd("", [("Current password: ", "alice2"),
                      ("New password: ", "alice3"),
                      ("Retype new password: ", "alice3")], "alice")
    check(seg is not None and "Password changed for alice" in seg,
          "alice changing her own password did not report success")
    seg = logout("alice")
    check(seg is not None and "Logged out." in seg, "alice logout failed")
    check(not login("alice", "alice2"),
          "alice's previous password still logged in after her own change")
    ok &= login("alice", "alice3")
    seg = logout("alice")
    check(seg is not None and "Logged out." in seg, "alice logout 2 failed")
    ok &= login("root", "pwroot")
    seg = cmd("ls", "root")
    check(seg is not None and
          re.search(r"users\.txt\s+\d+ bytes\s+uid 0\s+mode 384", seg) is not None,
          "rewritten users.txt is not root-owned 0600 (mode 384)")
    seg = cmd("cat audit.log", "root")
    check(seg is not None and "passwd alice" in seg,
          "audit.log has no passwd entry for alice")
    # Root changing his own password: no "Current password: " prompt is
    # expected — waiting straight for "New password: " proves it, since
    # a current-password prompt would leave the guest waiting for input.
    seg = passwd("", [("New password: ", "root2"),
                      ("Retype new password: ", "root2")], "root")
    check(seg is not None and "Password changed for root" in seg,
          "root changing his own password did not report success")
    seg = logout("root")
    check(seg is not None and "Logged out." in seg, "root logout 2 failed")
    ok &= login("root", "root2")
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
print("PASSWD TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
