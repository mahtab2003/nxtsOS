#!/usr/bin/env python3
"""Repo-window root checks: a non-root desktop session must not be
able to update the repo index or install a package, even though the
pkg layer itself writes as uid 0 and the shell's root-only rule lives
in shell.c, not in pkg. Single boot, one persistent disk, one HTTP
server (slirp host 10.0.2.2). Phase 1 as root: dhcp, pkg repo, shell
pkg update (stores the 1-package index), logout. Phase 2 as alice:
desktopreporoottest — the kernel autotest mode 27 script: Start,
launcher Repo row (Repo opens with the stored index), Update
(refused: "repo: update needs root"), row 0 select (sysinfo),
Install (refused: "repo: install needs root"), Terminal icon
(desktop exits so the harness can run shell `pkg list`).
Login typing is not echoed for the password, so login() retries on
"Login incorrect" — but at most 2 recorded failures per user, since
a third locks the account (kernel fails_is_locked, count >= 3) and
no further login for that user could succeed. The QEMU sendkey
doubling flake is the only expected cause of a retry.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_repo_root.py <iso> <workdir>
<workdir> is created by tests/qemu_test_repo_root_setup.py.
"""
import os, shutil, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
SERVED = os.path.join(WORK, "served")
PORT = 18089
REPO = f"10.0.2.2:{PORT}"

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
ok = True
if os.path.isdir(SERVED): shutil.rmtree(SERVED)
shutil.copytree(os.path.join(WORK, "repo_v1"), SERVED)
server = subprocess.Popen([sys.executable, "-m", "http.server", str(PORT),
                           "--bind", "127.0.0.1", "--directory", SERVED],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
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
            # Logout returns to the login prompt, not to a shell prompt:
            # waiting for f"{user}@nxts> " here would time out even on
            # success (the chmod test's first-run failure class).
            before = POS[0]
            send_text("logout")
            if not wait_from("Logged out.", 30, f"logout {user}"):
                return None
            return log_text()[before:POS[0]]

        def step(name, cond):
            global ok
            print(f"STEP {'PASS' if cond else 'FAIL'} {name}")
            ok = ok and cond
        step("login root", login("root", "pwroot"))
        seg = cmd("dhcp", "root")
        step("dhcp configured", seg is not None and "dhcp: configured" in seg)
        seg = cmd(f"pkg repo {REPO}", "root")
        step("pkg repo set", seg is not None and f"Repository set to {REPO}" in seg)
        seg = cmd("pkg update", "root")
        step("pkg update", seg is not None and "Repository index updated: 1 package(s), version 1" in seg)
        seg = logout("root")
        step("logout root", seg is not None and "Logged out." in seg)
        step("login alice", login("alice", "pwalice"))
        send_text("desktopreporoottest")
        step("desktop test returned", wait_from("desktopreporoottest returned", 120, "desktop test returned"))
        # The desktop exit prints a fresh shell prompt BEFORE the next
        # command is typed: cmd() must consume that prompt first, or
        # its wait for "alice@nxts> " matches the pre-command prompt
        # and the segment ends before the command's output.
        step("shell prompt after desktop", wait_from("alice@nxts> ", 30, "shell prompt after desktop"))
        seg = cmd("pkg list", "alice")
        step("pkg list empty", seg is not None and "(no packages installed)" in seg)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
finally:
    server.terminate()

log = log_text()
def check(cond, label):
    global ok
    print(f"{'PASS' if cond else 'FAIL'} {label}"); ok = ok and cond
check("Desktop: Repo opened" in log, "repo window opened (alice)")
check("repo: index version 1" in log, "stored index loads for alice")
check("repo: sysinfo 1.0" in log, "stored list shows sysinfo")
check("repo: update needs root" in log, "update refused for non-root")
check("repo: selected sysinfo" in log, "row 0 selects sysinfo")
check("repo: install needs root" in log, "install refused for non-root")
check("Installed sysinfo 1.0" not in log, "no install happened (negative control)")
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in log, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
