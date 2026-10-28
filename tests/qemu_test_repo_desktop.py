#!/usr/bin/env python3
"""Repo-window Update + Install test: a desktop-only user must be able
to fetch the repo index and install a package without the shell.
Single boot, one persistent disk, one HTTP server (slirp host 10.0.2.2).
Boot: dhcp, pkg repo (NO pkg update — the desktop Update is the fetch),
then desktoprepoapptest — the kernel autotest mode 10 script: Start,
launcher Repo row (Repo opens with no stored index), Update (fetches
the 1-package index), Install with no selection (refused), row 0
select (sysinfo), Install (fetches + installs sysinfo), Start,
launcher Packages row (Packages lists the installed sysinfo entry).
The Update and Install fetches block the desktop loop, so the script
holds the release over a wide step range after each fetch (Web test
pattern); a press landing while the button is still held would lose
the click, so the ranges, not single steps, carry the release.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_repo_desktop.py <iso> <workdir>
<workdir> is created by tests/qemu_test_repo_desktop_setup.py.
The sender verifies the shell's echo of each command and
retypes once on mismatch (the QEMU sendkey-doubling flake
class from the repo test); login typing is not echoed.
"""
import os, shutil, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
SERVED = os.path.join(WORK, "served")
PORT = 18087
REPO = f"10.0.2.2:{PORT}"

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus", ":": "shift-semicolon"}

if os.path.isdir(SERVED): shutil.rmtree(SERVED)
shutil.copytree(os.path.join(WORK, "repo_v1"), SERVED)
server = subprocess.Popen([sys.executable, "-m", "http.server", str(PORT),
                           "--bind", "127.0.0.1", "--directory", SERVED],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
ok = True
try:
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:20", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
    ])
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        ok &= wait_for(lambda t: "root@nxts> " in t, 60, "shell prompt")
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
        send_text("dhcp"); time.sleep(1)
        send_text(f"pkg repo {REPO}"); time.sleep(1)
        send_text("desktoprepoapptest")
        ok &= wait_for(lambda t: "packages: sysinfo 1.0" in t, 120, "packages lists sysinfo")
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
check("Desktop: Repo opened" in log, "repo window opened")
check("repo: no stored index" in log, "repo opens with no stored index")
check("Repository index updated: 1 package(s), version 1" in log, "desktop update fetched 1-package index")
check("repo: index version 1" in log, "repo index version 1 after update")
check("repo: sysinfo 1.0" in log, "updated list shows sysinfo")
check("repo: install needs selection" in log, "install refused with no selection")
check("repo: selected sysinfo" in log, "row 0 selects sysinfo")
check("Installed sysinfo 1.0" in log, "desktop install installed sysinfo")
check("packages: sysinfo 1.0" in log, "packages window lists installed sysinfo")
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in log, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
