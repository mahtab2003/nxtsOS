#!/usr/bin/env python3
"""Repo-window scroll test: a 10-entry signed index must be fully
browsable from the desktop. The Repo window shows 8 rows, so entries
9 and 10 are reachable only through the Up/Dn buttons added for this
chunk; before it, the window drew rows 0..7 only and silently hid them.
Single boot, one persistent disk, one HTTP server (slirp host 10.0.2.2).
Boot: dhcp, pkg repo, pkg update (index v1, 10 packages), pkg avail
(lists all 10 through the shell), then desktoprepotest — the kernel
autotest mode 9 script: Start, launcher Repo row, Dn -> scroll 1,
Dn -> scroll 2 (the clamp for 10 entries), Dn -> no change and no
marker, Up -> scroll 1, Up -> scroll 0, Up -> no change and no marker.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_repo_scroll.py <iso> <workdir>
<workdir> is created by tests/qemu_test_repo_scroll_setup.py.
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
PORT = 18086
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
        "-display", "vnc=:19", "-serial", f"file:{SERIAL}",
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
        send_text("pkg update")
        ok &= wait_for(lambda t: "Repository index updated: 10 package(s), version 1" in t, 60, "pkg update")
        send_text("pkg avail"); time.sleep(2)
        send_text("desktoprepotest")
        ok &= wait_for(lambda t: "repo: scroll 0" in t, 90, "repo scroll 0")
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
check("Repository index updated: 10 package(s), version 1" in log, "update: 10 packages")
check("Desktop: Repo opened" in log, "repo window opened")
check("repo: index version 1" in log, "repo index version 1")
for name in ("calc", "term", "bench", "sysinfo",
             "scroll-a", "scroll-b", "scroll-c", "scroll-d", "scroll-e", "scroll-f"):
    check(f"repo: {name} 1.0" in log, f"open-time copy: {name}")
check(log.count("repo: scroll 1") >= 2, "scroll 1 printed twice (Dn then Up)")
check(log.count("repo: scroll 2") == 1, "scroll 2 printed once (clamp, third Dn silent)")
check("repo: scroll 0" in log, "scroll 0 printed (Up back to top)")
check("repo: scroll 3" not in log, "no over-scroll past clamp")
for bad in ("EXCEPTION", "PANIC", "page fault"):
    check(bad not in log, f"no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
