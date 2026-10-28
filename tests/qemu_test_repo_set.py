#!/usr/bin/env python3
"""Repo-window Set repo test: a desktop-only user must be able to
point the Repo window at a repository without the shell.
Single boot, one persistent disk, one HTTP server (slirp host
10.0.2.2). Boot: dhcp (NO shell pkg repo — the desktop Set is the
configuration), then desktopreposettest — the kernel autotest mode
19 script: Start, launcher Repo row (Repo opens with no repository
set and no stored index), Set repo with an empty field (refused),
field click, type "10.0.2.2:18088", Set repo (configures it),
Update (fetches the 1-package index), row 0 select (sysinfo),
Install (fetches + installs sysinfo), Terminal icon (desktop
exits). The harness then runs `pkg repo` + `pkg list` on the shell:
the stored URL and the installed package are the registry proofs,
not just the markers. The Update and Install fetches block the
desktop loop, so the script holds the release over a wide step
range after each fetch (Web test pattern).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_repo_set.py <iso> <workdir>
<workdir> is created by tests/qemu_test_repo_set_setup.py.
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
PORT = 18088
REPO = f"10.0.2.2:{PORT}"

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

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
        "-display", "vnc=:22", "-serial", f"file:{SERIAL}",
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
        send_text("desktopreposettest")
        ok &= wait_for(lambda t: "desktopreposettest returned" in t, 150, "desktopreposettest returned")
        # Desktop has exited (Terminal icon); the shell prompt is back.
        time.sleep(4)
        send_text("pkg repo"); time.sleep(1)
        send_text("pkg list"); time.sleep(2)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
finally:
    server.terminate()
log = log_text()
for m in ["Desktop: Repo opened",
          "repo: set needs url",
          "Repository set to 10.0.2.2:18088",
          "repo: set 10.0.2.2:18088",
          "Repository index updated: 1 package(s), version 1",
          "repo: index version 1",
          "repo: sysinfo 1.0",
          "repo: selected sysinfo",
          "Installed sysinfo 1.0",
          "desktopreposettest returned"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
# Registry proofs: the post-desktop `pkg repo` output shows the URL
# the desktop Set stored, and the post-desktop `pkg list` shows the
# installed package (position-checked: after the test's return line,
# so these are the post-desktop outputs, not earlier prints).
ret_pos = log.find("desktopreposettest returned")
tail = log[ret_pos:] if ret_pos >= 0 else ""
f = "Repository: 10.0.2.2:18088" in tail
print(f"{'PASS' if f else 'FAIL'} pkg repo after desktop: stored URL"); ok = ok and f
f = "sysinfo 1.0" in tail
print(f"{'PASS' if f else 'FAIL'} pkg list after desktop: sysinfo 1.0"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
