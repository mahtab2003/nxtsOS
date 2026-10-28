#!/usr/bin/env python3
"""Files-window Install test: a desktop-only user must be able
to install a package file sitting on disk without the shell.
Single boot: desktopfileinstalltest — the kernel autotest
mode 12 script: Files icon, row 0 select (the disk holds only
calc.nxpkg, so row 0 is certainly it), Open (installs calc),
row 0 select again, Open again (already-installed refusal),
Terminal icon (desktop exits). The harness then runs `pkg list`
on the shell and checks the fresh output lists calc — the
registry proof, not just the markers.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_files_install.py <iso> <workdir>
<workdir> is created by tests/qemu_test_files_install_setup.py.
The sender verifies the shell's echo of each command and
retypes once on mismatch (the QEMU sendkey-doubling flake
class from the repo test); login typing is not echoed.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

def boot(actions, wait_marker=None, wait_timeout=60, post=None):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:21", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
    ])
    ok = True
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
            return False, log_text()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
        def send_text(txt):
            for _attempt in range(2):
                before = len(log_text())
                for ch in txt:
                    s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
                s.sendall(b"sendkey ret\n"); time.sleep(1)
                if "Unknown command" not in log_text()[before:]:
                    break
        for txt in actions:
            send_text(txt); time.sleep(1)
        if wait_marker:
            ok = wait_for(lambda t: wait_marker in t, wait_timeout, wait_marker)
        if post:
            post(send_text)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return ok, log_text()

def post_desktop(send_text):
    # Mode 12 ends by clicking the Terminal icon, so the desktop
    # has exited and the shell is back; list what is installed.
    time.sleep(3)
    send_text("pkg list"); time.sleep(2)

ok = True
ok1, log1 = boot(["desktopfileinstalltest"],
                 wait_marker="files: installed calc.nxpkg",
                 wait_timeout=60, post=post_desktop)
for m in ["Desktop: Files opened",
          "Installed calc 1.0",
          "files: installed calc.nxpkg",
          "pkg: package already installed (same version)"]:
    f = m in log1; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
ok = ok and ok1
# Registry proof: the fresh `pkg list` output after the desktop
# exit lists calc.
tail = log1[log1.rfind("pkg list"):]
f = "calc 1.0" in tail; print(f"{'PASS' if f else 'FAIL'} pkg list has calc"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log1; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
