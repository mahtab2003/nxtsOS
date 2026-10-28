#!/usr/bin/env python3
"""Packages-window Remove test: a desktop-only user must be able
to uninstall a package without the shell.
Boot 1: pkg install calc.nxpkg + term.nxpkg (registry order calc,
term, so mode-11 row 1 is term). Boot 2: desktoppackageapptest —
the kernel autotest mode 11 script: Start, launcher Packages row,
Remove with no selection (refused), row 1 select (term), Remove
(confirm), Remove (removes term), Terminal icon (desktop exits).
The harness then runs `pkg list` on the shell and checks the
fresh output lists calc but not term — the registry proof, not
just the markers.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_packages_remove.py <iso> <workdir>
<workdir> is created by tests/qemu_test_packages_remove_setup.py.
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

ok = True
ok1, log1 = boot(["pkg install calc.nxpkg", "pkg install term.nxpkg"],
                 wait_marker="Installed term 1.0")
for m in ["Installed calc 1.0", "Installed term 1.0"]:
    f = m in log1; print(f"{'PASS' if f else 'FAIL'} install: {m}"); ok = ok and f
ok = ok and ok1

def post_desktop(send_text):
    # Mode 11 ends by clicking the Terminal icon, so the desktop
    # has exited and the shell is back; list what remains.
    time.sleep(3)
    send_text("pkg list"); time.sleep(2)

ok2, log2 = boot(["desktoppackageapptest"],
                 wait_marker="packages: removed term",
                 wait_timeout=60, post=post_desktop)
for m in ["Desktop: Packages opened",
          "packages: calc 1.0",
          "packages: term 1.0",
          "packages: remove needs selection",
          "packages: selected term",
          "packages: remove confirm term",
          "Removed term",
          "packages: removed term"]:
    f = m in log2; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
ok = ok and ok2
# Registry proof: the fresh `pkg list` output after the desktop
# exit lists calc and no longer lists term.
tail = log2[log2.rfind("pkg list"):]
f = "calc 1.0" in tail; print(f"{'PASS' if f else 'FAIL'} pkg list still has calc"); ok = ok and f
f = "term" not in tail; print(f"{'PASS' if f else 'FAIL'} pkg list no longer has term"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log2; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
