#!/usr/bin/env python3
"""Packages-window Rollback test: a desktop-only user must be able
to undo the last system update without the shell.
Boot 1: shell `sysupdate bundle_good.nxupd` installs greet 1.0 +
hello 1.0 and leaves a rollback snapshot on disk. Boot 2:
desktoprollbacktest — the kernel autotest mode 18 script: Start,
launcher Packages row, Rollback (arms the two-click confirm),
Rollback (rolls back), Rollback (arms again), Rollback (refused:
no snapshot left — the negative control proving the first
rollback really consumed it), Terminal icon (desktop exits).
The harness then runs `pkg list` on the shell and checks the
fresh output reports no packages installed — the registry proof,
not just the markers.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_packages_rollback.py <iso> <workdir>
<workdir> is created by tests/qemu_test_packages_rollback_setup.py.
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
    # Mode 18 ends on the Terminal icon, so the desktop has
    # exited and the shell prompt is back; list the packages.
    time.sleep(4)
    send_text("pkg list"); time.sleep(2)

ok = True
ok1, log1 = boot(["sysupdate bundle_good.nxupd"],
                 wait_marker="System update complete: 2 package(s)",
                 wait_timeout=90)
print(f"{'PASS' if ok1 else 'FAIL'} boot 1: shell sysupdate leaves snapshot"); ok = ok and ok1

ok2, log2 = boot(["desktoprollbacktest"],
                 wait_marker="desktoprollbacktest returned",
                 wait_timeout=90, post=post_desktop)
for m in ["Desktop: Packages opened",
          "packages: greet 1.0",
          "packages: hello 1.0",
          "packages: rollback confirm",
          "Rolled back to the previous version",
          "packages: rollback done",
          "sysrollback: no update to roll back",
          "packages: rollback failed",
          "desktoprollbacktest returned"]:
    f = m in log2; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
ok = ok and ok2
# Registry proof: the fresh `pkg list` output after the desktop
# exit reports no packages (position-checked: after the test's
# return line, so it is the post-desktop list, not an earlier
# print). A leftover greet/hello line after that point fails.
ret_pos = log2.find("desktoprollbacktest returned")
tail = log2[ret_pos:] if ret_pos >= 0 else ""
f = "(no packages installed)" in tail
print(f"{'PASS' if f else 'FAIL'} pkg list after desktop: no packages installed"); ok = ok and f
f = "greet 1.0" not in tail and "hello 1.0" not in tail
print(f"{'PASS' if f else 'FAIL'} pkg list after desktop: no greet/hello left"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log2; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
