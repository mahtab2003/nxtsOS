#!/usr/bin/env python3
"""Desktop Reboot test: a desktop-only user must be able to
reboot without the shell.
Single QEMU run (a reboot does not exit QEMU, it resets the
machine): boot, run desktopreboottest — the kernel autotest
mode 15 script: Start, launcher Reboot row (first click only
arms, "desktop: reboot confirm"), Start again, Reboot row
again (confirming click, "desktop: rebooting", keyboard
controller reset). The harness then waits for the shell
prompt to appear a SECOND time in the same serial log —
the second boot, not just the markers: a failed reset would
halt forever and never print it.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_desktop_reboot.py <iso> <workdir>
<workdir> is created by tests/qemu_test_desktop_reboot_setup.py.
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
    if not wait_for(lambda t: "root@nxts> " in t, 60, "first prompt"):
        ok = False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
    def send_text(txt):
        for _attempt in range(2):
            before = len(log_text())
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            if "Unknown command" not in log_text()[before:]:
                break
    if ok:
        send_text("desktopreboottest"); time.sleep(1)
        ok = wait_for(lambda t: "desktop: reboot confirm" in t, 60, "reboot confirm") and ok
        ok = wait_for(lambda t: "desktop: rebooting" in t, 60, "rebooting") and ok
        # Second-boot proof: the prompt appears a second time in
        # the same log (the first boot printed it once already).
        ok = wait_for(lambda t: t.count("root@nxts> ") >= 2, 60, "second prompt") and ok
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

log = log_text()
for m in ["desktop: reboot confirm", "desktop: rebooting"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
f = log.count("root@nxts> ") >= 2
print(f"{'PASS' if f else 'FAIL'} second boot prompt (count={log.count('root@nxts> ')})"); ok = ok and f
f = "desktopreboottest returned" not in log
print(f"{'PASS' if f else 'FAIL'} autotest did not return (reboot happened)"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
