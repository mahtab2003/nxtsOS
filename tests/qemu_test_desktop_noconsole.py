#!/usr/bin/env python3
"""Bug C test (v1.1.2 real-device report): shell text bleeds onto the
desktop background. Boot (no disk, setup mode root):
desktopnoconsoletest (mode 32) — sample the framebuffer, print
console marker lines (which pre-fix painted glyphs over the
wallpaper), sample again. Post-fix both samples match (console
output is suppressed during desktop); pre-fix they differ.
Usage: python3 tests/qemu_test_desktop_noconsole.py <iso> <workdir>
Exit 0 only if all checks pass."""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
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
    "-display", "vnc=:19", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
        print("RESULT: FAIL"); sys.exit(1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
    def send_text(txt):
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.2)
        s.sendall(b"sendkey ret\n"); time.sleep(1)
    send_text("desktopnoconsoletest")
    wait_for(lambda t: "noconsole: SAME" in t or "noconsole: DIFF" in t, 60, "noconsole marker")
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

ok = True
log = log_text()
f = "noconsole: SAME" in log; print(f"{'PASS' if f else 'FAIL'} noconsole: SAME (framebuffer unchanged by console output)"); ok = ok and f
f = "noconsole: DIFF" not in log; print(f"{'PASS' if f else 'FAIL'} noconsole: absent DIFF"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} noconsole: absent {bad}"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
