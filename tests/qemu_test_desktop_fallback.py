#!/usr/bin/env python3
"""Desktop fallback-redraw test (v1.1.0 real-device bug): with a
real PS/2 mouse, cursor_move_only's fallback could fire inside
the desktop loop (saved cursor position != loop's prev, after an
interrupt moved the pointer mid-iteration). Pre-fix the fallback
ran the CLASSIC redraw unconditionally: green background
0x00106040, classic "Shell" taskbar, window frames with no
desktop content — the user's "green screen". Post-fix the
fallback dispatches on the active UI and runs a full desktop
redraw.

Mode 30 opens the Web window via the launcher, then forces the
fallback with a stale old position (0,0) while the saved cursor
sits at the Web row (300,432), and samples the scene in the
SAME step (before any clock refresh can repaint over it):
  fb30: saved=(300,432) bg=0x183050 green=0 web=1
Wait condition (hardened for the 1.1.3 ship gate): the harness
waits for the FULL fb30 line in the serial log before
terminating QEMU. Waiting only for the "fb30:" prefix let a
timer tick suspend the print mid-line while the harness's poll
observed prefix-only and killed QEMU, truncating the verdict
line — a harness race, not a kernel bug. If the full line never
arrives within the timeout, the test FAILS (fail closed).
Assertions: saved proves the fallback path was really taken
(not the restore path); bg must be the Classic desktop
background (NOT green); green is a strided full-frame count of
exact 0x00106040 pixels (the bug paints the whole screen, so a
stride-2 scan is decisive); web proves the window survived.

Usage: qemu_test_desktop_fallback.py <iso> <workdir>
Exit 0 only if all checks pass. Always terminates QEMU.
"""
import os
import re
import socket
import subprocess
import sys
import time

ISO, WORK = sys.argv[1:3]
os.makedirs(WORK, exist_ok=True)
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

# Full verdict line, reused as the wait predicate: QEMU is only
# terminated once this matches, so the verdict line can never be
# cut mid-print by the harness itself.
FB30_RE = re.compile(r"fb30: saved=\((-?\d+),(-?\d+)\) bg=0x([0-9a-f]+) "
                     r"green=(\d+) web=(\d+)")


def log_text():
    try:
        return open(SERIAL, errors="replace").read()
    except FileNotFoundError:
        return ""


def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()):
            return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}")
    return False


for p in (SERIAL, MON):
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "vnc=:23", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
])
ok = True
try:
    for _ in range(100):
        if os.path.exists(MON):
            break
        time.sleep(0.1)
    if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
        ok = False
    else:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(MON)
        s.recv(4096)
        for ch in "desktopfallbacktest":
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode())
            time.sleep(0.2)
        s.sendall(b"sendkey ret\n")
        if not wait_for(lambda t: FB30_RE.search(t) is not None, 60,
                        "full fb30 line"):
            ok = False
        s.close()
finally:
    qemu.terminate()
    try:
        qemu.wait(timeout=10)
    except subprocess.TimeoutExpired:
        qemu.kill()

log = log_text()
m = FB30_RE.search(log)
if not m:
    print("FAIL: no fb30 marker in serial log")
    ok = False
else:
    sx, sy, bg, green, web = int(m.group(1)), int(m.group(2)), \
        int(m.group(3), 16), int(m.group(4)), int(m.group(5))
    print(f"fb30: saved=({sx},{sy}) bg=0x{bg:x} green={green} web={web}")
    checks = [
        ("fallback really taken (saved == Web row 300,432)",
         (sx, sy) == (300, 432)),
        ("background is Classic desktop bg, not green",
         bg == 0x183050),
        ("no green pixels in strided full-frame scan", green == 0),
        ("Web window present after fallback", web == 1),
    ]
    for label, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}: {label}")
        ok = ok and passed
for bad in ("EXCEPTION", "PANIC", "page fault"):
    f = bad not in log
    print(f"{'PASS' if f else 'FAIL'}: absent {bad}")
    ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
