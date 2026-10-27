#!/usr/bin/env python3
"""Phase 10 polish test (v0.10.0, mode 4).
Boot (text shell, no disk): desktop10test — Settings icon ->
Appearance toggle -> Theme value (Classic -> Dark) -> Save ->
workspace button (WS1 -> WS2, pixel must be the dark desktop bg) ->
back to WS1 (pixel must be Settings client grey) -> '[' snaps the
Settings window left -> '\' restores it.
Usage: python3 tests/qemu_test_desktop10.py <iso> <workdir>
Exit 0 only if all checks pass."""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
os.makedirs(WORK, exist_ok=True)
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
    "-display", "vnc=:17", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
        print("RESULT: FAIL"); sys.exit(1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
    # Monitor sendkey occasionally delivers a doubled key (seen as
    # "desktoop10test" / "desktop10testt"); retry once on Unknown.
    for _attempt in range(2):
        before = len(log_text())
        for ch in "desktop10test":
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.2)
        s.sendall(b"sendkey ret\n"); time.sleep(1)
        if "Unknown command" not in log_text()[before:]:
            break
    wait_for(lambda t: "p10: restored x=160 w=480" in t, 60, "desktop10test")
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

ok = True
log = log_text()
for m in ["Desktop theme changed to Dark",
          "p10: ws2 pixel 0x101010",
          "p10: ws1 pixel 0xD0D0D0",
          "p10: snapped x=0 w=400",
          "p10: restored x=160 w=480"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} {m}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} absent {bad}"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
