#!/usr/bin/env python3
"""Phase 8 desktop test (v0.8.0).
Boot 1 (text shell, no disk): cliptest (clip redraw == full redraw),
cursortest, desktopautotest (scripted Settings icon -> Idle value
button -> Start -> Lock entry -> Enter unlock in setup mode ->
Terminal icon exit). Boot 2: run `desktop`, screendump, check the
desktop background, Settings icon, taskbar and cursor pixels.
Usage: python3 tests/qemu_test_desktop.py <iso> <workdir>
Exit 0 only if all checks pass."""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
os.makedirs(WORK, exist_ok=True)
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
PPM = os.path.join(WORK, "desktop.ppm")

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

def boot(actions, screendump=False):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:14", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
    ])
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
            return False, log_text()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
        def send_text(txt):
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.2)
            s.sendall(b"sendkey ret\n"); time.sleep(0.5)
        for txt in actions:
            send_text(txt); time.sleep(1)
        if "desktopautotest" in actions:
            wait_for(lambda t: "desktopautotest PASS" in t or "desktopautotest FAIL" in t, 30, "desktopautotest")
        if screendump:
            time.sleep(1)
            s.sendall(f"screendump {PPM}\n".encode()); time.sleep(1)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return True, log_text()

ok = True
_, log1 = boot(["cliptest", "cursortest", "desktopautotest"])
for m in ["cliptest PASS", "cursortest PASS", "desktopautotest PASS",
          "Desktop setting idle changed to", "Desktop: lock screen shown",
          "Desktop: unlocked (setup mode, no password)",
          "Desktop notification: Welcome to nxtsOS desktop"]:
    f = m in log1; print(f"{'PASS' if f else 'FAIL'} boot1: {m}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log1; print(f"{'PASS' if f else 'FAIL'} boot1: absent {bad}"); ok = ok and f

_, log2 = boot(["desktop"], screendump=True)
print("screendump exists:", os.path.exists(PPM))
try:
    from PIL import Image
    im = Image.open(PPM); print("screendump size:", im.size)
    px = im.load()
    checks = [
        ("background (700,300)", px[700, 300], (24, 48, 80)),
        ("Settings icon (40,40)", px[40, 40], (32, 96, 160)),
        ("Start button (10,588)", px[10, 588], (96, 96, 96)),
        ("cursor (400,300)", px[400, 300], (255, 255, 255)),
    ]
    for name, got, want in checks:
        got3 = got[:3] if isinstance(got, tuple) else got
        f = got3 == want; print(f"{'PASS' if f else 'FAIL'} screendump {name}: got {got3} want {want}"); ok = ok and f
    f = im.size == (800, 600); print(f"{'PASS' if f else 'FAIL'} screendump size 800x600"); ok = ok and f
except Exception as e:
    print("FAIL screendump analysis:", e); ok = False
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
