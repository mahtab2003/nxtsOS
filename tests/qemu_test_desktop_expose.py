#!/usr/bin/env python3
"""Bug B test (v1.1.2 real-device report): Calculator window goes blank
blue after a desktop redraw. Boot 1 (as root): install calc.nxpkg
from the security-setup disk. Boot 2 (as root): desktopexposetest
(mode 31) — click the Calc icon, click '7', force a full desktop
redraw, wait for the app tick, probe the display pixel, screendump.
The display pixel must still be white (post-fix: the app repaints
on EXPOSE); pre-fix it reads the desktop background.
Usage: python3 tests/qemu_test_desktop_expose.py <iso> <workdir>
<workdir> is created by tests/security_test_desktop_setup.py.
Exit 0 only if all checks pass."""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
PPM = os.path.join(WORK, "expose.ppm")

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

def boot(login_user, login_pass, actions, wait_marker=None, screendump=False):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:18", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
    ])
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        if not wait_for(lambda t: "login: " in t, 60, "login prompt"):
            return False, log_text()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON)
        try: s.recv(4096)
        except socket.timeout: pass
        def send_text(txt):
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(0.5)
        send_text(login_user); send_text(login_pass); time.sleep(1)
        for txt in actions:
            send_text(txt); time.sleep(1)
        if wait_marker:
            wait_for(lambda t: wait_marker in t, 60, wait_marker)
        if screendump:
            time.sleep(3)
            s.sendall(f"screendump {PPM}\n".encode()); time.sleep(1)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return True, log_text()

ok = True
_, log1 = boot("root", "rootpass", ["pkg install calc.nxpkg"],
               wait_marker="Installed calc 1.0")
f = "Installed calc 1.0" in log1; print(f"{'PASS' if f else 'FAIL'} install: Installed calc 1.0"); ok = ok and f

_, log2 = boot("root", "rootpass", ["desktopexposetest"],
               wait_marker="expose: pixel", screendump=True)
f = "expose: redraw forced" in log2; print(f"{'PASS' if f else 'FAIL'} expose: redraw forced"); ok = ok and f
f = "expose: pixel 0xFFFFFF" in log2; print(f"{'PASS' if f else 'FAIL'} expose: pixel 0xFFFFFF (display repainted)"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log2; print(f"{'PASS' if f else 'FAIL'} expose: absent {bad}"); ok = ok and f
print("screendump exists:", os.path.exists(PPM))
try:
    from PIL import Image
    im = Image.open(PPM); print("screendump size:", im.size)
    px = im.load()
    checks = [
        ("calc title bar (300,170)", px[300, 170][:3], (32, 96, 160)),
        ("calc display white after redraw (250,190)", px[250, 190][:3], (255, 255, 255)),
        ("calc key grey after redraw (260,260)", px[260, 260][:3], (192, 192, 192)),
    ]
    for name, got, want in checks:
        f = got == want; print(f"{'PASS' if f else 'FAIL'} screendump {name}: got {got} want {want}"); ok = ok and f
    f = im.size == (800, 600); print(f"{'PASS' if f else 'FAIL'} screendump size 800x600"); ok = ok and f
except Exception as e:
    print("FAIL screendump analysis:", e); ok = False
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
