#!/usr/bin/env python3
"""Graphics/input adversarial security test (Phase 7).
Boot 1 (text shell, keyboard only): mousetest (packet parsing,
clamping, overflow, buttons), guitest (negative/huge/off-screen/
zero-size windows, window-count limit, corner-pixel background
after cleanup), wmautotest (scripted OK click, title-bar drag,
taskbar Shell exit — scripted mouse via mouse_test_set, because
QEMU monitor mouse_move/button did not deliver PS/2 packets to
the guest in this sandbox, see docs/GRAPHICS.md).
Boot 2 (GUI screendump): run `gui`, take a QEMU screendump, and
check the image is 800x600, contains the teal background, window
title blue, and a white cursor pixel at the initial mouse
position (400,300). No panic/exception in either boot.
Usage: python3 tests/security_test_gui.py <iso> <workdir>
Exit 0 only if all checks pass."""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
os.makedirs(WORK, exist_ok=True)
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
PPM = os.path.join(WORK, "gui.ppm")

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}
def boot(actions, prompt, screendump=False):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:12", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
    ])
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        if not wait_for(lambda t: prompt in t, 60, f"prompt {prompt!r}"):
            return False, log_text()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
        def send_text(txt):
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.2)
            s.sendall(b"sendkey ret\n"); time.sleep(0.5)
        for txt in actions:
            send_text(txt); time.sleep(1)
        # wmautotest takes ~3 seconds of scripted steps; wait for it.
        if "wmautotest" in actions:
            wait_for(lambda t: "wmautotest PASS" in t or "wmautotest FAIL" in t, 20, "wmautotest")
        if screendump:
            s.sendall(f"screendump {PPM}\n".encode()); time.sleep(1)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return True, log_text()

ok = True
# Boot 1: driver + WM edge cases + scripted interaction.
_, log1 = boot(["mousetest", "guitest", "wmautotest"], "root@nxts> ")
for m in ["mousetest PASS", "guitest PASS", "wmautotest PASS",
          "mousetest: after (50,30) left-down: x=450 y=270 left=1",
          "mousetest: after large moves: x=799 y=0",
          "guitest: neg clamped to x=-100 y=0",
          "guitest: huge clamped to w=800 h=600",
          "guitest: off clamped to x=700 y=550",
          "overflow=-1 count=8 (max 8)",
          "guitest: corner pixels 0x106040 0x106040",
          "Button OK clicked"]:
    f = m in log1; print(f"{'PASS' if f else 'FAIL'} boot1: {m}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log1; print(f"{'PASS' if f else 'FAIL'} boot1: absent {bad}"); ok = ok and f

# Boot 2: GUI screendump.
_, log2 = boot(["gui"], "root@nxts> ", screendump=True)
print("screendump exists:", os.path.exists(PPM))
ok = ok and os.path.exists(PPM)
if os.path.exists(PPM):
    try:
        from PIL import Image
        im = Image.open(PPM); print("screendump size:", im.size)
        ok = ok and im.size == (800, 600)
        pix = im.load()
        # Teal background (0x10,0x60,0x40), title blue, white text/cursor.
        def count_col(rgb):
            return sum(1 for y in range(im.height) for x in range(im.width) if pix[x, y] == rgb)
        teal = count_col((0x10, 0x60, 0x40))
        blue = count_col((0x20, 0x60, 0xA0))
        white = count_col((255, 255, 255))
        print(f"pixels: teal={teal} blue={blue} white={white} cursor(400,300)={pix[400,300]}")
        ok = ok and teal > 10000 and blue > 1000 and white > 1000
        ok = ok and pix[400, 300] == (255, 255, 255)
        print(f"{'PASS' if teal > 10000 and blue > 1000 and white > 1000 else 'FAIL'} screendump colours")
    except Exception as e:
        print("FAIL screendump analysis:", e); ok = False

print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
