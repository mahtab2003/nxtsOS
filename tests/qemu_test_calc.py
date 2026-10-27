#!/usr/bin/env python3
"""Calculator GUI application test (Phase 8).
Boot 1 (as root): install calc.nxpkg from the security-setup disk.
Boot 2 (as root): desktopcalctest — click the Calc icon, then click
the '7' key, screendump, and check: the Calculator title bar, the
white display area, a grey key, and the black-pixel count of the
display glyph against the font data (the display must show '7',
not the initial '0'). The expected glyph count is computed from
kernel/font_data.h, not hard-coded.
Usage: python3 tests/qemu_test_calc.py <iso> <workdir>
<workdir> is created by tests/security_test_desktop_setup.py.
Exit 0 only if all checks pass."""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
PPM = os.path.join(WORK, "calc.ppm")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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
        "-display", "vnc=:16", "-serial", f"file:{SERIAL}",
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
            wait_for(lambda t: wait_marker in t, 30, wait_marker)
        if screendump:
            time.sleep(3)
            s.sendall(f"screendump {PPM}\n".encode()); time.sleep(1)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return True, log_text()

def glyph_bits(ch):
    text = open(os.path.join(ROOT, "kernel", "font_data.h")).read()
    glyphs = re.findall(r"\{((?:0x[0-9a-f]+,?)+)\}", text)
    assert len(glyphs) == 256, f"font glyphs: {len(glyphs)}"
    row = [int(x, 16) for x in glyphs[ord(ch)].split(",")]
    return sum(bin(b).count("1") for b in row)

ok = True
_, log1 = boot("root", "rootpass", ["pkg install calc.nxpkg"],
               wait_marker="Installed calc 1.0")
f = "Installed calc 1.0" in log1; print(f"{'PASS' if f else 'FAIL'} install: Installed calc 1.0"); ok = ok and f

_, log2 = boot("root", "rootpass", ["desktopcalctest"],
               wait_marker="Calculator started", screendump=True)
f = "Calculator started" in log2; print(f"{'PASS' if f else 'FAIL'} calc: Calculator started"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log2; print(f"{'PASS' if f else 'FAIL'} calc: absent {bad}"); ok = ok and f
print("screendump exists:", os.path.exists(PPM))
try:
    from PIL import Image
    im = Image.open(PPM); print("screendump size:", im.size)
    px = im.load()
    checks = [
        ("calc title bar (300,170)", px[300, 170][:3], (32, 96, 160)),
        ("calc display white (250,190)", px[250, 190][:3], (255, 255, 255)),
        ("calc key grey (260,260)", px[260, 260][:3], (192, 192, 192)),
    ]
    for name, got, want in checks:
        f = got == want; print(f"{'PASS' if f else 'FAIL'} screendump {name}: got {got} want {want}"); ok = ok and f
    # Display glyph: text at absolute (253,193), 8x16 cell, black on white.
    black = 0
    for yy in range(193, 209):
        for xx in range(253, 261):
            if px[xx, yy][:3] == (0, 0, 0): black += 1
    want7 = glyph_bits("7"); want0 = glyph_bits("0")
    print(f"display glyph black pixels: {black} (expected '7'={want7}, initial '0'={want0})")
    f = black == want7; print(f"{'PASS' if f else 'FAIL'} display shows '7'"); ok = ok and f
    f = im.size == (800, 600); print(f"{'PASS' if f else 'FAIL'} screendump size 800x600"); ok = ok and f
except Exception as e:
    print("FAIL screendump analysis:", e); ok = False
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
