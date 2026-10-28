#!/usr/bin/env python3
"""Shell echo / cursor visibility test (v1.1.0 real-device bug):
in framebuffer text mode, console_putchar's fast path drew typed
characters and the inverted cursor cell into the BACK buffer but
never presented them, so on a real display the shell showed a
frozen screen: typed commands and the cursor never appeared
(serial always worked, which is why sandbox serial-only tests
never caught it). After the fix, each typed character presents
its cell(s).

Two boots (VNC screendump ground truth, not serial):
  boot1: plain text shell (setup mode, no disk): screendump,
         type "whoami", screendump again. The second image must
         contain substantially more white pixels (echo + output
         + new prompt) and at least one fully-white 8x16 cell
         (the inverted cursor on an empty cell). Pre-fix the two
         images are pixel-identical (nothing ever presents).
  boot2: desktopautotest (ends with the Terminal-icon exit back
         to the shell, i.e. the desktop -> shell path the user
         reported), then the same type + screendump checks.

Usage: qemu_test_shell_echo.py <iso> <workdir>
Exit 0 only if all checks pass. Always terminates QEMU.
"""
import os
import socket
import subprocess
import sys
import time

ISO, WORK = sys.argv[1:3]
os.makedirs(WORK, exist_ok=True)
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}


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


def boot2(actions, dumps):
    """Boot, run actions, screendump before typing whoami and
    after. actions are typed first (e.g. desktopautotest)."""
    for p in (SERIAL, MON):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:22", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
    ])
    try:
        for _ in range(100):
            if os.path.exists(MON):
                break
            time.sleep(0.1)
        if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
            return False
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(MON)
        s.recv(4096)

        def send_text(txt):
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode())
                time.sleep(0.2)
            s.sendall(b"sendkey ret\n")
            time.sleep(0.5)

        def dump(path):
            time.sleep(1)
            s.sendall(f"screendump {path}\n".encode())
            time.sleep(1)

        for act in actions:
            send_text(act)
            if act == "desktopautotest":
                if not wait_for(lambda t: "desktopautotest PASS" in t
                                or "desktopautotest FAIL" in t, 30,
                                "autotest"):
                    return False
                time.sleep(1)
        dump(dumps[0])
        send_text("whoami")
        time.sleep(2)
        dump(dumps[1])
        s.close()
    finally:
        qemu.terminate()
        try:
            qemu.wait(timeout=10)
        except subprocess.TimeoutExpired:
            qemu.kill()
    return True


def analyze(before_path, after_path, label):
    from PIL import Image
    ok = True
    try:
        b = Image.open(before_path).convert("RGB")
        a = Image.open(after_path).convert("RGB")
    except Exception as e:
        print(f"FAIL {label}: cannot read screendumps: {e}")
        return False
    print(f"{label}: size before={b.size} after={a.size}")
    if b.size != (800, 600) or a.size != (800, 600):
        print(f"FAIL {label}: unexpected screendump size")
        return False
    bp, ap = b.load(), a.load()
    # Pre-fix signature: the screen NEVER presents, so the two
    # dumps are pixel-identical. Any live display differs.
    if b.tobytes() == a.tobytes():
        print(f"FAIL {label}: screendumps identical (screen frozen)")
        return False
    print(f"PASS {label}: screen changed after typing")

    def row_sig(px, r):
        y = r * 16
        return tuple(px[x, y + dy] for dy in range(16)
                     for x in range(0, 800, 4))

    def full_row(px, r):
        y0 = r * 16
        return sum(1 for y in range(y0, y0 + 16) for x in range(800)
                   if px[x, y][0] > 200 and px[x, y][1] > 200
                   and px[x, y][2] > 200)

    # Scroll coherence: after must equal before scrolled by k
    # text rows (typing "whoami" + output adds lines; a full
    # boot log scrolls). A coherent scroll proves the display
    # is live, not garbage.
    best_k, best_m = 0, -1
    for k in range(0, 5):
        m = sum(1 for r in range(0, 25 - k)
                if row_sig(bp, r + k) == row_sig(ap, r))
        if m > best_m:
            best_k, best_m = k, m
    print(f"{label}: best scroll k={best_k} matching rows={best_m}/25")
    if best_m < 20:
        print(f"FAIL {label}: after image is not a coherent scroll "
              f"of before")
        ok = False
    else:
        print(f"PASS {label}: coherent scroll (display live)")
    # Echo proof: some row gained white pixels vs its scrolled
    # counterpart (the typed "whoami" on the prompt row), or a
    # brand-new bottom row has content (output / fresh prompt).
    gain = 0
    for r in range(0, 25 - best_k):
        gain = max(gain, full_row(ap, r) - full_row(bp, r + best_k))
    for r in range(25 - best_k, 25):
        gain = max(gain, full_row(ap, r))
    print(f"{label}: max row white gain={gain}")
    if gain < 40:
        print(f"FAIL {label}: no row gained text (echo not visible)")
        ok = False
    else:
        print(f"PASS {label}: typed text visible (echo gain)")
    # Cursor: a fully-white 8x16 cell (inverted cursor on an
    # empty cell) must exist in the after image.
    found = False
    for y in range(0, 600 - 15, 16):
        for x in range(0, 800 - 7, 8):
            allwhite = True
            for dy in range(16):
                for dx in range(8):
                    r, g, bl = ap[x + dx, y + dy]
                    if not (r > 200 and g > 200 and bl > 200):
                        allwhite = False
                        break
                if not allwhite:
                    break
            if allwhite:
                found = True
                break
        if found:
            break
    print(f"{'PASS' if found else 'FAIL'} {label}: "
          f"inverted cursor cell {'found' if found else 'missing'}")
    ok = ok and found
    for bad in ("EXCEPTION", "PANIC", "page fault"):
        if bad in log_text():
            print(f"FAIL {label}: forbidden marker {bad}")
            ok = False
    return ok


ok = True
b1 = os.path.join(WORK, "echo1-before.ppm")
a1 = os.path.join(WORK, "echo1-after.ppm")
if not boot2([], [b1, a1]):
    print("FAIL boot1: did not reach prompt")
    ok = False
else:
    ok = analyze(b1, a1, "boot1-plain-shell") and ok
b2 = os.path.join(WORK, "echo2-before.ppm")
a2 = os.path.join(WORK, "echo2-after.ppm")
if not boot2(["desktopautotest"], [b2, a2]):
    print("FAIL boot2: desktopautotest did not finish")
    ok = False
else:
    if "desktopautotest PASS" not in log_text():
        print("FAIL boot2: desktopautotest did not PASS")
        ok = False
    ok = analyze(b2, a2, "boot2-after-desktop-exit") and ok
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
