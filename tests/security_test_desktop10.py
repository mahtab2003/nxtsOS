#!/usr/bin/env python3
"""Phase 10 adversarial app test (v0.10.0, mode 6).
Boot (setup mode, no login): desktop10sec — garbage settings.txt
must be rejected at load (out-of-range theme/wallpaper ignored,
non-numeric values skipped, desktop still starts); evil.txt must
be sanitised on Editor load; empty.txt must open as 0 bytes;
big.bmp (200x200 header, no pixels) must be refused as oversize
before any pixel read; good.bmp must open.
Usage: python3 tests/security_test_desktop10.py <iso> <workdir>
<workdir> is created by tests/qemu_test_desktop10sec_setup.py.
Exit 0 only if all checks pass."""
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
    "-display", "vnc=:19", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
        print("RESULT: FAIL"); sys.exit(1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
    for _attempt in range(2):
        before = len(log_text())
        for ch in "desktop10sec":
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(1)
        if "Unknown command" not in log_text()[before:]:
            break
    wait_for(lambda t: "viewer: opened good.bmp 64x64" in t, 60, "desktop10sec")
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

ok = True
log = log_text()
for m in ["settings: ignored invalid theme=99",
          "settings: ignored invalid wallpaper=5",
          "editor: sanitized 4 bytes in evil.txt",
          "editor: opened evil.txt",
          "editor: opened empty.txt 0 bytes",
          "viewer: refused big.bmp (oversize 200x200, cap 128x128)",
          "viewer: opened good.bmp 64x64"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} {m}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} absent {bad}"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
