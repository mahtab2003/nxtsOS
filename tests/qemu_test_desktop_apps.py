#!/usr/bin/env python3
"""Phase 10 apps test (v0.10.0, mode 5).
Boot 1 (setup mode, no login): install calc.nxpkg + term.nxpkg.
Boot 2: desktopappstest — launcher column 2 (Editor, Monitor,
Network, Web, Viewer, Console), then Files: notes.txt -> Editor,
close Editor, pic.bmp -> Viewer.
Usage: python3 tests/qemu_test_desktop_apps.py <iso> <workdir>
<workdir> is created by tests/qemu_test_desktop_apps_setup.py.
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

def boot(actions, wait_marker=None):
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
        if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
            return False, log_text()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
        def send_text(txt):
            # Monitor sendkey occasionally doubles a key; retry once
            # if the shell reports the mistyped command as unknown.
            for _attempt in range(2):
                before = len(log_text())
                for ch in txt:
                    s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
                s.sendall(b"sendkey ret\n"); time.sleep(1)
                if "Unknown command" not in log_text()[before:]:
                    break
        for txt in actions:
            send_text(txt); time.sleep(1)
        if wait_marker:
            wait_for(lambda t: wait_marker in t, 60, wait_marker)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return True, log_text()

ok = True
_, log1 = boot(["pkg install calc.nxpkg", "pkg install term.nxpkg"],
               wait_marker="Installed term 1.0")
for m in ["Installed calc 1.0", "Installed term 1.0"]:
    f = m in log1; print(f"{'PASS' if f else 'FAIL'} install: {m}"); ok = ok and f

_, log2 = boot(["desktopappstest"], wait_marker="viewer: opened pic.bmp 64x64")
for m in ["Desktop notification: Console started",
          "term: window opened",
          "editor: opened notes.txt",
          "viewer: opened pic.bmp 64x64"]:
    f = m in log2; print(f"{'PASS' if f else 'FAIL'} apps: {m}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log2; print(f"{'PASS' if f else 'FAIL'} apps: absent {bad}"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
