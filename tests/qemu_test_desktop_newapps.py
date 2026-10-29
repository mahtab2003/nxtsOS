#!/usr/bin/env python3
"""New-apps test (apps run): Calendar, Stopwatch, Notes.

Builds its own disk (users root/user + settings), boots, logs in
as root, runs desktopnewappstest (mode 33): launcher column 3
opens each app, paints (button-fill + client-grey pixel probes),
acts (Calendar Prev/Next/day-15 select, Stopwatch Start/Lap/
Stop, Notes type + Enter + select + Delete), closes each app,
and re-opens Calendar (repeated-open proof). The harness checks
the serial markers + pixel probes + screendump presence.
Usage: python3 tests/qemu_test_desktop_newapps.py <iso> <workdir>
Exit 0 only if all checks pass. QEMU is always terminated.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
PPM = os.path.join(WORK, "newapps.ppm")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

os.makedirs(WORK, exist_ok=True)
run(["python3", os.path.join(ROOT, "tools", "mkuser.py"),
     os.path.join(WORK, "users.txt"),
     "--user", "root:0:rootpass", "--user", "user:1000:userpass"])
open(os.path.join(WORK, "settings.txt"), "w").write("idle=120\nmouse=1\nclock=1\nicons=1\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     DISK,
     "--add", f"users.txt:{os.path.join(WORK, 'users.txt')}:600:0",
     "--add", f"settings.txt:{os.path.join(WORK, 'settings.txt')}:600:0"])

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
    "-display", "vnc=:21", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    if not wait_for(lambda t: "login: " in t, 60, "login prompt"):
        print("RESULT: FAIL"); sys.exit(1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2); s.connect(MON)
    try: s.recv(4096)
    except socket.timeout: pass
    def send_text(txt):
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(0.5)
    send_text("root"); send_text("rootpass"); time.sleep(1)
    send_text("desktopnewappstest")
    wait_for(lambda t: "newapps: done" in t, 180, "newapps: done")
    time.sleep(3)
    s.sendall(f"screendump {PPM}\n".encode()); time.sleep(1)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

ok = True
log = log_text()
for m in [
    "Desktop: Calendar opened",
    "calendar: shown",
    "calendar: selected 15/",
    "Desktop: Stopwatch opened",
    "stopwatch: started",
    "stopwatch: lap 1 ",
    "stopwatch: stopped",
    "Desktop: Notes opened",
    "notes: loaded 0",
    "notes: added",
    "notes: selected 0",
    "notes: deleted",
    "Window closed: Calendar",
    "Window closed: Stopwatch",
    "Window closed: Notes",
    "newapps: calendar px button=0xE0E0E0 grey=0xD0D0D0",
    "newapps: stopwatch px button=0xE0E0E0",
    "newapps: stopwatch px grey=0xD0D0D0",
    "newapps: notes px button=0xE0E0E0",
    "newapps: done",
]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} serial: {m[:60]}"); ok = ok and f
# Repeated open: Calendar must open twice.
n = log.count("Desktop: Calendar opened")
f = n >= 2; print(f"{'PASS' if f else 'FAIL'} serial: Calendar opened count {n} (expect >= 2)"); ok = ok and f
# Calendar navigation: open + Prev + Next = at least 3 shown markers.
n = log.count("calendar: shown")
f = n >= 3; print(f"{'PASS' if f else 'FAIL'} serial: calendar shown count {n} (expect >= 3)"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} serial: absent {bad}"); ok = ok and f
f = os.path.exists(PPM); print(f"{'PASS' if f else 'FAIL'} screendump exists"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
