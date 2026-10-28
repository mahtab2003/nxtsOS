#!/usr/bin/env python3
"""Redraw-storm test (post-v1.0.0 queue 6a).
Boot 1 (text shell, no disk): run `stormtest` — 40 deterministic
rounds of window open/move/close/minimise-restore, each checked
by the clip==full redraw invariant — plus the established
cliptest/cursortest as controls. Exit 0 only if all pass and
no EXCEPTION/PANIC/page fault appears.
Usage: python3 tests/qemu_test_storm.py <iso> <workdir>"""
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
    "-display", "vnc=:14", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
])
ok = True
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
        ok = False
    else:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
        def send_text(txt):
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.2)
            s.sendall(b"sendkey ret\n"); time.sleep(0.5)
        for txt in ["cliptest", "cursortest", "stormtest"]:
            send_text(txt); time.sleep(1)
        wait_for(lambda t: "stormtest PASS" in t or "stormtest FAIL" in t, 60, "stormtest")
        s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

log = log_text()
for m in ["cliptest PASS", "cursortest PASS", "stormtest PASS"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} boot1: {m}"); ok = ok and f
for line in log.splitlines():
    if line.startswith("stormtest:"):
        print("stormtest summary:", line)
for bad in ["EXCEPTION", "PANIC", "page fault", "stormtest FAIL"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} boot1: absent {bad}"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
