#!/usr/bin/env python3
"""v0.7.1 bugfix test: fbinfo, idle setting, logout/login cycle,
plus GUI commands (guitest/mousetest/wmautotest) on the normal boot.
Usage: python3 tests/qemu_test_v071.py <iso> <workdir>
Exit 0 only if all markers are found in the serial log."""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
os.makedirs(WORK, exist_ok=True)
SERIAL = os.path.join(WORK, "serial.log"); MON = os.path.join(WORK, "mon.sock")
for p in (SERIAL, MON):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen(["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "vnc=:13", "-serial", f"file:{SERIAL}", "-monitor", f"unix:{MON},server,nowait"])
def text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(text()): return True
        time.sleep(0.1)
    print("TIMEOUT:", label); return False
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}
ok = True
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    if not wait_for(lambda t: "root@nxts> " in t, 60, "shell prompt"):
        print("RESULT: FAIL"); sys.exit(1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
    def send(txt):
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(0.5)
    for cmd in ["fbinfo", "guitest", "mousetest", "idle", "idle 5", "idle", "idle off", "idle", "idle 120", "logout"]:
        send(cmd); time.sleep(1)
    # wmautotest takes ~3 s of scripted steps
    send("wmautotest")
    wait_for(lambda t: "wmautotest PASS" in t or "wmautotest FAIL" in t, 20, "wmautotest")
    # After logout (setup mode), the shell must return to a working prompt:
    wait_for(lambda t: t.count("Welcome to nxtsOS") >= 2, 20, "second welcome after logout")
    send("mem")
    time.sleep(1)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = text()
for m in ["Framebuffer: 800x600", "guitest PASS", "mousetest PASS",
          "Idle timeout: 120 minutes", "Idle timeout set to 5 minutes",
          "Idle timeout: 5 minutes", "Idle lock disabled for this session",
          "Idle timeout: disabled", "Idle timeout set to 120 minutes",
          "Logged out.", "Memory: total", "wmautotest PASS"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'}: {m}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'}: absent {bad}"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
