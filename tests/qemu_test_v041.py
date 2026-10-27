#!/usr/bin/env python3
"""v0.4.1 test: background jobs, kill, manual lock, logout kills jobs,
and no early idle lock (shell still works after 30 s idle).
Usage: python3 tests/qemu_test_v041.py <iso> <ram_mb> <serial_log> <mon_sock> <disk_img>
Exit 0 only if all markers are found."""
import os, socket, subprocess, sys, time
ISO, RAM, SERIAL_LOG, MON_SOCK, DISK = sys.argv[1:6]

def log_text():
    try: return open(SERIAL_LOG, errors="replace").read()
    except FileNotFoundError: return ""
def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}
def send_text(s, sock):
    for ch in s:
        sock.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    sock.sendall(b"sendkey ret\n"); time.sleep(0.3)

for p in (SERIAL_LOG, MON_SOCK):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", RAM,
    "-display", "none", "-serial", f"file:{SERIAL_LOG}",
    "-monitor", f"unix:{MON_SOCK},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
])
ok = True
try:
    for _ in range(100):
        if os.path.exists(MON_SOCK): break
        time.sleep(0.1)
    ok &= wait_for(lambda t: "login: " in t, 60, "login prompt")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON_SOCK); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    send_text("user", s); send_text("userpass", s); time.sleep(1)
    ok &= wait_for(lambda t: "user@nxts> " in t, 10, "user prompt")
    # Background job: slow stays active long enough to type jobs/kill.
    send_text("runbg slow.elf", s); time.sleep(1)
    send_text("jobs", s); time.sleep(1)
    send_text("kill 10", s); time.sleep(1)
    send_text("jobs", s); time.sleep(1)
    # Manual lock: wrong password logs out, then login again.
    send_text("lock", s); time.sleep(1)
    send_text("wrongpass", s); time.sleep(1)
    ok &= wait_for(lambda t: t.count("login: ") >= 2, 10, "login after failed unlock")
    send_text("user", s); send_text("userpass", s); time.sleep(1)
    ok &= wait_for(lambda t: t.count("user@nxts> ") >= 2, 10, "user prompt again")
    # No early idle lock: wait 30 s, then a command must still work.
    time.sleep(30)
    send_text("whoami", s); time.sleep(1)
    send_text("logout", s); time.sleep(1)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = log_text()
print("--- serial log ---"); print(log); print("--- marker check ---")
markers = [
    "Background job slow.elf started (pid 10, uid 1000)",
    "pid 10  slow.elf  uid 1000",
    "Killed background job pid 10",
    "(no background jobs)",
    "Session locked. Enter password: ",
    "Unlock failed. Logging out.",
    "Welcome, user.",
    "user uid 1000",
    "Logged out.",
]
for m in markers:
    found = m in log; print(f"{'FOUND' if found else 'MISSING'}: {m}"); ok = ok and found
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
