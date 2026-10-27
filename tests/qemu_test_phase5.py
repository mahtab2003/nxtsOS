#!/usr/bin/env python3
"""Phase 5 test: login as user, permission checks, run ELF from disk,
logout, login as root, run ELF again, read audit log.
Usage: python3 tests/qemu_test_phase5.py <iso> <ram_mb> <serial_log> <mon_sock> <disk_img>
Exit 0 only if all markers are found, in order where order matters.
QEMU is always terminated."""
import os, socket, subprocess, sys, time

ISO, RAM, SERIAL_LOG, MON_SOCK, DISK = sys.argv[1:6]

def log_text():
    try: return open(SERIAL_LOG, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}")
    return False

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}
def send_text(s, sock):
    for ch in s:
        sock.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode())
        time.sleep(0.15)
    sock.sendall(b"sendkey ret\n")
    time.sleep(0.3)

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
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(MON_SOCK); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    # Login as user.
    send_text("user", s); send_text("userpass", s); time.sleep(1)
    ok &= wait_for(lambda t: "user@nxts> " in t, 10, "user shell prompt")
    send_text("whoami", s); time.sleep(1)
    send_text("cat secret.txt", s); time.sleep(1)
    send_text("cat public.txt", s); time.sleep(1)
    send_text("run hello.elf", s); time.sleep(3)
    send_text("logout", s); time.sleep(1)
    ok &= wait_for(lambda t: t.count("login: ") >= 2, 10, "second login prompt")
    # Login as root.
    send_text("root", s); send_text("rootpass", s); time.sleep(1)
    ok &= wait_for(lambda t: "root@nxts> " in t, 10, "root shell prompt")
    send_text("cat secret.txt", s); time.sleep(1)
    send_text("run hello.elf", s); time.sleep(3)
    send_text("cat audit.log", s); time.sleep(1)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

log = log_text()
print("--- serial log ---")
print(log)
print("--- marker check ---")
markers = [
    "Welcome, user.", "user uid 1000", "cat: cannot read secret.txt",
    "public data", "Hello from ELF", "uid: 1000",
    "secret: access denied", "elf write ok", "Program hello.elf finished",
    "Logged out.", "Welcome, root.", "top secret", "uid: 0",
    "login-ok user", "login-ok root", "logout user",
]
for m in markers:
    found = m in log
    print(f"{'FOUND' if found else 'MISSING'}: {m}")
    ok = ok and found
# The root run must read the secret (after the user run denied it).
user_run = log.find("secret: access denied")
root_secret = log.find("secret: top secret")
print(f"user-denied-before-root-read: {'YES' if 0 <= user_run < root_secret else 'NO'}")
ok = ok and 0 <= user_run < root_secret
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
