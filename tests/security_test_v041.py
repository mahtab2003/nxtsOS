#!/usr/bin/env python3
"""v0.4.1 security test: persistent brute-force lockout.
Boot 1: 3 wrong passwords for user -> halt (fails.txt now holds 3).
Boot 2, same disk: correct password for user -> "Account locked",
then root login, `unlock user`, logout, user login with correct
password -> succeeds. This proves a reboot does not reset the counter.
Usage: python3 tests/security_test_v041.py <iso> <serial_log> <mon_sock> <disk_img>
Exit 0 only if all markers are found."""
import os, socket, subprocess, sys, time
ISO, SERIAL_LOG, MON_SOCK, DISK = sys.argv[1:5]

def run_boot(markers_to_check, actions, timeout_login=60):
    for p in (SERIAL_LOG, MON_SOCK):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "none", "-serial", f"file:{SERIAL_LOG}",
        "-monitor", f"unix:{MON_SOCK},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
    ])
    try:
        for _ in range(100):
            if os.path.exists(MON_SOCK): break
            time.sleep(0.1)
        def log_text():
            try: return open(SERIAL_LOG, errors="replace").read()
            except FileNotFoundError: return ""
        for _ in range(int(timeout_login * 10)):
            if "login: " in log_text(): break
            time.sleep(0.1)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON_SOCK); s.settimeout(2)
        try: s.recv(4096)
        except socket.timeout: pass
        KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}
        def send_text(txt):
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(0.3)
        for txt in actions:
            send_text(txt); time.sleep(1)
        time.sleep(2); s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return open(SERIAL_LOG, errors="replace").read()

log1 = run_boot(None, ["user", "bad1", "user", "bad2", "user", "bad3"])
print("--- boot 1 log ---"); print(log1)
log2 = run_boot(None, ["user", "userpass", "root", "rootpass", "unlock user", "logout", "user", "userpass"])
print("--- boot 2 log ---"); print(log2)
ok = True
for m in ["Too many failed attempts. System halted."]:
    f = m in log1; print(f"{'FOUND' if f else 'MISSING'} boot1: {m}"); ok = ok and f
for m in ["Account locked. Contact root to unlock.", "Unlocked user", "Welcome, user."]:
    f = m in log2; print(f"{'FOUND' if f else 'MISSING'} boot2: {m}"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
