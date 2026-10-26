#!/usr/bin/env python3
"""Adversarial Phase 5 tests, three boots:
 A. Malformed ELFs + syscall-abuse ELF, run as root: every bad file must
    be refused cleanly, the good ELF must then run, shell must survive.
 B. Login brute force: 3 wrong passwords must halt the system (no shell).
 C. Malformed users.txt: a bad line must be skipped, root login must
    still work.
Usage: python3 tests/security_test_phase5.py <iso> <workdir>
The caller must have already built build/hello.elf, build/evil.elf and
generated users files in <workdir> via the setup in the test report
(see tests/security_test_phase5_setup.py for the exact disk layout).
Exit 0 only if every case passes. QEMU is always terminated."""
import os, socket, struct, subprocess, sys, time

ISO, WORK = sys.argv[1:3]

def log_text(path):
    try: return open(path, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(path, pred, timeout):
    for _ in range(int(timeout * 10)):
        if pred(log_text(path)): return True
        time.sleep(0.1)
    return False

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}
def send_text(s, sock):
    for ch in s:
        sock.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode())
        time.sleep(0.15)
    sock.sendall(b"sendkey ret\n")
    time.sleep(0.3)

def boot(disk, ram="128"):
    serial = os.path.join(WORK, "sec5.log")
    mon = os.path.join(WORK, "sec5.sock")
    for p in (serial, mon):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", ram,
        "-display", "none", "-serial", f"file:{serial}",
        "-monitor", f"unix:{mon},server,nowait",
        "-drive", f"file={disk},format=raw,if=ide,index=0",
    ])
    for _ in range(100):
        if os.path.exists(mon): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(mon); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    return qemu, s, serial

def stop(qemu, s):
    try: s.close()
    except Exception: pass
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

def no_panic(log):
    return not any(w in log for w in ("KERNEL PANIC", "EXCEPTION", "PAGE FAULT"))

results = []

# --- Boot A: malformed ELFs + evil ELF ---
disk_a = os.path.join(WORK, "disk_a.img")
qemu, s, serial = boot(disk_a)
try:
    ok = wait_for(serial, lambda t: "login: " in t, 60)
    send_text("root", s); send_text("rootpass", s); time.sleep(1)
    ok = ok and wait_for(serial, lambda t: "root@nxts> " in t, 10)
    for name in ["badmagic.elf", "badtrunc.elf", "badphnum.elf", "badoffset.elf",
                 "badkaddr.elf", "badstack.elf", "badentry.elf", "badmemsz.elf"]:
        send_text(f"run {name}", s); time.sleep(1)
    send_text("run evil.elf", s); time.sleep(2)
    send_text("run hello.elf", s); time.sleep(2)
    time.sleep(1)
finally:
    stop(qemu, s)
log = log_text(serial)
bad_ok = all(f"run: cannot run {n}" in log for n in
             ["badmagic.elf", "badtrunc.elf", "badphnum.elf", "badoffset.elf",
              "badkaddr.elf", "badstack.elf", "badentry.elf", "badmemsz.elf"])
evil_ok = all(m in log for m in ["evil print rejected", "evil filename rejected",
                                 "evil buffer rejected", "evil null buffer rejected",
                                 "evil write buffer rejected", "evil: done, kernel survived"])
good_ok = "Hello from ELF" in log and "root@nxts> " in log
case_a = bad_ok and evil_ok and good_ok and no_panic(log) and log.count("nxtsOS kernel starting") == 1
print(f"{'PASS' if case_a else 'FAIL'}: A malformed+evil ELFs (bad={bad_ok}, evil={evil_ok}, good={good_ok}, no_panic={no_panic(log)})")
results.append(case_a)

# --- Boot B: brute force ---
disk_b = os.path.join(WORK, "disk_b.img")
qemu, s, serial = boot(disk_b)
try:
    ok = wait_for(serial, lambda t: "login: " in t, 60)
    for _ in range(3):
        send_text("user", s); send_text("wrongpass", s); time.sleep(1)
    time.sleep(2)
finally:
    stop(qemu, s)
log = log_text(serial)
case_b = ("Too many failed attempts" in log and "user@nxts> " not in log
          and "root@nxts> " not in log and no_panic(log)
          and log.count("nxtsOS kernel starting") == 1)
print(f"{'PASS' if case_b else 'FAIL'}: B brute force halt (halt_msg={'Too many failed attempts' in log}, no_shell={'user@nxts> ' not in log})")
results.append(case_b)

# --- Boot C: malformed users.txt ---
disk_c = os.path.join(WORK, "disk_c.img")
qemu, s, serial = boot(disk_c)
try:
    ok = wait_for(serial, lambda t: "login: " in t, 60)
    send_text("root", s); send_text("rootpass", s); time.sleep(1)
    ok = ok and wait_for(serial, lambda t: "root@nxts> " in t, 10)
finally:
    stop(qemu, s)
log = log_text(serial)
case_c = ok and no_panic(log) and log.count("nxtsOS kernel starting") == 1
print(f"{'PASS' if case_c else 'FAIL'}: C malformed users line skipped, root login works")
results.append(case_c)

print("RESULT:", "PASS" if all(results) else "FAIL")
sys.exit(0 if all(results) else 1)
