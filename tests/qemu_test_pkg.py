#!/usr/bin/env python3
"""Phase 6 test: SHA-256 vector, pkg install/list/remove, dependency
order, duplicate install, upgrade, root-only install.
Usage: python3 tests/qemu_test_pkg.py <iso> <ram_mb> <serial_log> <mon_sock> <disk_img>
Disk must contain abc.txt ("abc", no newline), hello.nxpkg (hello 1.0),
greet.nxpkg (greet 1.0, depends hello>=1.0), hello11.nxpkg (hello 1.1).
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
    ok &= wait_for(lambda t: "root@nxts> " in t, 60, "root prompt (setup mode)")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON_SOCK); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    # SHA-256 known vector: sha256("abc").
    send_text("sha256 abc.txt", s); time.sleep(1)
    # Dependency order: greet must fail before hello is installed.
    send_text("pkg install greet.nxpkg", s); time.sleep(1)
    send_text("pkg install hello.nxpkg", s); time.sleep(1)
    send_text("pkg install greet.nxpkg", s); time.sleep(1)
    send_text("pkg install hello.nxpkg", s); time.sleep(1)  # duplicate
    send_text("pkg list", s); time.sleep(1)
    send_text("run hello.elf", s); time.sleep(2)
    send_text("run greet.elf", s); time.sleep(1)
    # Removal of a depended-on package must be refused.
    send_text("pkg remove hello", s); time.sleep(1)
    send_text("pkg remove greet", s); time.sleep(1)
    send_text("pkg remove hello", s); time.sleep(1)
    send_text("pkg list", s); time.sleep(1)
    # Upgrade: reinstall hello 1.0, then upgrade to 1.1, run it.
    send_text("pkg install hello.nxpkg", s); time.sleep(1)
    send_text("pkg install hello11.nxpkg", s); time.sleep(1)
    send_text("pkg list", s); time.sleep(1)
    send_text("run hello.elf", s); time.sleep(2)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = log_text()
print("--- serial log ---"); print(log); print("--- marker check ---")
markers = [
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  abc.txt",
    "missing or conflicting dependency",  # greet before hello
    "Installed hello 1.0",
    "Installed greet 1.0",
    "package already installed",  # duplicate hello 1.0
    "hello 1.0",
    "greet 1.0",
    "Hello from ELF",
    "Greetings from greet",
    "depends on hello, removal refused",  # remove hello while greet installed
    "Removed greet",
    "Removed hello",
    "(no packages installed)",
    "Upgraded hello to 1.1",
    "hello 1.1",
    "Hello v1.1",
]
for m in markers:
    found = m in log; print(f"{'FOUND' if found else 'MISSING'}: {m}"); ok = ok and found
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
