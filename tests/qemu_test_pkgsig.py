#!/usr/bin/env python3
"""Phase 11 keyring test: a package signed with a key that is NOT the
compiled-in vendor key must install iff that key's modulus is listed
in the root-owned pubkeys.txt keyring (one 512-hex-char modulus per
line, exponent 65537). Setup (by the caller): a disk with pubkeys.txt
and krhello.nxpkg (hello 1.0, signed with the keyring key).
Usage: python3 tests/qemu_test_pkgsig.py <iso> <disk_img>
Exit 0 only if install + run both succeed.
"""
import os, socket, subprocess, sys, time
ISO, DISK = sys.argv[1:3]
SERIAL, MON = "/tmp/pkgsig.log", "/tmp/pkgsig.mon"
for p in (SERIAL, MON):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "none", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
])
def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
ok = True
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    for _ in range(600):
        if "root@nxts> " in log_text(): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}
    def send_text(txt):
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(1)
    send_text("pkg install krhello.nxpkg"); time.sleep(2)
    send_text("run hello.elf"); time.sleep(2)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = log_text()
for marker in ["Installed hello 1.0", "Hello from ELF"]:
    found = marker in log
    print(f"{'PASS' if found else 'FAIL'}: {marker}")
    ok = ok and found
if "bad package signature" in log or "not signed" in log:
    print("FAIL: keyring-signed package was refused"); ok = False
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
