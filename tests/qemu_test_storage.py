#!/usr/bin/env python3
"""Persistence test: boot with a nxtsFS disk, write a file, reboot the
guest, boot again, read the file back. Usage:
  python3 tests/qemu_test_storage.py <iso> <ram_mb> <serial_log> <mon_sock> <disk_img>
Exit 0 only if the written content is read back after the reboot.
QEMU is always terminated. The disk image is modified in place, so pass
a throwaway copy."""
import os, socket, subprocess, sys, time

ISO, RAM, SERIAL_LOG, MON_SOCK, DISK = sys.argv[1:6]

def log_text():
    try: return open(SERIAL_LOG, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT waiting for: {label}")
    return False

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}
def send_text(s, sock):
    for ch in s:
        k = KEYMAP.get(ch, ch)
        sock.sendall(f"sendkey {k}\n".encode())
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
    ok &= wait_for(lambda t: "nxts> " in t, 60, "first shell prompt")
    ok &= wait_for(lambda t: "Filesystem mounted" in t, 1, "filesystem mounted (checked in log)")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(MON_SOCK); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    # Seeded file must be readable before the write test.
    send_text("cat hello.txt", s); time.sleep(1)
    send_text("write persist.txt hello-persist", s); time.sleep(1)
    ok &= wait_for(lambda t: "Wrote persist.txt" in t, 10, "Wrote persist.txt")
    send_text("reboot", s)
    # After a guest reboot, GRUB reloads the kernel: a second boot
    # banner and a second shell prompt must appear.
    ok &= wait_for(lambda t: t.count("nxtsOS kernel starting") >= 2, 30, "second boot")
    ok &= wait_for(lambda t: t.count("nxts> ") >= 2, 60, "second shell prompt")
    send_text("cat persist.txt", s); time.sleep(1)
    send_text("ls", s); time.sleep(1)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

log = log_text()
print("--- serial log ---")
print(log)
print("--- marker check ---")
for m in ["Filesystem mounted", "Hello from nxtsFS", "Wrote persist.txt",
          "hello-persist", "persist.txt"]:
    found = m in log
    print(f"{'FOUND' if found else 'MISSING'}: {m}")
    ok = ok and found
# The read-back must happen after the second boot, not just before it.
second_boot = log.find("nxtsOS kernel starting", log.find("nxtsOS kernel starting") + 1)
readback = log.find("hello-persist", second_boot) if second_boot >= 0 else -1
print(f"readback-after-reboot: {'YES' if readback >= 0 else 'NO'}")
ok = ok and readback >= 0
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
