#!/usr/bin/env python3
"""Boot nxtsOS in QEMU, type shell commands via the QEMU monitor, and
check the serial log for the expected markers. Usage:
  python3 tests/qemu_test.py <iso> <ram_mb> <serial_log> <monitor_sock>
Exit 0 only if all markers are found. QEMU is always terminated."""
import os, socket, subprocess, sys, time

ISO, RAM, SERIAL_LOG, MON_SOCK = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
MARKERS = [
    "nxtsOS kernel starting",
    "PMM:",
    "GDT installed",
    "Interrupts enabled",
    "nxts> ",
    "Commands: help, mem, ticks, clear, reboot",
    "Memory: total",
]

for p in (SERIAL_LOG, MON_SOCK):
    try: os.unlink(p)
    except FileNotFoundError: pass

qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", RAM,
    "-display", "none", "-serial", f"file:{SERIAL_LOG}",
    "-monitor", f"unix:{MON_SOCK},server,nowait",
])
try:
    # Wait for the monitor socket to appear.
    for _ in range(100):
        if os.path.exists(MON_SOCK): break
        time.sleep(0.1)
    time.sleep(4)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(MON_SOCK)
    s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    def sendkey(k):
        s.sendall(f"sendkey {k}\n".encode())
        time.sleep(0.25)
    for k in ["h", "e", "l", "p", "ret"]:
        sendkey(k)
    time.sleep(1)
    for k in ["m", "e", "m", "ret"]:
        sendkey(k)
    time.sleep(2)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

log = open(SERIAL_LOG, errors="replace").read() if os.path.exists(SERIAL_LOG) else ""
print("--- serial log ---")
print(log)
print("--- marker check ---")
ok = True
for m in MARKERS:
    found = m in log
    print(f"{'FOUND' if found else 'MISSING'}: {m}")
    ok = ok and found
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
