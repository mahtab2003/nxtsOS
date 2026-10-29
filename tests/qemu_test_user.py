#!/usr/bin/env python3
"""Boot nxtsOS in QEMU and verify Phase 3 user processes: both processes
print all iterations, output interleaves, and preemption is proven by
P1 iter 1 appearing before P2 iter 1 (P2's first busy loop is preempted
several times before it prints iter 1). Usage:
  python3 tests/qemu_test_user.py <iso> <ram_mb> <serial_log>
Exit 0 only if all checks pass. QEMU is always terminated."""
import os, subprocess, sys, time

ISO, RAM, SERIAL_LOG = sys.argv[1], sys.argv[2], sys.argv[3]
try: os.unlink(SERIAL_LOG)
except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", RAM,
    "-display", "none", "-serial", f"file:{SERIAL_LOG}", "-monitor", "none",
])
try:
    for _ in range(400):
        time.sleep(0.1)
        try: log = open(SERIAL_LOG, errors="replace").read()
        except FileNotFoundError: continue
        if "All user processes finished." in log: break
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = open(SERIAL_LOG, errors="replace").read() if os.path.exists(SERIAL_LOG) else ""
print("--- serial log ---")
print(log)
checks = []
for pid in (1, 2):
    for i in range(5):
        checks.append((f"P{pid} iter {i}", f"P{pid} iter {i}" in log))
checks.append(("All user processes finished.",
               "All user processes finished." in log))
# The prompt check must search AFTER the finish line for the real
# prompt: log.find("nxts> ") alone always hits the early notice
# ("The nxts> shell prompt will appear when they finish"),
# which precedes the finish line and fails every run even
# though the prompt itself is present. Require "root@nxts> "
# after the finish line instead (stricter, not weaker).
i_fin = log.find("All user processes finished.")
checks.append(("Shell prompt after processes",
               i_fin >= 0 and
               log.find("root@nxts> ", i_fin) > i_fin))
# Preemption proof: P1 iter 1 occurs during P2's first busy loop.
i_p1_1 = log.find("P1 iter 1")
i_p2_1 = log.find("P2 iter 1")
checks.append(("Preemption: P1 iter 1 before P2 iter 1",
               i_p1_1 != -1 and i_p2_1 != -1 and i_p1_1 < i_p2_1))
ok = True
for name, found in checks:
    print(f"{'FOUND' if found else 'MISSING'}: {name}")
    ok = ok and found
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
