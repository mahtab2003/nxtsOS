#!/usr/bin/env python3
"""Monitor-window Disk test: a desktop-only user must be able
to see disk total and free space without the shell's `fs`
command. Single boot: desktopmonitordisktest — the kernel
autotest mode 24 script: Start, launcher Monitor row, a
pixel scan of both Disk rows (the pixel proof that the
rows actually drew), Terminal icon (desktop exits). The
harness checks the Monitor's open marker against the
shell's own `fs` output after the desktop exit — two
independent reports of the same numbers for the same disk.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_monitor_disk.py <iso> <workdir>
<workdir> is created by tests/qemu_test_monitor_disk_setup.py.
The sender verifies the shell's echo of each command and
retypes once on mismatch (the QEMU sendkey-doubling flake
class from the repo test); login typing is not echoed.
"""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

ok = True
for p in (SERIAL, MON):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "vnc=:24", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    ok &= wait_for(lambda t: "root@nxts> " in t, 60, "shell prompt")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    def send_text(txt):
        for _attempt in range(2):
            before = len(log_text())
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            if "Unknown command" not in log_text()[before:]:
                break
    send_text("desktopmonitordisktest")
    ok &= wait_for(lambda t: "desktopmonitordisktest returned" in t, 60, "desktopmonitordisktest returned")
    time.sleep(4)
    send_text("fs"); time.sleep(2)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = log_text()
for m in ["Desktop: Monitor opened",
          "monitor: disk rows drawn",
          "desktopmonitordisktest returned"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
# Two independent proofs: the Monitor's open marker and the
# shell's own `fs` output after the desktop exit must report
# the same total and free sector counts for this disk.
mm = re.search(r"monitor: disk (\d+) sectors total, (\d+) free", log)
ret_pos = log.find("desktopmonitordisktest returned")
tail = log[ret_pos:] if ret_pos >= 0 else ""
mf = re.search(r"Filesystem: nxtsFS v1, (\d+) sectors total, (\d+) free", tail)
print(f"monitor marker: {mm.groups() if mm else None}")
print(f"shell fs: {mf.groups() if mf else None}")
f = bool(mm and mf and mm.groups() == mf.groups())
print(f"{'PASS' if f else 'FAIL'} monitor disk numbers match shell fs"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
