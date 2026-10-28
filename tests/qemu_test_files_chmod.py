#!/usr/bin/env python3
"""Files-window Chmod test: a desktop-only user must be able to
change a file's mode without the shell's `chmod` command.
Single boot: desktopfileschmodtest — the kernel autotest mode
26 script: Files icon, Chmod with no selection (refused),
row 0 select (the disk holds only readme.txt, so row 0 is
certainly it), Chmod with an empty mode (refused), type 999
and Chmod (bad mode, refused, field kept), backspace, type
600 and Chmod (success, field cleared), type 644 and Chmod
(success again — proving the field really cleared, since a
stale "600" would have made "600644", a bad mode), Terminal
icon (desktop exits). The harness checks every desktop
marker, then runs shell `ls` as a second, independent proof:
mode 420 is the decimal form of 0644.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_files_chmod.py <iso> <workdir>
<workdir> is created by tests/qemu_test_files_chmod_setup.py.
The sender verifies the shell's echo of each command and
retypes once on mismatch (the QEMU sendkey-doubling flake
class from the repo test); login typing is not echoed.
"""
import os, socket, subprocess, sys, time
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
    "-display", "vnc=:23", "-serial", f"file:{SERIAL}",
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
    send_text("desktopfileschmodtest")
    ok &= wait_for(lambda t: "desktopfileschmodtest returned" in t, 60, "desktopfileschmodtest returned")
    time.sleep(4)
    send_text("ls"); time.sleep(2)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = log_text()
for m in ["Desktop: Files opened",
          "files: chmod needs selection",
          "files: chmod needs mode",
          "files: chmod bad mode 999",
          "files: chmod readme.txt mode 600",
          "files: chmod readme.txt mode 644",
          "desktopfileschmodtest returned"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
# Second proof: shell `ls` after the desktop exit must report
# mode 420 (decimal 0644) for readme.txt.
ret_pos = log.find("desktopfileschmodtest returned")
tail = log[ret_pos:] if ret_pos >= 0 else ""
f = "readme.txt" in tail and "mode 420" in tail
print(f"{'PASS' if f else 'FAIL'} shell ls after desktop reports mode 420"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
