#!/usr/bin/env python3
"""Files-window Hash test: a desktop-only user must be able to
get a file's SHA-256 without the shell's `sha256` command.
Single boot: desktopfileshashtest — the kernel autotest mode
23 script: Files icon, Hash with no selection (refused),
row 0 select (the disk holds only readme.txt, so row 0 is
certainly it), Hash (prints the full hex), Terminal icon
(desktop exits). The harness computes the expected hex with
hashlib from the same bytes the setup wrote, and checks the
desktop marker against it; it then runs shell `sha256
readme.txt` as a second, independent proof of the same value.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_files_hash.py <iso> <workdir>
<workdir> is created by tests/qemu_test_files_hash_setup.py.
The sender verifies the shell's echo of each command and
retypes once on mismatch (the QEMU sendkey-doubling flake
class from the repo test); login typing is not echoed.
"""
import hashlib, os, socket, subprocess, sys, time
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

expected = hashlib.sha256(open(os.path.join(WORK, "readme.txt"), "rb").read()).hexdigest()
print(f"expected sha256: {expected}")
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
    send_text("desktopfileshashtest")
    ok &= wait_for(lambda t: "desktopfileshashtest returned" in t, 60, "desktopfileshashtest returned")
    time.sleep(4)
    send_text("sha256 readme.txt"); time.sleep(2)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = log_text()
for m in ["Desktop: Files opened",
          "files: hash needs selection",
          f"files: sha256 readme.txt {expected}",
          "desktopfileshashtest returned"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
# Second proof: the shell's own sha256 output after the desktop
# exit must print the same hex for the same file.
ret_pos = log.find("desktopfileshashtest returned")
tail = log[ret_pos:] if ret_pos >= 0 else ""
f = f"{expected}  readme.txt" in tail
print(f"{'PASS' if f else 'FAIL'} shell sha256 after desktop matches"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
