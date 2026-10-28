#!/usr/bin/env python3
"""Shell `mv` test: the metadata-only fs_rename_as primitive must
rename a file (same content, new name), and must refuse a missing
source, an existing destination (never overwrites), and a rename
onto itself.
Single boot, one persistent disk, no network.
Boot: ls, mv alpha.txt beta.txt, cat beta.txt (original content),
mv missing.txt new.txt (refused), mv beta.txt keep.txt (refused),
mv beta.txt beta.txt (refused), ls (beta.txt present, alpha.txt gone).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_mv.py <iso> <workdir>
<workdir> is created by tests/qemu_test_mv_setup.py.
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
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus", ":": "shift-semicolon"}

ok = True
for p in (SERIAL, MON):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "none", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    prompt = "root@nxts> "
    ok &= wait_for(lambda t: prompt in t, 60, "shell prompt")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    def send_text(txt):
        def type_cmd(t):
            for ch in t:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(1)
        before = len(log_text())
        type_cmd(txt)
        for _ in range(150):
            fresh = log_text()[before:]
            if f"{prompt}{txt}" in fresh: return
            if fresh.count(prompt) >= 1: break
            time.sleep(0.1)
        if f"{prompt}{txt}" not in log_text()[before:]:
            before2 = len(log_text())
            type_cmd(txt)
            for _ in range(150):
                if f"{prompt}{txt}" in log_text()[before2:]: break
                time.sleep(0.1)
    for act in ["ls", "mv alpha.txt beta.txt", "cat beta.txt",
                "mv missing.txt new.txt", "mv beta.txt keep.txt",
                "mv beta.txt beta.txt"]:
        send_text(act); time.sleep(1)
    before_final_ls = len(log_text())
    send_text("ls"); time.sleep(1)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = log_text()
print("--- boot log ---"); print(log)
def check(marker, should):
    global ok
    found = marker in log
    good = found if should else not found
    print(f"{'PASS' if good else 'FAIL'}: {'found' if should else 'absent'} {marker}")
    ok = ok and good
for m in ["Renamed alpha.txt to beta.txt",
          "alpha content",
          "mv: cannot rename missing.txt to new.txt",
          "mv: cannot rename beta.txt to keep.txt",
          "mv: cannot rename beta.txt to beta.txt"]:
    check(m, True)
final_ls = log[before_final_ls:]
for m, should in [("beta.txt", True), ("alpha.txt", False)]:
    found = m in final_ls
    good = found if should else not found
    print(f"{'PASS' if good else 'FAIL'}: final ls {'shows' if should else 'hides'} {m}")
    ok = ok and good
for m in ["EXCEPTION", "PANIC", "page fault"]:
    check(m, False)
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
