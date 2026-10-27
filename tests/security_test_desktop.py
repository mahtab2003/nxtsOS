#!/usr/bin/env python3
"""Phase 8 adversarial security test (desktop).
Boot A (as user): desktopsectest — Settings Save on a root-owned
settings.txt must be denied (serial marker, no "settings saved"),
then a wrong lock-screen password must fail and the lock must stay
up (no "unlocked" line, no desktopsectest return).
Boot B (as root): guibad.elf — GUI syscalls without a desktop, plus
null/huge/non-printable arguments, must all be rejected.
Boot C (tamper): install calc as root, terminate, flip one byte in
the installed calc.elf on disk, boot again, runbg calc.elf — it must
be refused by the registry hash check, even though the ELF is
otherwise intact (this is the launcher path: the desktop launcher
starts Calculator through the same proc_bg_start/elf loader).
Usage: python3 tests/security_test_desktop.py <iso> <workdir>
<workdir> is created by tests/security_test_desktop_setup.py.
Exit 0 only if all checks pass."""
import os, socket, struct, subprocess, sys, time
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

def boot(login_user, login_pass, actions, wait_marker=None):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:15", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
    ])
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        if not wait_for(lambda t: "login: " in t, 60, "login prompt"):
            return False, log_text()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON)
        try: s.recv(4096)
        except socket.timeout: pass
        def send_text(txt):
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(0.5)
        send_text(login_user); send_text(login_pass); time.sleep(1)
        for txt in actions:
            send_text(txt); time.sleep(1)
        if wait_marker:
            wait_for(lambda t: wait_marker in t, 30, wait_marker)
        else:
            time.sleep(1)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return True, log_text()

ok = True
# Boot A: non-admin settings save + wrong lock password.
_, log_a = boot("user", "userpass", ["desktopsectest"],
                wait_marker="Desktop: lock password failed")
for marker, should in [
        ("Desktop settings save failed: permission denied", True),
        ("Desktop: lock screen shown", True),
        ("Desktop: lock password failed (1/3)", True),
        ("Desktop settings saved", False),
        ("Desktop: unlocked", False),
        ("desktopsectest returned", False)]:
    found = marker in log_a
    print(f"{'PASS' if found == should else 'FAIL'} boot A: {'found' if should else 'absent'} {marker}")
    ok = ok and (found == should)
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log_a; print(f"{'PASS' if f else 'FAIL'} boot A: absent {bad}"); ok = ok and f

# Boot B: malformed GUI syscalls, no desktop.
_, log_b = boot("root", "rootpass", ["run guibad.elf"])
for marker, should in [("guibad PASS", True), ("guibad FAIL", False)]:
    found = marker in log_b
    print(f"{'PASS' if found == should else 'FAIL'} boot B: {'found' if should else 'absent'} {marker}")
    ok = ok and (found == should)

# Boot C, part 1: install calc as root.
_, log_c1 = boot("root", "rootpass", ["pkg install calc.nxpkg", "pkg list"])
f = "Installed calc 1.0" in log_c1; print(f"{'PASS' if f else 'FAIL'} boot C1: Installed calc 1.0"); ok = ok and f

# Tamper: flip a byte at offset 1000 in calc.elf's data on disk.
with open(DISK, "r+b") as fh:
    fh.seek(9 * 512)
    rootdir = fh.read(4 * 512)
    start = None
    for i in range(32):
        e = rootdir[i*64:(i+1)*64]
        name = e[:32].split(b"\x00")[0].decode()
        if name == "calc.elf":
            start = struct.unpack("<I", e[36:40])[0]; break
    assert start is not None, "calc.elf not found on disk"
    fh.seek(start * 512 + 1000)
    b = fh.read(1)
    fh.seek(start * 512 + 1000)
    fh.write(bytes([b[0] ^ 0xFF]))
    print(f"Tampered calc.elf at sector {start}, offset 1000: {b[0]:02x} -> {b[0]^0xFF:02x}")

# Boot C, part 2: tampered calc must not run.
_, log_c2 = boot("root", "rootpass", ["runbg calc.elf", "pkg list"])
for marker, should in [
        ("runbg: cannot start calc.elf", True),
        ("calc 1.0  depends:", True)]:
    found = marker in log_c2
    print(f"{'PASS' if found == should else 'FAIL'} boot C2: {'found' if should else 'absent'} {marker}")
    ok = ok and (found == should)
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
