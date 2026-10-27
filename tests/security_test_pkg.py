#!/usr/bin/env python3
"""Phase 6 adversarial security test.
Boot A: install hello, then try badhash, badsize, badpath, badabs,
selfdep, cycle a/b, need99, huge — all must be refused, hello must
still run, and no evil files must appear in ls.
Boot B/C (tamper): install hello, terminate, flip one byte in
hello.elf's data sector on disk, boot again, run hello.elf — it must
be refused (hash mismatch), even though the ELF is otherwise intact.
Usage: python3 tests/security_test_pkg.py <iso> <workdir>
<workdir> is created by tests/security_test_pkg_setup.py, plus a disk
image built by the caller (see the test report for the exact disk).
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
def boot_and_run(actions, prompt="root@nxts> "):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "none", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
    ])
    ok = True
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        ok &= wait_for(lambda t: prompt in t, 60, "shell prompt")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
        try: s.recv(4096)
        except socket.timeout: pass
        def send_text(txt):
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(0.3)
        for txt in actions:
            send_text(txt); time.sleep(1)
        time.sleep(1); s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return ok, log_text()

# Boot A: malicious installs.
ok_a, log_a = boot_and_run([
    "pkg install hello.nxpkg",
    "pkg install badhash.nxpkg", "pkg install badsize.nxpkg",
    "pkg install badpath.nxpkg", "pkg install badabs.nxpkg",
    "pkg install selfdep.nxpkg", "pkg install cyc_a.nxpkg",
    "pkg install cyc_b.nxpkg", "pkg install need99.nxpkg",
    "pkg install huge.nxpkg", "pkg install huge2.nxpkg",
    "pkg list", "ls", "run hello.elf",
])
print("--- boot A log ---"); print(log_a)
checks_a = [
    ("Installed hello 1.0", True),
    ("malformed package or hash mismatch", True),
    ("package depends on itself", True),
    ("missing or conflicting dependency", True),
    ("cannot read package file", True),  # huge (over buffer cap)
    ("hello 1.0", True),
    ("Hello from ELF", True),
    ("evil.elf", False),
    ("self.elf", False),
    ("a.elf", False),
    ("b.elf", False),
    ("need.elf", False),
    ("big.elf", False),
]
ok = ok_a
for marker, should in checks_a:
    found = marker in log_a
    good = found if should else not found
    print(f"{'PASS' if good else 'FAIL'}: {'found' if should else 'absent'} {marker}")
    ok = ok and good

# Tamper: flip a byte at offset 1000 in hello.elf's data on disk.
with open(DISK, "r+b") as f:
    f.seek(9 * 512)
    rootdir = f.read(4 * 512)
    start = None
    for i in range(32):
        e = rootdir[i*64:(i+1)*64]
        name = e[:32].split(b"\x00")[0].decode()
        if name == "hello.elf":
            start = struct.unpack("<I", e[36:40])[0]; break
    assert start is not None, "hello.elf not found on disk"
    f.seek(start * 512 + 1000)
    b = f.read(1)
    f.seek(start * 512 + 1000)
    f.write(bytes([b[0] ^ 0xFF]))
    print(f"Tampered hello.elf at sector {start}, offset 1000: {b[0]:02x} -> {b[0]^0xFF:02x}")

ok_b, log_b = boot_and_run(["run hello.elf", "pkg list"])
print("--- boot B (tampered) log ---"); print(log_b)
for marker, should in [("cannot run hello.elf", True), ("hello 1.0", True)]:
    found = marker in log_b
    print(f"{'PASS' if found == should else 'FAIL'}: {marker}")
    ok = ok and (found == should)
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
