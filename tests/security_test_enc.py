#!/usr/bin/env python3
"""Encryption adversarial security test.
Host checks (no QEMU): the encrypted disk image must not contain any
plaintext from the original disk ("top secret", "public data",
"Hello from ELF"), while the plain disk does.
QEMU checks, all on disks created fresh by this script from a plain
disk + tools/mkdisk_enc.py (passphrase "diskpass"):
 A. Superblock tamper: flip a byte in physical sector 1 (encrypted
    superblock), boot with the correct passphrase — FS mount must fail
    cleanly ("no valid nxtsFS"), no panic, shell still works with no FS.
 B. Header-check tamper: flip a byte in the header key-check
    ciphertext (offset 32), boot with the correct passphrase three
    times — every attempt must fail, system halts, no unlock, no FS.
 C. Package tamper on an encrypted disk: install hello on an encrypted
    disk, terminate, decrypt the disk on the host (OpenSSL, key derived
    from the header salt + passphrase) to find hello.elf's sector,
    flip a byte in its encrypted sector, boot again with the correct
    passphrase — FS mounts, but `run hello.elf` must be refused
    (package hash mismatch on the decrypted, corrupted plaintext).
Usage: python3 tests/security_test_enc.py <iso> <workdir>
<workdir>/plain.img must exist (unencrypted, with users.txt,
public.txt, secret.txt, hello.nxpkg). Exit 0 only if all checks pass."""
import hashlib, os, socket, struct, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
PLAIN = os.path.join(WORK, "plain.img")
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
def boot(disk, actions, prompt):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "none", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={disk},format=raw,if=ide,index=0",
    ])
    ok = True
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        ok &= wait_for(lambda t: prompt in t, 60, f"prompt {prompt!r}")
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

def make_enc(out):
    r = subprocess.run(["python3", "tools/mkdisk_enc.py", PLAIN, out, "--passphrase", "diskpass"],
                       capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

ok = True
# Host raw-string check.
plain = open(PLAIN, "rb").read()
enc0 = os.path.join(WORK, "enc0.img"); make_enc(enc0)
enc = open(enc0, "rb").read()
for s in [b"top secret", b"public data", b"Hello from ELF"]:
    print(f"{'PASS' if s in plain and s not in enc else 'FAIL'}: raw disk hides {s!r}")
    ok = ok and (s in plain and s not in enc)

# A. Superblock tamper.
disk_a = os.path.join(WORK, "enc_a.img"); make_enc(disk_a)
# Flip the superblock magic byte (offset 0 of the encrypted superblock
# sector, physical sector 1). Flipping a reserved superblock byte
# would not affect mounting, so the magic byte is the right target.
with open(disk_a, "r+b") as f:
    f.seek(1 * 512 + 0); b = f.read(1); f.seek(1 * 512 + 0); f.write(bytes([b[0] ^ 0xFF]))
_, log_a = boot(disk_a, ["diskpass"], "Disk passphrase: ")
print("--- A log (superblock tamper) ---"); print(log_a)
for m, should in [("Disk unlocked.", True), ("no valid nxtsFS", True),
                  ("Filesystem mounted", False), ("Users configured", False)]:
    f = m in log_a; print(f"{'PASS' if f == should else 'FAIL'} A: {'found' if should else 'absent'} {m}")
    ok = ok and (f == should)

# B. Header-check tamper.
disk_b = os.path.join(WORK, "enc_b.img"); make_enc(disk_b)
with open(disk_b, "r+b") as f:
    f.seek(32); b = f.read(1); f.seek(32); f.write(bytes([b[0] ^ 0xFF]))
_, log_b = boot(disk_b, ["diskpass", "diskpass", "diskpass"], "Disk passphrase: ")
print("--- B log (header tamper) ---"); print(log_b)
for m, should in [("Wrong passphrase.", True), ("Too many failed attempts. System halted.", True),
                  ("Disk unlocked.", False), ("Filesystem mounted", False)]:
    f = m in log_b; print(f"{'PASS' if f == should else 'FAIL'} B: {'found' if should else 'absent'} {m}")
    ok = ok and (f == should)

# C. Package tamper on an encrypted disk.
disk_c = os.path.join(WORK, "enc_c.img"); make_enc(disk_c)
_, log_c1 = boot(disk_c, ["diskpass", "root", "rootpass", "pkg install hello.nxpkg"], "Disk passphrase: ")
assert "Installed hello 1.0" in log_c1, "setup: pkg install failed in boot C1"
# Decrypt on the host to find hello.elf's logical start sector.
enc_bytes = open(disk_c, "rb").read()
salt = enc_bytes[16:32]
h = hashlib.sha256(salt + b"diskpass").digest()
for _ in range(9999):
    h = hashlib.sha256(h + salt).digest()
open(os.path.join(WORK, "fs_enc.bin"), "wb").write(enc_bytes[512:])
r = subprocess.run(["openssl", "enc", "-d", "-aes-256-ctr", "-K", h.hex(), "-iv", "00"*16,
                    "-nopad", "-in", os.path.join(WORK, "fs_enc.bin"),
                    "-out", os.path.join(WORK, "fs_dec.img")], capture_output=True)
assert r.returncode == 0, "host decryption failed"
fs = open(os.path.join(WORK, "fs_dec.img"), "rb").read()
rootdir = fs[9*512:13*512]
start = None
for i in range(32):
    e = rootdir[i*64:(i+1)*64]
    if e[52] & 1 and e[:32].split(b"\x00")[0].decode() == "hello.elf":
        start = struct.unpack("<I", e[36:40])[0]; break
assert start is not None, "hello.elf not found after install"
with open(disk_c, "r+b") as f:
    phys = (start + 1) * 512 + 1000
    f.seek(phys); b = f.read(1); f.seek(phys); f.write(bytes([b[0] ^ 0xFF]))
    print(f"Tampered encrypted hello.elf at physical sector {start+1}, offset 1000")
_, log_c2 = boot(disk_c, ["diskpass", "root", "rootpass", "run hello.elf", "pkg list"], "Disk passphrase: ")
print("--- C log (package tamper) ---"); print(log_c2)
for m, should in [("Disk unlocked.", True), ("Filesystem mounted", True),
                  ("cannot run hello.elf", True), ("hello 1.0", True)]:
    f = m in log_c2; print(f"{'PASS' if f == should else 'FAIL'} C: {'found' if should else 'absent'} {m}")
    ok = ok and (f == should)

print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
