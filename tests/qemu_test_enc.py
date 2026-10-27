#!/usr/bin/env python3
"""Encryption test, three boots on the same encrypted disk.
Boot 1 (correct passphrase): disk unlocks, FS mounts, login as user,
public read, secret denied, run hello, pkg install hello (package on
the encrypted disk), run installed hello, pkg list.
Boot 2 (wrong passphrase x3): system halts, no shell prompt, no FS.
Boot 3 (aes-test, no disk): AES-256 FIPS vector passes.
Usage: python3 tests/qemu_test_enc.py <iso> <workdir>
<workdir>/enc.img must exist (from tools/mkdisk_enc.py, passphrase
"diskpass", users root/rootpass and user/userpass, files public.txt,
secret.txt, hello.elf, hello.nxpkg). Exit 0 only if all checks pass."""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "enc.img")
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
def boot(actions, disk, prompt, timeout_prompt=60):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    args = ["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
            "-display", "none", "-serial", f"file:{SERIAL}",
            "-monitor", f"unix:{MON},server,nowait"]
    if disk:
        args += ["-drive", f"file={disk},format=raw,if=ide,index=0"]
    qemu = subprocess.Popen(args)
    ok = True
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        ok &= wait_for(lambda t: prompt in t, timeout_prompt, f"prompt {prompt!r}")
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

ok = True
# Boot 1: correct passphrase, then login and package install on the encrypted disk.
ok1, log1 = boot(["diskpass", "user", "userpass", "cat public.txt", "cat secret.txt",
                  "logout", "root", "rootpass", "pkg install hello.nxpkg",
                  "pkg list", "run hello.elf"],
                 DISK, "Disk passphrase: ")
print("--- boot 1 log ---"); print(log1)
for m in ["Disk unlocked.", "Filesystem mounted", "AES-256-CTR enabled",
          "Welcome, user.", "public data", "cat: cannot read secret.txt",
          "Welcome, root.", "Installed hello 1.0", "hello 1.0", "Hello from ELF"]:
    f = m in log1; print(f"{'FOUND' if f else 'MISSING'} boot1: {m}"); ok = ok and f and ok1
# Boot 2: wrong passphrase three times -> halt, no shell.
ok2, log2 = boot(["wrong1", "wrong2", "wrong3"], DISK, "Disk passphrase: ")
print("--- boot 2 log ---"); print(log2)
for m, should in [("Too many failed attempts. System halted.", True),
                  ("Disk unlocked.", False), ("Filesystem mounted", False),
                  ("user@nxts> ", False), ("root@nxts> ", False)]:
    f = m in log2
    print(f"{'PASS' if f == should else 'FAIL'} boot2: {'found' if should else 'absent'} {m}")
    ok = ok and (f == should)
# Boot 3: aes-test with no disk.
ok3, log3 = boot(["aes-test"], None, "root@nxts> ")
print("--- boot 3 log ---"); print(log3)
for m in ["8ea2b7ca516745bfeafc49904b496089", "AES test PASS"]:
    f = m in log3; print(f"{'FOUND' if f else 'MISSING'} boot3: {m}"); ok = ok and f and ok3
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
