#!/usr/bin/env python3
"""Phase 11 sysupdate test (3 boots, one persistent disk).
Boot 1: sysupdate bundle_good (greet first, hello second) must
install both (bundle-local dependency, order-independent) and both
must run.
Boot 2: sysupdate bundle_bad (good hello 1.1 + wrong-key package)
must be refused as a whole — hello must NOT be installed.
Boot 3: sysupdate bundle_up upgrades hello 1.0 -> 1.1, then
sysrollback restores 1.0, and a second sysrollback reports that
there is nothing to roll back; re-applying bundle_good (both
already installed) is refused as same-version.
Usage: python3 tests/qemu_test_sysupdate.py <iso> <workdir>
<workdir> is created by tests/qemu_test_sysupdate_setup.py.
Exit 0 only if all checks pass.
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
            before = len(log_text())
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            # Sendkey occasionally delivers a doubled key: if the
            # shell reports Unknown command for the fresh portion,
            # retry the command once.
            if "Unknown command" in log_text()[before:]:
                for ch in txt:
                    s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
                s.sendall(b"sendkey ret\n"); time.sleep(1)
        for txt in actions:
            send_text(txt); time.sleep(1)
        time.sleep(1); s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return ok, log_text()

def check(log, marker, should, ok):
    found = marker in log
    good = found if should else not found
    print(f"{'PASS' if good else 'FAIL'}: {'found' if should else 'absent'} {marker}")
    return ok and good

ok, log1 = boot_and_run([
    "sysupdate bundle_good.nxupd", "pkg list",
    "run hello.elf", "run greet.elf",
])
print("--- boot 1 log ---"); print(log1)
for m, s in [("Installed hello 1.0", True), ("Installed greet 1.0", True),
             ("System update complete", True), ("Hello from ELF", True),
             ("Greetings from greet", True)]:
    ok = check(log1, m, s, ok)

ok, log2 = boot_and_run([
    "sysupdate bundle_bad.nxupd", "pkg list", "run hello.elf",
])
print("--- boot 2 log ---"); print(log2)
for m, s in [("bad package signature", True), ("update refused", True),
             ("hello 1.0", True), ("hello 1.1", False),
             ("Hello from ELF", True)]:
    ok = check(log2, m, s, ok)

ok, log3 = boot_and_run([
    "sysupdate bundle_up.nxupd", "run hello.elf",
    "sysrollback", "run hello.elf", "pkg list",
    "sysrollback", "sysupdate bundle_good.nxupd",
])
print("--- boot 3 log ---"); print(log3)
for m, s in [("Upgraded hello to 1.1", True), ("Hello v1.1", True),
             ("Rolled back to the previous version", True),
             ("Hello from ELF", True), ("hello 1.0", True),
             ("no update to roll back", True),
             ("already installed (same version)", True)]:
    ok = check(log3, m, s, ok)
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
