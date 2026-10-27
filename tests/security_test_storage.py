#!/usr/bin/env python3
"""Adversarial storage tests: boot v0.3.0 with corrupt/malicious disk
images and check the kernel rejects them cleanly -- no panic, no hang,
no reboot loop, shell still works -- instead of trusting them.
Also tests a too-long filename via the shell.
Usage: python3 tests/security_test_storage.py <iso> <good_disk> <workdir>
Exit 0 only if every case passes. QEMU is always terminated."""
import os, shutil, socket, struct, subprocess, sys, time

ISO, GOOD, WORK = sys.argv[1:4]
os.makedirs(WORK, exist_ok=True)

def run_case(name, disk, extra_keys=None):
    serial, mon = os.path.join(WORK, name + ".log"), os.path.join(WORK, name + ".sock")
    for p in (serial, mon):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "none", "-serial", f"file:{serial}",
        "-monitor", f"unix:{mon},server,nowait",
        "-drive", f"file={disk},format=raw,if=ide,index=0",
    ])
    try:
        for _ in range(100):
            if os.path.exists(mon): break
            time.sleep(0.1)
        prompt = False
        for _ in range(600):
            try: log = open(serial, errors="replace").read()
            except FileNotFoundError: log = ""
            if "nxts> " in log: prompt = True; break
            time.sleep(0.1)
        extra_ok = True
        if prompt and extra_keys:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(mon); s.settimeout(2)
            try: s.recv(4096)
            except socket.timeout: pass
            for ch in extra_keys:
                k = {" ": "spc", ".": "dot", "-": "minus"}.get(ch, ch)
                s.sendall(f"sendkey {k}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            s.close(); time.sleep(1)
            log = open(serial, errors="replace").read()
            extra_ok = "cannot write" in log
        log = open(serial, errors="replace").read() if os.path.exists(serial) else ""
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    panics = [w for w in ("KERNEL PANIC", "EXCEPTION", "PAGE FAULT") if w in log]
    boots = log.count("nxtsOS kernel starting")
    passed = prompt and not panics and boots == 1 and extra_ok
    print(f"{'PASS' if passed else 'FAIL'}: {name} "
          f"(prompt={prompt}, panics={panics}, boots={boots}, extra_ok={extra_ok})")
    return passed

def corrupt(name, fn):
    disk = os.path.join(WORK, name + ".img")
    shutil.copyfile(GOOD, disk)
    with open(disk, "r+b") as f:
        fn(f)
    return disk

def w32(f, off, val):
    f.seek(off); f.write(struct.pack("<I", val))

cases = []
cases.append(("bad-magic", corrupt("bad-magic", lambda f: f.seek(0) or f.write(b"XXXXXXXX"))))
cases.append(("huge-total", corrupt("huge-total", lambda f: w32(f, 12, 0xFFFFFFFF))))
cases.append(("bad-data-start", corrupt("bad-data-start", lambda f: w32(f, 28, 0))))
# Directory starts at sector 9 (bitmap 8 sectors for 16 MiB). First entry:
# name at 9*512, size at +32, start at +36, count at +40.
DIR0 = 9 * 512
cases.append(("oob-start", corrupt("oob-start", lambda f: (w32(f, DIR0 + 36, 999999), w32(f, DIR0 + 40, 10)))))
cases.append(("huge-size", corrupt("huge-size", lambda f: w32(f, DIR0 + 32, 0xFFFFFF00))))
cases.append(("no-nul-name", corrupt("no-nul-name", lambda f: (f.seek(DIR0), f.write(b"A" * 32)))))
cases.append(("bad-mode", corrupt("bad-mode", lambda f: w32(f, DIR0 + 48, 0xFFFFFFFF))))

results = [run_case(n, d) for n, d in cases]
# Too-long filename (40 chars > 31 limit) on a good disk.
long_name = "a" * 40
results.append(run_case("long-name", GOOD, extra_keys=f"write {long_name} x"))

print("RESULT:", "PASS" if all(results) else "FAIL")
sys.exit(0 if all(results) else 1)
