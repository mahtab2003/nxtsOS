#!/usr/bin/env python3
"""6(c) package-ecosystem test: the new bench package must
install from a signed local repo by name and run.
Single boot, one persistent disk, one HTTP server.
Boot: dhcp, pkg repo, pkg update (v1, 3 packages),
pkg install bench, pkg list, run bench.elf.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_repo_bench.py <iso> <workdir>
<workdir> is created by tests/qemu_test_repo_bench_setup.py.
The sender verifies the shell's echo of each command and
retypes once on mismatch (the QEMU sendkey-doubling flake
class from the repo test); login typing is not echoed.
"""
import os, shutil, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
SERVED = os.path.join(WORK, "served")
PORT = 18083
REPO = f"10.0.2.2:{PORT}"

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus", ":": "shift-semicolon"}

if os.path.isdir(SERVED): shutil.rmtree(SERVED)
shutil.copytree(os.path.join(WORK, "repo_v1"), SERVED)
server = subprocess.Popen([sys.executable, "-m", "http.server", str(PORT),
                           "--bind", "127.0.0.1", "--directory", SERVED],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
ok = True
try:
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
        for act in ["dhcp", f"pkg repo {REPO}", "pkg repo", "pkg update",
                    "pkg install bench", "pkg list", "run bench.elf"]:
            send_text(act); time.sleep(1)
        time.sleep(1); s.close()
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
    for m in [f"Repository set to {REPO}", f"Repository: {REPO}",
              "Repository index updated: 3 package(s), version 1",
              "Installed bench 1.0",
              "bench 1.0  depends: (none)  files: 1",
              "bench: ", " rounds in ", " ticks, checksum "]:
        check(m, True)
    for m in ["EXCEPTION", "PANIC", "page fault"]:
        check(m, False)
finally:
    server.terminate()
    try: server.wait(timeout=5)
    except subprocess.TimeoutExpired: server.kill()
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
