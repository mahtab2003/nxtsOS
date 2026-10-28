#!/usr/bin/env python3
"""Files-window Run test: a desktop-only user must be able to
run a program file sitting on disk without the shell.
Two boots: boot 1 installs calc (so the disk holds calc.nxpkg,
calc.elf, packages.txt in that slot order); boot 2 runs
desktopfileruntest — the kernel autotest mode 13 script:
Files icon, row 1 select (certainly calc.elf), Open (runs
calc as a background job, its Calculator window opens),
Calculator X button (window closes), Terminal icon (desktop
exits). The harness then runs `jobs` on the shell and checks
the fresh output lists calc.elf — the job proof, not just
the markers. The closing of the window is NOT claimed to
finish the job: calc's event loop spins on a missing window
after close (pre-existing launcher behaviour), so `jobs`
still lists it — that is the proof the job really started.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_files_run.py <iso> <workdir>
<workdir> is created by tests/qemu_test_files_run_setup.py.
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

def boot(actions, wait_marker=None, wait_timeout=60, post=None):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:21", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
    ])
    ok = True
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
            return False, log_text()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
        def send_text(txt):
            for _attempt in range(2):
                before = len(log_text())
                for ch in txt:
                    s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
                s.sendall(b"sendkey ret\n"); time.sleep(1)
                if "Unknown command" not in log_text()[before:]:
                    break
        for txt in actions:
            send_text(txt); time.sleep(1)
        if wait_marker:
            ok = wait_for(lambda t: wait_marker in t, wait_timeout, wait_marker)
        if post:
            post(send_text)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return ok, log_text()

def post_desktop(send_text):
    # Mode 13 ends by clicking the Terminal icon, so the desktop
    # has exited and the shell is back; list the background jobs.
    time.sleep(4)
    send_text("jobs"); time.sleep(2)

ok = True
ok1, log1 = boot(["pkg install calc.nxpkg"],
                  wait_marker="Installed calc 1.0",
                  wait_timeout=60)
for m in ["Installed calc 1.0"]:
    f = m in log1; print(f"{'PASS' if f else 'FAIL'} boot1 marker: {m}"); ok = ok and f
ok = ok and ok1

ok2, log2 = boot(["desktopfileruntest"],
                 wait_marker="Window closed: Calculator",
                 wait_timeout=60, post=post_desktop)
for m in ["Desktop: Files opened",
          "Background job calc.elf started",
          "files: started calc.elf",
          "Window closed: Calculator"]:
    f = m in log2; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
ok = ok and ok2
# Job proof: the fresh `jobs` output after the desktop exit
# lists calc.elf (the window close does not finish the job).
tail = log2[log2.rfind("jobs"):]
f = "calc.elf" in tail; print(f"{'PASS' if f else 'FAIL'} jobs lists calc.elf"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log2; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
