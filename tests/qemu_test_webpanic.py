#!/usr/bin/env python3
"""Web-open kernel panic repro (user report 2026-10-28, v1.1.2 on
Virt-Manager): EXCEPTION 14, eip in net_send, PAGE FAULT at 0x41003810
(the e1000 MMIO virtual base) right after "Desktop: Web opened".

Theory under test: the shell/desktop loop runs with a user page
directory after the first background-job tick (sched_switch_asm never
restores CR3), and user PDs share only PD entries 0-7 + 256
(framebuffer) — NOT entry 260 (0x41000000, e1000 MMIO). So the first
network send while a background job is alive faults on the MMIO read.

Repro (no desktop needed — the shell loop ticks jobs the same way):
boot, dhcp (kernel PD: works), runbg slow.elf (a yield-loop job that
stays alive ~5 s, printing "slow iter N" each second), then ping the
slirp gateway while it is alive. Pre-fix the ping faults; post-fix it
replies. Aliveness is proven by log order: the ping outcome must
appear before "slow done" (or "slow done" must be absent).
Usage: python3 tests/qemu_test_webpanic.py <iso> <workdir>
Exit 0 only if all checks pass."""
import os, socket, subprocess, sys, time

ISO, WORK = sys.argv[1:3]
os.makedirs(WORK, exist_ok=True)
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
DISK = os.path.join(WORK, "disk.img")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

r = subprocess.run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
                    DISK, "--add", f"slow.elf:{os.path.join(ROOT, 'build', 'slow.elf')}"],
                   capture_output=True, text=True)
if r.returncode != 0:
    print(r.stdout, r.stderr); print("RESULT: FAIL (mkdisk)"); sys.exit(1)

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

for p in (SERIAL, MON):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "vnc=:21", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
    "-netdev", "user,id=n0", "-device", "e1000,netdev=n0",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
        print("RESULT: FAIL"); sys.exit(1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
    def send_text(txt):
        for _attempt in range(2):
            before = len(log_text())
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            if "Unknown command" not in log_text()[before:]:
                break
    send_text("dhcp")
    wait_for(lambda t: "net: DHCP ok ip=10.0.2.15" in t, 30, "dhcp")
    send_text("runbg slow.elf")
    ok_job = wait_for(lambda t: "Background job slow.elf started" in t, 30, "job start")
    time.sleep(1)  # shell loop ticks the job -> user PD active
    send_text("ping 10.0.2.2")
    wait_for(lambda t: "ping: reply received" in t or "PANIC" in t or "EXCEPTION" in t, 60, "ping outcome")
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

log = log_text()
ok = True
for m in ["net: DHCP ok ip=10.0.2.15",
          "Background job slow.elf started",
          "ping: reply received"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} {m}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "PAGE FAULT"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} absent {bad}"); ok = ok and f
# Aliveness: ping outcome must precede "slow done" (job still running).
if "slow done" in log:
    outcome_idx = min([log.find(x) for x in ("ping: reply received", "PANIC", "EXCEPTION") if x in log] or [-1])
    alive = outcome_idx >= 0 and log.find("slow done") > outcome_idx
else:
    alive = True
print(f"{'PASS' if alive else 'FAIL'} job alive at ping time"); ok = ok and alive
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
