#!/usr/bin/env python3
"""Desktop-level Web-open panic check (user report 2026-10-28, v1.1.2 on
Virt-Manager): Web opened from the desktop while a background job was
alive panicked in net_send (EXCEPTION 14, PAGE FAULT at 0x41003810).

A test-only yield-loop job (tests/spin.c, compiled here, never exits)
keeps a user page directory active; then desktopwebtest fetches.
desktopwebtest stays in the desktop (it does not return to the shell),
so "repeated opens" is covered by running this test twice (two boots),
not by re-running the mode in one boot. Pre-fix the fetch faults;
post-fix it succeeds.
Usage: python3 tests/qemu_test_webpanic_desktop.py <iso> <workdir>
Exit 0 only if all checks pass."""
import os, socket, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ISO, WORK = sys.argv[1:3]
os.makedirs(WORK, exist_ok=True)
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
DISK = os.path.join(WORK, "disk.img")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

run(["gcc", "-m32", "-ffreestanding", "-O0", "-Wall", "-Wextra",
     "-fno-stack-protector", "-fno-pic", "-fno-pie", "-no-pie", "-nostdlib",
     "-c", os.path.join(ROOT, "tests", "spin.c"),
     "-o", os.path.join(WORK, "spin_main.o")])
run(["gcc", "-m32", "-no-pie", "-Wl,--build-id=none",
     "-T", os.path.join(ROOT, "userland", "linker.ld"), "-nostdlib",
     "-o", os.path.join(WORK, "spin.elf"),
     os.path.join(ROOT, "build", "user_start.o"),
     os.path.join(WORK, "spin_main.o")])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     DISK, "--add", f"spin.elf:{os.path.join(WORK, 'spin.elf')}"])

BODY = b"A" * 20000
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/big.txt":
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *a): pass

srv = ThreadingHTTPServer(("127.0.0.1", 18081), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()

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
    "-display", "vnc=:22", "-serial", f"file:{SERIAL}",
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
    send_text("runbg spin.elf")
    wait_for(lambda t: "Background job spin.elf started" in t, 30, "job start")
    send_text("desktopwebtest")
    wait_for(lambda t: log_text().count("web: truncated at 8192") >= 1, 120, "web fetch")
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
    srv.shutdown()

log = log_text()
ok = True
for m in ["net: DHCP ok ip=10.0.2.15",
          "Background job spin.elf started"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} {m}"); ok = ok and f
n = log.count("web: truncated at 8192")
print(f"{'PASS' if n >= 1 else 'FAIL'} web fetch (got {n}, want >= 1)"); ok = ok and n >= 1
for bad in ["EXCEPTION", "PANIC", "PAGE FAULT"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} absent {bad}"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
