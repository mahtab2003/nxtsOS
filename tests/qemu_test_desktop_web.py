#!/usr/bin/env python3
"""Phase 10 web test (v0.10.0, mode 7).
A host HTTP server on 127.0.0.1:18081 serves a 20000-byte page at
/big.txt. The guest (slirp) runs `dhcp` for an IP, then
desktopwebtest: Start -> Web -> focus the address field -> type
10.0.2.2:18081/big.txt -> Fetch. The 8192-byte body buffer must
fill and report truncation.
Usage: python3 tests/qemu_test_desktop_web.py <iso> <workdir>
Exit 0 only if all checks pass."""
import os, socket, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ISO, WORK = sys.argv[1:3]
os.makedirs(WORK, exist_ok=True)
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")

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
    "-display", "vnc=:20", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-netdev", "user,id=n0", "-device", "e1000,netdev=n0",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
        print("RESULT: FAIL"); srv.shutdown(); sys.exit(1)
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
    send_text("desktopwebtest")
    wait_for(lambda t: "web: truncated at 8192" in t, 90, "web fetch")
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
    srv.shutdown()

ok = True
log = log_text()
for m in ["net: DHCP ok ip=10.0.2.15", "web: truncated at 8192"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} {m}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} absent {bad}"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
