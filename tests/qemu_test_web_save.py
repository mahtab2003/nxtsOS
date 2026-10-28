#!/usr/bin/env python3
"""Web-window Save test: a desktop-only user must be able
to keep a fetched page on disk without the shell. Single
boot: shell `dhcp` first, then desktopwebsavetest — the
kernel autotest mode 25 script: Start, launcher Web row,
Save press with no fetch (refusal), address field, type
10.0.2.2:18082/small.txt, Fetch (blocking, wide release
range), Save press with an empty name (refusal),
save-field click, type page.txt, Save press (success),
save-field click again, type page.txt again, Save press
(file-exists refusal, the negative control proving the
first save really wrote the file), Terminal icon
(desktop exits). The harness then runs shell `ls` +
`cat page.txt`: the saved bytes must equal the served
page, proving the save is byte-faithful and not just a
marker. Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_web_save.py <iso> <workdir>
<workdir> is created by tests/qemu_test_web_save_setup.py.
The sender verifies the shell's echo of each command and
retypes once on mismatch (the QEMU sendkey-doubling flake
class from the repo test); login typing is not echoed.
"""
import os, socket, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")

BODY = b"nxtsOS web save test\nline two of the saved page\n"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/small.txt":
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *a): pass

srv = ThreadingHTTPServer(("127.0.0.1", 18082), Handler)
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

ok = True
for p in (SERIAL, MON):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "vnc=:25", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
    "-netdev", "user,id=n0", "-device", "e1000,netdev=n0",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    ok &= wait_for(lambda t: "root@nxts> " in t, 60, "shell prompt")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    def send_text(txt):
        for _attempt in range(2):
            before = len(log_text())
            for ch in txt:
                s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            if "Unknown command" not in log_text()[before:]:
                break
    send_text("dhcp")
    ok &= wait_for(lambda t: "net: DHCP ok ip=10.0.2.15" in t, 30, "dhcp")
    send_text("desktopwebsavetest")
    ok &= wait_for(lambda t: "desktopwebsavetest returned" in t, 120, "desktopwebsavetest returned")
    time.sleep(2)
    send_text("ls"); time.sleep(2)
    send_text("cat page.txt"); time.sleep(2)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
    srv.shutdown()

log = log_text()
for m in ["Desktop: Web opened",
          "web: save needs fetch",
          f"web: fetched {len(BODY)} bytes",
          "web: save needs name",
          f"web: saved page.txt {len(BODY)} bytes",
          "web: save exists page.txt",
          "desktopwebsavetest returned"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
# Second, independent proof: after the desktop exit, the
# shell's own `ls` must list page.txt and `cat` must print
# exactly the served bytes — the save is byte-faithful.
ret_pos = log.find("desktopwebsavetest returned")
tail = log[ret_pos:] if ret_pos >= 0 else ""
f = "page.txt" in tail
print(f"{'PASS' if f else 'FAIL'} shell ls lists page.txt"); ok = ok and f
f = BODY.decode() in tail
print(f"{'PASS' if f else 'FAIL'} shell cat page.txt equals served page"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
