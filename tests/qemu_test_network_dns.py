#!/usr/bin/env python3
"""Network-window Set DNS test: a desktop-only user must be able to
point the resolver at a chosen DNS server without the shell.
Single boot, one persistent disk, default QEMU user networking.
Boot: dhcp (so netinfo prints a DNS line after the desktop exits),
then desktopdnssettest — the kernel autotest mode 20 script: Start,
launcher Network row (Network opens, now 480x360), Set DNS with an
empty field (refused), field click, type "999.1.1.1", Set DNS
(refused: malformed address, field content kept), field click again
(the Set click defocused the field, as with every field window),
backspace x9 to clear, type "1.1.1.1", Set DNS (sets it), Terminal
icon (desktop exits).
The harness then runs `netinfo` on the shell: the dns=1.1.1.1 in
that output is the registry proof, not just the markers (the DHCP
DNS is the slirp gateway, never 1.1.1.1, so the value can only
have come from the desktop Set).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_network_dns.py <iso> <workdir>
<workdir> is created by tests/qemu_test_network_dns_setup.py.
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

ok = True
for p in (SERIAL, MON):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "vnc=:22", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
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
    send_text("dhcp"); time.sleep(1)
    send_text("desktopdnssettest")
    ok &= wait_for(lambda t: "desktopdnssettest returned" in t, 150, "desktopdnssettest returned")
    # Desktop has exited (Terminal icon); the shell prompt is back.
    time.sleep(4)
    send_text("netinfo"); time.sleep(2)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = log_text()
for m in ["Desktop: Network opened",
          "network: dns needs ip",
          "network: dns bad ip 999.1.1.1",
          "network: dns set 1.1.1.1",
          "desktopdnssettest returned"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
# Registry proof: the post-desktop `netinfo` output shows the DNS
# the desktop Set stored (position-checked: after the test's return
# line, so this is the post-desktop output, not an earlier print).
ret_pos = log.find("desktopdnssettest returned")
tail = log[ret_pos:] if ret_pos >= 0 else ""
f = "dns=1.1.1.1" in tail
print(f"{'PASS' if f else 'FAIL'} netinfo after desktop: dns=1.1.1.1"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
