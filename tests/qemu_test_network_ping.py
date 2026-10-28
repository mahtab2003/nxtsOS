#!/usr/bin/env python3
"""Network-window Ping-host test: a desktop-only user must be able to
ping an arbitrary host IP without the shell (Ping gateway only probes
the gateway). Single boot, one persistent disk, default QEMU user
networking. Boot: dhcp (waited for, so the window is configured when
Ping runs), then desktopnetpingtest — the kernel autotest mode 21
script: Start, launcher Network row (Network opens, now 480x400),
Ping with an empty field (refused), ping field click, type
"999.1.1.1", Ping (refused: malformed address, field content kept),
ping field click again (the Ping click defocused the field, as with
every field window), backspace x9 to clear, type "10.0.2.2", Ping
(reply: the slirp host answers ICMP), ping field click again (the
reply cleared the field, so the click only refocuses it), type
"192.0.2.1" (TEST-NET-1, nothing answers), Ping with a wide release
range covering net_ping's 300-tick wait (no reply), Terminal icon
(desktop exits).
Ping changes no registry state, so the markers are the proof here,
not a post-desktop shell command; the reply/no-reply markers can
only have come from the desktop Ping presses.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_network_ping.py <iso> <workdir>
<workdir> is created by tests/qemu_test_network_ping_setup.py.
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
    send_text("dhcp")
    ok &= wait_for(lambda t: "dhcp: configured" in t, 30, "dhcp configured")
    send_text("desktopnetpingtest")
    ok &= wait_for(lambda t: "desktopnetpingtest returned" in t, 180, "desktopnetpingtest returned")
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = log_text()
for m in ["Desktop: Network opened",
          "network: ping needs ip",
          "network: ping bad ip 999.1.1.1",
          "network: ping reply 10.0.2.2",
          "network: ping no reply 192.0.2.1",
          "desktopnetpingtest returned"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
