#!/usr/bin/env python3
"""Shell grouping + per-command help test (apps run).

Boots with no disk (setup mode, root, no login) and drives the
shell over the QEMU monitor, proving the grouped help system:
  - bare `help` is a short group index, NOT the old stacked dump
  - `help <group>` lists that group's commands
  - `help <command>` / `help pkg <sub>` / `help castore <sub>`
    print the command's dedicated usage + description
  - group dispatch works: `net ping`, `test csprngtest`,
    `fs ls`, `system ver`, `net castore list`
  - flat aliases still work: `ping`, `csprngtest`
  - unknown help topics are refused with a hint, not a dump
Usage: python3 tests/qemu_test_shell_groups.py <iso> <workdir>
Exit 0 only if all checks pass. QEMU is always terminated.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
# The kernel banner/ver string must match VERSION; read it from
# the repo root instead of hardcoding a release number (a stale
# literal failed this suite on the v1.1.4 ISO, where the kernel
# correctly reported v1.1.4).
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "VERSION")) as _vf:
    VER = _vf.read().strip()
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT waiting for: {label}")
    return False

def boot(actions):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "64",
        "-display", "none", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
    ])
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        if not wait_for(lambda t: "nxts> " in t, 60, "prompt"):
            return False, log_text()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2); s.connect(MON); s.recv(4096)
        def send_text(txt):
            # Monitor sendkey occasionally doubles a key; retry once
            # if the shell reports the mistyped command as unknown.
            for _attempt in range(2):
                before = len(log_text())
                for ch in txt:
                    s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
                s.sendall(b"sendkey ret\n"); time.sleep(1)
                if "Unknown command" not in log_text()[before:]:
                    break
        for txt in actions:
            send_text(txt); time.sleep(0.5)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return True, log_text()

ok = True
_, log = boot([
    "help",
    "help net",
    "help ping",
    "help pkg install",
    "help castore add",
    "net help",
    "net ping 999.1.1.1",
    "ping 999.1.1.1",
    "test csprngtest",
    "csprngtest",
    "fs ls",
    "system ver",
    "net castore list",
    "pkg help",
    "help nosuchcmd",
])
for m in [
    # Group index (bare help).
    "Command groups: system, session, fs, proc, pkg, net, crypto, diag, gui, test",
    "  net: Network, web, and trust stores",
    "  test: Self-tests and autotest scripts",
    "Type 'help <group>' for a group's commands",
    # Group listing.
    "Group net: Network, web, and trust stores",
    "  ping: Ping a dotted-quad IPv4 address; reports reply or no reply.",
    "  castore: Manage the CA store (root for add/update/clear).",
    # Per-command dedicated help.
    "ping (net)",
    "  Usage: ping <ip>",
    "pkg install (pkg)",
    "  Usage: pkg install <file>|<name>",
    "castore add (net)",
    "  Usage: castore add <file>",
    # Group dispatch.
    "ping: bad IP",
    "csprngtest PASS",
    "No filesystem mounted",
    "nxtsOS v" + VER,
    "castore: no store",
    # pkg group help.
    "Group pkg: Packages and system updates",
    "  pkg install: Root only: install a local .nxpkg file, or a named package from the repo.",
    # Unknown help topic.
    "help: no such command or group 'nosuchcmd'",
]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} serial: {m[:60]}"); ok = ok and f
# The old stacked dump must be gone.
for bad in ["Commands: help, mem, ticks, clear, reboot",
            "EXCEPTION", "PANIC"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} serial: absent {bad}"); ok = ok and f
# Group dispatch must have produced the bad-IP line twice
# (once via `net ping`, once via flat `ping`).
n = log.count("ping: bad IP")
f = n >= 2; print(f"{'PASS' if f else 'FAIL'} serial: ping bad-IP count {n} (expect >= 2)"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
