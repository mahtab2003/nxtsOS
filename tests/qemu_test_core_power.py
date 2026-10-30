#!/usr/bin/env python3
"""Core power test: shutdown / poweroff / halt / reboot.

Boots (all on the same ISO):
  A (no disk, setup-mode root): `acpi` must report PM1a 0x604
     (regression guard: an earlier build read the FADT EVT block
     at offset 56 instead of the CNT block at 64, so the poweroff
     write went to the status register and silently did nothing);
     usage errors for bad flags; confirm-abort for `n` and for a
     non-y answer (fail-closed); `reboot` still reboots at once.
  B (no disk, root): `shutdown` + answer `y` powers QEMU off
     (process exits on its own, log ends at "Powering off...").
  C (no disk, root): `poweroff --force` powers QEMU off (alias).
  D (no disk, root): `halt --force` prints "System halted." and
     QEMU keeps running with no new prompt (halt, not poweroff).
  E (users.txt disk, alice): every privileged power command is
     refused with a root-only message and the machine keeps
     running ("shutdown: root only" / "halt: root only").

The QEMU sendkey doubling flake is handled by the send_text
retry (same pattern as the chmod test); a doubled confirm answer
is harmless because anything but exactly `y` aborts.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_core_power.py <iso> <workdir>
<workdir> is created by tests/qemu_test_core_power_setup.py.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
POS = [0]

def wait_from(needle, timeout, label):
    for _ in range(int(timeout * 10)):
        t = log_text()
        i = t.find(needle, POS[0])
        if i >= 0:
            POS[0] = i + len(needle)
            return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

def boot(with_disk):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    POS[0] = 0
    args = ["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
            "-display", "none", "-serial", f"file:{SERIAL}",
            "-monitor", f"unix:{MON},server,nowait"]
    if with_disk:
        args += ["-drive", f"file={DISK},format=raw,if=ide,index=0"]
    qemu = subprocess.Popen(args)
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    return qemu, s

def stop(qemu, s):
    try: s.close()
    except Exception: pass
    if qemu.poll() is None:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()

def send_text(s, txt):
    for _attempt in range(2):
        before = len(log_text())
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(1)
        if "Unknown command" not in log_text()[before:]:
            break

def cmd(s, txt, user):
    before = POS[0]
    send_text(s, txt)
    if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt}"):
        return None
    seg = log_text()[before:POS[0]]
    if "Unknown command" in seg:
        if not wait_from(f"{user}@nxts> ", 30, f"retry prompt after {txt}"):
            return None
        seg = log_text()[before:POS[0]]
    return seg

def confirm(s, txt, answer, user, abort_msg):
    """Type a confirm-guarded command, answer the prompt, and
    require the abort message plus a returning prompt."""
    before = POS[0]
    send_text(s, txt)
    if not wait_from("? (y/n) ", 30, f"confirm prompt for {txt}"):
        return None
    send_text(s, answer)
    if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt} {answer}"):
        return None
    seg = log_text()[before:POS[0]]
    return seg if abort_msg in seg else None

def login(s, user, pw):
    if not wait_from("login: ", 60, f"login prompt {user}"): return False
    send_text(s, user)
    if not wait_from("Password: ", 30, f"password prompt {user}"): return False
    send_text(s, pw)
    if not wait_from(f"Welcome, {user}.", 30, f"login result {user}"): return False
    return wait_from(f"{user}@nxts> ", 30, f"shell prompt {user}")

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

# ---- Boot A: diag, usage, confirm-abort, reboot (root, no disk) ----
qemu, s = boot(False)
try:
    check(wait_from("root@nxts> ", 60, "boot A prompt"), "boot A prompt")
    seg = cmd(s, "acpi", "root")
    check(seg is not None and "PM1a 0x604" in seg and "SLP_TYP 0/0" in seg,
          "acpi reports PM1a 0x604 + SLP_TYP 0/0")
    seg = cmd(s, "shutdown --bogus", "root")
    check(seg is not None and "Usage: shutdown [--force]" in seg,
          "shutdown bad flag is a usage error")
    seg = confirm(s, "shutdown", "n", "root", "shutdown: aborted")
    check(seg is not None, "shutdown + n aborts and prompt returns")
    seg = confirm(s, "shutdown", "x", "root", "shutdown: aborted")
    check(seg is not None, "shutdown + non-y aborts (fail-closed)")
    seg = cmd(s, "halt --bogus", "root")
    check(seg is not None and "Usage: halt [--force]" in seg,
          "halt bad flag is a usage error")
    seg = confirm(s, "halt", "n", "root", "halt: aborted")
    check(seg is not None, "halt + n aborts and prompt returns")
    send_text(s, "reboot")
    check(wait_from("root@nxts> ", 60, "prompt after reboot"),
          "reboot restarts the machine at once (unchanged)")
finally:
    stop(qemu, s)

# ---- Boot B: shutdown + y powers off ----
qemu, s = boot(False)
try:
    check(wait_from("root@nxts> ", 60, "boot B prompt"), "boot B prompt")
    send_text(s, "shutdown")
    check(wait_from("? (y/n) ", 30, "boot B confirm prompt"), "boot B confirm prompt")
    send_text(s, "y")
    exited = False
    for _ in range(100):
        if qemu.poll() is not None: exited = True; break
        time.sleep(0.1)
    check(exited and "Powering off..." in log_text(),
          "shutdown + y powers QEMU off")
finally:
    stop(qemu, s)

# ---- Boot C: poweroff --force powers off (alias) ----
qemu, s = boot(False)
try:
    check(wait_from("root@nxts> ", 60, "boot C prompt"), "boot C prompt")
    send_text(s, "poweroff --force")
    exited = False
    for _ in range(100):
        if qemu.poll() is not None: exited = True; break
        time.sleep(0.1)
    check(exited and "Powering off..." in log_text(),
          "poweroff --force powers QEMU off")
finally:
    stop(qemu, s)

# ---- Boot D: halt --force halts, QEMU keeps running ----
qemu, s = boot(False)
try:
    check(wait_from("root@nxts> ", 60, "boot D prompt"), "boot D prompt")
    send_text(s, "halt --force")
    check(wait_from("System halted.", 30, "halt message"), "halt prints System halted.")
    time.sleep(3)
    check(qemu.poll() is None, "halted VM stays present (no poweroff)")
    check("root@nxts> " not in log_text()[POS[0]:], "no new prompt after halt")
finally:
    stop(qemu, s)

# ---- Boot E: non-root refusals (alice) ----
qemu, s = boot(True)
try:
    check(login(s, "alice", "pwalice"), "boot E login alice")
    seg = cmd(s, "shutdown --force", "alice")
    check(seg is not None and "shutdown: root only" in seg,
          "shutdown --force as alice refused")
    seg = cmd(s, "halt --force", "alice")
    check(seg is not None and "halt: root only" in seg,
          "halt --force as alice refused")
    seg = cmd(s, "poweroff", "alice")
    check(seg is not None and "shutdown: root only" in seg,
          "poweroff as alice refused")
    check(qemu.poll() is None, "machine still running after refusals")
finally:
    stop(qemu, s)

print("CORE_POWER TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
