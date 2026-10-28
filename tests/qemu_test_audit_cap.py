#!/usr/bin/env python3
"""The audit log's 4096-byte cap must refuse a new entry with a
console warning and leave history intact, instead of truncating.
Filling the log with ~200 real events is not a bounded chunk, so
this test pre-seeds the log instead (see the setup script): one
disk seeded to 4080 bytes, where no login-ok entry can fit, and
one seeded to 4000 bytes, where one must. Two boots, both as
root (no logout: the logout event would also hit the cap and
add a second warning marker, which is not what is measured).
Read-back is by `sha256 audit.log`, NOT `cat`, because only a
hash proves byte identity: cat now walks a file of any size in
1023-byte windows (fs_read_range_as, see
tests/qemu_test_cat_large.py), so `cat audit.log` on a
near-full log displays in full, but display is not a byte
proof. sha256 reads up to 64 KiB, so it hashes the whole log:
- cap disk: the login must print "audit: log full or
  unavailable, event not recorded", and the guest hash must
  equal the seed hash exactly — the refused entry was dropped
  and the seed was neither appended to nor truncated.
- room disk: the login must print NO warning, the guest hash
  must differ from the seed hash, and it must equal
  sha256(seed + "login-ok root <ticks>\\n") for some tick count
  (brute-forced offline) — exactly one login-ok entry appended,
  nothing else changed.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_audit_cap.py <iso> <workdir>
<workdir> is created by tests/qemu_test_audit_cap_setup.py.
"""
import hashlib, os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
MON = os.path.join(WORK, "mon.sock")
WARN = "audit: log full or unavailable, event not recorded"

def make_log_reader(path):
    def log_text():
        try: return open(path, errors="replace").read()
        except FileNotFoundError: return ""
    return log_text
POS = [0]
log_text = None

def wait_from(needle, timeout, label):
    for _ in range(int(timeout * 10)):
        t = log_text()
        i = t.find(needle, POS[0])
        if i >= 0:
            POS[0] = i + len(needle)
            return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

def wait_either(needles, timeout, label):
    for _ in range(int(timeout * 10)):
        t = log_text()
        best = None
        for n in needles:
            i = t.find(n, POS[0])
            if i >= 0 and (best is None or i < best[1]):
                best = (n, i)
        if best:
            POS[0] = best[1] + len(best[0])
            return best[0]
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return None

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus", ":": "shift-semicolon"}
ok = True
SOCK = [None]

def send_text(txt):
    s = SOCK[0]
    for _attempt in range(2):
        before = len(log_text())
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(1)
        if "Unknown command" not in log_text()[before:]:
            break

def boot(serial, disk):
    global log_text
    log_text = make_log_reader(serial)
    POS[0] = 0
    try: os.unlink(serial)
    except FileNotFoundError: pass
    try: os.unlink(MON)
    except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:27", "-serial", f"file:{serial}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={disk},format=raw,if=ide,index=0",
    ])
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    SOCK[0] = s
    return qemu, s

def end_boot(qemu, s):
    s.close()
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

def login(user, pw):
    for _attempt in range(3):
        if not wait_from("login: ", 60, f"login prompt {user}"): return False
        send_text(user)
        if not wait_from("Password: ", 30, f"password prompt {user}"): return False
        send_text(pw)
        got = wait_either([f"Welcome, {user}.", "Login incorrect",
                           "Account locked. Contact root to unlock."],
                          30, f"login result {user}")
        if got == f"Welcome, {user}.":
            return wait_from(f"{user}@nxts> ", 30, f"shell prompt {user}")
        if got != "Login incorrect":
            return False
    return False

def step(name, cond):
    global ok
    print(f"STEP {'PASS' if cond else 'FAIL'} {name}")
    ok = ok and cond

def run_boot(disk, serial):
    qemu, s = boot(serial, disk)
    sha_slice = ""
    try:
        step(f"login root ({os.path.basename(disk)})", login("root", "pwroot"))
        before = len(log_text())
        send_text("sha256 audit.log")
        step(f"shell prompt after sha256 ({os.path.basename(disk)})",
             wait_from("root@nxts> ", 30, "shell prompt after sha256"))
        sha_slice = log_text()[before:]
    finally:
        end_boot(qemu, s)
    return sha_slice, open(serial, errors="replace").read()

cap_slice, cap_log = run_boot(os.path.join(WORK, "disk_cap.img"),
                              os.path.join(WORK, "serial_cap.log"))
room_slice, room_log = run_boot(os.path.join(WORK, "disk_room.img"),
                                os.path.join(WORK, "serial_room.log"))

def guest_hash(slice_text):
    m = re.search(r"\b([0-9a-f]{64})\s+audit\.log\b", slice_text)
    return m.group(1) if m else None

def check(cond, label):
    global ok
    print(f"{'PASS' if cond else 'FAIL'} {label}"); ok = ok and cond
cap_seed = open(os.path.join(WORK, "audit_cap.log"), "rb").read()
room_seed = open(os.path.join(WORK, "audit_room.log"), "rb").read()
cap_seed_hash = hashlib.sha256(cap_seed).hexdigest()
room_seed_hash = hashlib.sha256(room_seed).hexdigest()
cap_guest = guest_hash(cap_slice)
room_guest = guest_hash(room_slice)
print(f"cap seed hash:  {cap_seed_hash}")
print(f"cap guest hash: {cap_guest}")
print(f"room seed hash:  {room_seed_hash}")
print(f"room guest hash: {room_guest}")
check(WARN in cap_log, "cap disk: full-log warning printed at login")
check(cap_guest == cap_seed_hash,
      "cap disk: guest hash equals seed hash, log byte-identical")
check(WARN not in room_log, "room disk: no warning when the entry fits")
check(room_guest is not None, "room disk: guest hash printed")
check(room_guest != room_seed_hash, "room disk: guest hash differs from seed hash")
ticks_hit = None
if room_guest:
    for t in range(300000):
        if hashlib.sha256(room_seed + f"login-ok root {t}\n".encode()).hexdigest() == room_guest:
            ticks_hit = t
            break
check(ticks_hit is not None,
      f"room disk: guest hash equals seed + exactly one login-ok entry (ticks={ticks_hit})")
for label, log in (("cap", cap_log), ("room", room_log)):
    for bad in ("EXCEPTION", "PANIC", "page fault"):
        check(bad not in log, f"{label} disk: no {bad}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
