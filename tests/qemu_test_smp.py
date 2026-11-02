#!/usr/bin/env python3
"""SMP / multi-core (CORE_CLI.md section 15.3): AP boots to an
idle loop and signals readiness (never reported before it does),
uniprocessor boot still works, spinlock correctness under
contention (exact counter, no lost updates), PMM allocation
from both CPUs without corruption (disjoint frames, free count
restored), TLB shootdown proof (AP keeps reading via its stale
TLB after the BSP unmaps, then faults only after the shootdown
IPI), CPU affinity visible and honoured, and per-CPU runqueues
scheduling background jobs on both CPUs at once (plus a pended
affinity move for a RUNNING job).

Two boots on the same disk: Boot A with -smp 2 (the SMP proofs),
Boot B with -smp 1 (the uniprocessor path: AP absent, SMP
commands refuse honestly, a background job still runs).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_smp.py <iso> <workdir>
"""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
os.makedirs(WORK, exist_ok=True)
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5",
          "&": "shift-7", "|": "shift-backslash"}
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEYMAP[_c] = "shift-" + _c.lower()

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

def wait_log(needle, timeout, label):
    """Wait for needle anywhere in the whole log (not from POS)."""
    for _ in range(int(timeout * 10)):
        if needle in log_text():
            return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

def wait_log_count(needle, count, timeout, label):
    for _ in range(int(timeout * 10)):
        if log_text().count(needle) >= count:
            return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

def _current_line(t):
    idx = t.rfind("@nxts> ")
    raw = t[idx + len("@nxts> "):] if idx >= 0 else ""
    out = []
    for ch in raw:
        if ch == "\b":
            if out: out.pop()
        elif ch == "\n" or ch == "\r":
            out = []
        else:
            out.append(ch)
    return "".join(out)

def send_verified(s, txt):
    for _attempt in range(3):
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        time.sleep(0.5)
        if _current_line(log_text()) == txt:
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            return True
        for _ in range(len(txt) + 2):
            s.sendall(b"sendkey backspace\n"); time.sleep(0.1)
        time.sleep(0.5)
    s.sendall(b"sendkey ret\n"); time.sleep(1)
    return False

def send_verified_slow(s, txt):
    """Pacing-hardened send, used ONLY for the affinity step typed
    while two busy-spinning longrun jobs load both TCG vCPUs.
    send_verified types at 0.15 s/char with a fixed 0.5 s settle;
    under full load the guest echo never caught up in 0.5 s, so it
    erased the line and retried 3x and the kernel never received
    the command (proven harness race, 49/52). This variant types
    at 0.4 s/char, polls up to 20 s (not a fixed sleep) for the
    echoed line to equal txt before pressing Enter, and on a
    mismatch erases slowly (0.25 s/key) and polls for an empty
    line before retrying (6 attempts). No assertion text, regex,
    or pass criterion is changed by this helper."""
    time.sleep(2)
    for _attempt in range(6):
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.4)
        matched = False
        for _ in range(100):
            if _current_line(log_text()) == txt:
                matched = True; break
            time.sleep(0.2)
        if matched:
            s.sendall(b"sendkey ret\n"); time.sleep(1.5)
            return True
        for _ in range(len(txt) + 2):
            s.sendall(b"sendkey backspace\n"); time.sleep(0.25)
        for _ in range(25):
            if _current_line(log_text()) == "":
                break
            time.sleep(0.2)
        time.sleep(1)
    s.sendall(b"sendkey ret\n"); time.sleep(1.5)
    return False

def send_text(s, txt):
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def sh(s, txt, user):
    before = POS[0]
    send_verified(s, txt)
    for _ in range(4):
        if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt}"):
            try: s.sendall(b"sendkey ret\n")
            except Exception: pass
            time.sleep(1)
            continue
        seg = log_text()[before:POS[0]]
        if f"{txt}\n" in seg:
            return seg
        try: s.sendall(b"sendkey ret\n")
        except Exception: pass
        time.sleep(1)
    return None

def sh_slow(s, txt, user):
    """sh() but via send_verified_slow: same prompt-wait and same
    `txt\\n in seg` return contract, only the send pacing differs.
    Used only for the under-load affinity step below."""
    before = POS[0]
    send_verified_slow(s, txt)
    for _ in range(4):
        if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt}"):
            try: s.sendall(b"sendkey ret\n")
            except Exception: pass
            time.sleep(1)
            continue
        seg = log_text()[before:POS[0]]
        if f"{txt}\n" in seg:
            return seg
        try: s.sendall(b"sendkey ret\n")
        except Exception: pass
        time.sleep(1)
    return None

def login(s, user, pw):
    for attempt in range(4):
        if not wait_from("login: ", 60, f"login prompt {user}"):
            return False
        send_text(s, user)
        if not wait_from("Password: ", 30, f"password prompt {user}"):
            return False
        send_text(s, pw)
        got = None
        for _ in range(300):
            t = log_text()
            if f"Welcome, {user}." in t[POS[0]:]:
                got = "ok"; break
            if "Login incorrect" in t[POS[0]:]:
                got = "bad"; break
            time.sleep(0.1)
        if got == "ok":
            return wait_from(f"{user}@nxts> ", 30, f"shell prompt {user}")
        if got != "bad":
            return False
    return False

def boot(smp):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    POS[0] = 0
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-smp", str(smp),
        "-display", "none", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide"])
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(MON); s.settimeout(2)
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

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

# ---------------- Boot A: -smp 2 ----------------
qemu, s = boot(2)
try:
    check(wait_log("SMP: AP online", 60, "boot dmesg reports AP online"),
          "boot dmesg: AP online (never reported before readiness)")
    check("kmalloc selftest: PASS" in log_text(),
          "boot dmesg: kmalloc selftest still passes")
    check(login(s, "admin", "pwadmin"), "login as admin (smp 2)")
    seg = sh(s, "smp", "admin")
    check(seg is not None and "SMP: 2 CPU(s) online" in seg, "smp status: 2 CPUs online")
    check(seg is not None and "SMP: AP state: idle loop" in seg, "smp status: AP in idle loop")
    check(seg is not None and "SMP: AP jobs run 0, completed 0" in seg, "smp status: AP job stats start at zero")
    seg = sh(s, "cpu", "admin")
    check(seg is not None and "SMP: 2 CPU(s) online, AP online" in seg, "cpu extended with SMP state")
    seg = sh(s, "smp locktest", "admin")
    check(seg is not None and "smp locktest: counter 40000 expected 40000" in seg,
          "spinlock contention: exact counter, no lost updates")
    check(seg is not None and "smp locktest: PASS" in seg, "spinlock contention: PASS")
    seg = sh(s, "smp pmmtest", "admin")
    check(seg is not None and "smp pmmtest: 64 frames disjoint" in seg,
          "PMM from both CPUs: 64 frames disjoint")
    m = re.search(r"smp pmmtest: 64 frames disjoint, free (\d+) -> (\d+)", seg or "")
    check(m is not None and m.group(1) == m.group(2), "PMM from both CPUs: free count restored")
    check(seg is not None and "smp pmmtest: PASS" in seg, "PMM test: PASS")
    seg = sh(s, "smp tlb", "admin")
    check(seg is not None and "fault after shootdown: yes" in seg,
          "TLB shootdown: AP faults only after shootdown")
    check(seg is not None and "shootdown ack: yes" in seg, "TLB shootdown: IPI acked")
    m = re.search(r"smp tlb: stale reads (\d+) -> (\d+) after unmap", seg or "")
    check(m is not None and int(m.group(2)) > int(m.group(1)),
          "TLB shootdown: AP kept reading via stale TLB after unmap")
    check(seg is not None and "smp tlb: TLB shootdown: PROVEN" in seg, "TLB shootdown: PROVEN")
    seg = sh(s, "smp", "admin")
    check(seg is not None and "SMP: shootdowns sent 1, acked 1" in seg, "smp status: shootdown counted + acked")
    seg = sh(s, "help smp", "admin")
    check(seg is not None and "smp (diag)" in seg, "help smp gives a dedicated entry")
    seg = sh(s, "help smp locktest", "admin")
    check(seg is not None and "smp locktest (test)" in seg, "help smp locktest gives a dedicated entry")
    seg = sh(s, "help smp tlb", "admin")
    check(seg is not None and "smp tlb (test)" in seg, "help smp tlb gives a dedicated entry")
    seg = sh(s, "help affinity", "admin")
    check(seg is not None and "affinity (proc)" in seg, "help affinity gives a dedicated entry")
    seg = sh(s, "affinity 999 1", "admin")
    check(seg is not None and "no such job or no permission" in seg, "affinity: unknown job refused")
    seg = sh(s, "affinity", "admin")
    check(seg is not None and "Usage: affinity <pid> <cpu>" in seg, "affinity: bare form prints usage")
    # --- per-CPU runqueues: two jobs, one per CPU, at once ---
    # longrun (60 s), not slow10: the retry-heavy command
    # sequence outlasts a 10 s job, so slow10 jobs finished
    # mid-test and cascaded false failures.
    seg = sh(s, "runbg longrun.elf", "admin")
    check(seg is not None and "Background job longrun.elf started (pid 10" in seg, "runbg longrun (BSP job)")
    seg = sh(s, "runbg longrun.elf", "admin")
    check(seg is not None and "Background job longrun.elf started (pid 11" in seg, "runbg longrun (AP candidate)")
    seg = sh(s, "smp jobs", "admin")
    check(seg is not None and re.search(r"pid 10  longrun\.elf  uid 0  cpu 0", seg or "") is not None,
          "smp jobs: pid 10 on CPU 0")
    check(seg is not None and re.search(r"pid 11  longrun\.elf  uid 0  cpu 0", seg or "") is not None,
          "smp jobs: pid 11 starts on CPU 0")
    # Pacing-hardened send ONLY here: this command is typed while
    # both TCG vCPUs are busy-spinning, which starved the original
    # 0.15 s/char + 0.5 s settle send (see send_verified_slow).
    seg = sh_slow(s, "affinity 11 1", "admin")
    check(seg is not None and "affinity: pid 11 now CPU 1" in seg, "affinity: pid 11 moved to CPU 1")
    seg = sh(s, "smp jobs", "admin")
    check(seg is not None and re.search(r"pid 11  longrun\.elf  uid 0  cpu 1", seg or "") is not None,
          "smp jobs: pid 11 visible on CPU 1")
    # 300s, not 120s: two busy-spinning jobs on two TCG vCPUs share the
    # host translator and finish well past 120s wall (singles take
    # ~60s each, proven by /tmp/timecheck.py 2026-11-01: BSP 64.7s,
    # AP 56.0s). The kernel side is proven; the window is harness-only.
    check(wait_log_count("longrun done", 2, 300, "both longrun jobs print done"),
          "per-CPU runqueues: both jobs complete (one per CPU)")
    check(wait_log("Background job longrun.elf (pid 10) finished", 10, "pid 10 finished line"),
          "per-CPU runqueues: BSP job finished line")
    check(wait_log("Background job longrun.elf (pid 11) finished", 10, "pid 11 finished line"),
          "per-CPU runqueues: AP job finished line")
    seg = sh(s, "smp", "admin")
    m = re.search(r"SMP: AP jobs run (\d+), completed 1", seg or "")
    check(m is not None and int(m.group(1)) > 0,
          "per-CPU runqueues: AP ran the job and completed exactly 1")
    seg = sh(s, "wait 10", "admin")
    check(seg is not None and "wait: job 10 done" in seg and "exit status 0" in seg,
          "reap across CPUs: wait 10 reports BSP job status")
    seg = sh(s, "wait 11", "admin")
    check(seg is not None and "wait: job 11 done" in seg and "exit status 0" in seg,
          "reap across CPUs: wait 11 reports AP job status")
    seg = sh(s, "smp jobs", "admin")
    check(seg is not None and "(no background jobs)" in seg, "smp jobs: empty after both jobs")
    # --- pended affinity move for a RUNNING job ---
    seg = sh(s, "runbg longrun.elf", "admin")
    check(seg is not None and "Background job longrun.elf started (pid 10" in seg, "runbg longrun for pending-move test")
    seg = sh(s, "affinity 10 1", "admin")
    check(seg is not None and "affinity: pid 10 now CPU 1" in seg, "pending test: job moved to CPU 1")
    pending_seen = False
    for _attempt in range(4):
        seg = sh(s, "affinity 10 0", "admin")
        if seg is not None and "will move to CPU 0 at the next tick boundary" in seg:
            pending_seen = True
            break
        seg2 = sh(s, "affinity 10 1", "admin")
        if seg2 is None or "now CPU 1" not in seg2:
            break
    check(pending_seen, "affinity: RUNNING job move pends to the next tick boundary")
    check(wait_log_count("longrun done", 3, 120, "pending-move job finishes"),
          "pending-move job still completes after the move")
    seg = sh(s, "wait 10", "admin")
    check(seg is not None and "wait: job 10 done" in seg, "pending-move job reaped")
finally:
    stop(qemu, s)

# ---------------- Boot B: -smp 1 (UP path) ----------------
qemu, s = boot(1)
try:
    check(wait_log("SMP: 1 CPU", 60, "boot dmesg reports 1 CPU"),
          "UP boot: dmesg reports uniprocessor")
    check(login(s, "admin", "pwadmin"), "login as admin (smp 1)")
    seg = sh(s, "smp", "admin")
    check(seg is not None and "SMP: 1 CPU(s) online" in seg, "UP: smp status reports 1 CPU")
    check(seg is not None and "SMP: AP state: absent" in seg, "UP: AP state absent (never faked)")
    seg = sh(s, "smp locktest", "admin")
    check(seg is not None and "refused (no AP online" in seg, "UP: locktest refuses honestly")
    seg = sh(s, "smp tlb", "admin")
    check(seg is not None and "refused (no AP online" in seg, "UP: tlb refuses honestly")
    seg = sh(s, "smp pmmtest", "admin")
    check(seg is not None and "refused (no AP online" in seg, "UP: pmmtest refuses honestly")
    seg = sh(s, "runbg slow10.elf", "admin")
    check(seg is not None and "Background job slow10.elf started (pid 10" in seg, "UP: background job still starts")
    seg = sh(s, "affinity 10 1", "admin")
    check(seg is not None and "refused (no AP online" in seg, "UP: affinity to CPU 1 refuses honestly")
    check(wait_log("slow10 done", 30, "UP job finishes"),
          "UP: background job still runs to completion")
    seg = sh(s, "wait 10", "admin")
    check(seg is not None and "wait: job 10 done" in seg and "exit status 0" in seg,
          "UP: job reaped with status 0")
finally:
    stop(qemu, s)

print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
