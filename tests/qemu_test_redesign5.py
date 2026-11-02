#!/usr/bin/env python3
"""Demand paging + scheduler classes + capabilities (CORE_CLI.md
section 15.4, redesign 5), plus the section 13.2 leftovers that
fit core work (quoting, foreground Ctrl-C, multi-session
foundations). Swap activation and real-time classes are
explicitly OUT (see the section 15.4 notes): the suite proves
their honest refusal / absence, not fake behaviour.

One boot (-smp 1, so vruntime counts come from the BSP tick
only): quoting (single/double/backslash/empty + every old
unquoted form), demand-paged zero pages + out-of-VMA
termination (foreground and background), swap refusal +
slot reporting, capability refusal (root without the bit,
root with the bit, non-root unchanged, session reset on
re-login), vruntime fairness (nice 0 vs nice 15 over a fixed
window, tolerance-based), foreground Ctrl-C with type-ahead
intact, and multi-session refusal honesty.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_redesign5.py <iso> <workdir>
"""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
os.makedirs(WORK, exist_ok=True)
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5",
          "&": "shift-7", "|": "shift-backslash", ";": "semicolon",
          "'": "apostrophe", '"': "shift-apostrophe",
          "\\": "backslash", ">": "shift-dot", "<": "shift-comma"}
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
    for _ in range(int(timeout * 10)):
        if needle in log_text():
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
    # 5 attempts: QEMU sendkey doubling occasionally garbles one
    # typed line (known harness flake class); the kernel side is
    # proven by the same commands passing on other attempts/runs.
    for _attempt in range(5):
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

def send_text_raw(s, txt):
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    time.sleep(0.4)

def send_key(s, key, delay=0.3):
    s.sendall(f"sendkey {key}\n".encode()); time.sleep(delay)

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

def login(s, user, pw):
    for _attempt in range(4):
        if not wait_from("login: ", 60, f"login prompt {user}"):
            return False
        send_text_raw(s, user); send_key(s, "ret", 1.0)
        if not wait_from("Password: ", 30, f"password prompt {user}"):
            return False
        send_text_raw(s, pw); send_key(s, "ret", 1.0)
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

def logout_to_login(s):
    send_verified(s, "logout")
    if not wait_from("login: ", 30, "login prompt after logout"):
        return False
    # Rewind so the following login() finds this same prompt:
    # wait_from consumed it, and login() waits for it again.
    POS[0] -= len("login: ")
    return True

def boot():
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    POS[0] = 0
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-smp", "1",
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

qemu, s = boot()
try:
    check(login(s, "admin", "pwadmin"), "login as admin")
    # ---------- quoting ----------
    seg = sh(s, 'echo "hello world"', "admin")
    check(seg is not None and "\nhello world\n" in seg, "quoting: double quotes group words, quotes stripped")
    seg = sh(s, "echo 'single quoted'", "admin")
    check(seg is not None and "\nsingle quoted\n" in seg, "quoting: single quotes group words, quotes stripped")
    seg = sh(s, "echo a\\ b", "admin")
    check(seg is not None and "\na b\n" in seg, "quoting: backslash escapes a space into one word")
    seg = sh(s, 'echo \\"hi\\"', "admin")
    check(seg is not None and '\n"hi"\n' in seg, "quoting: escaped quotes print literally")
    seg = sh(s, 'echo "a" "" "b"', "admin")
    check(seg is not None and "\na  b\n" in seg, "quoting: empty-string arg survives (double space)")
    seg = sh(s, "echo 'a;b'", "admin")
    check(seg is not None and "\na;b\n" in seg and "Unknown command" not in seg,
          "quoting: semicolon inside quotes is not a chain operator")
    seg = sh(s, 'echo "a|b"', "admin")
    check(seg is not None and "\na|b\n" in seg, "quoting: pipe inside quotes is not a pipeline")
    seg = sh(s, 'echo "abc', "admin")
    check(seg is not None and "quote: unterminated quote" in seg, "quoting: unterminated quote errors, prompt returns")
    seg = sh(s, "echo one; echo two", "admin")
    check(seg is not None and "\none\n" in seg and "\ntwo\n" in seg, "quoting: real chains still split")
    seg = sh(s, "echo piped | cat", "admin")
    check(seg is not None and "\npiped\n" in seg, "quoting: real pipelines still run")
    seg = sh(s, 'write qw.txt "hello world"', "admin")
    check(seg is not None and "Wrote qw.txt" in seg, "quoting: write stores quoted text")
    seg = sh(s, "cat qw.txt", "admin")
    check(seg is not None and "\nhello world\n" in seg, "quoting: cat shows text without quotes")
    seg = sh(s, 'grep "hello world" qw.txt', "admin")
    check(seg is not None and "\nhello world\n" in seg, "quoting: grep pattern with a space")
    seg = sh(s, "write qempty.txt ''", "admin")
    check(seg is not None and "Wrote qempty.txt" in seg, "quoting: write with empty quoted text")
    seg = sh(s, "cat qempty.txt", "admin")
    # cat appends its terminating newline even for an empty file,
    # so the proof is: nothing but that newline before the prompt.
    check(seg is not None and "cat qempty.txt\n\nadmin@nxts> " in seg, "quoting: empty file cats to nothing")
    # old unquoted forms
    seg = sh(s, "echo hello world", "admin")
    check(seg is not None and "\nhello world\n" in seg, "quoting: old unquoted echo unchanged")
    seg = sh(s, "write qu.txt plain text here", "admin")
    check(seg is not None and "Wrote qu.txt" in seg, "quoting: old unquoted write unchanged")
    seg = sh(s, "cat qu.txt", "admin")
    check(seg is not None and "\nplain text here\n" in seg, "quoting: old unquoted cat unchanged")
    seg = sh(s, "alias q 'echo quoted'", "admin")
    seg2 = sh(s, "q", "admin")
    check(seg2 is not None and "\nquoted\n" in seg2, "quoting: parity2 alias-with-quotes form still works")
    # ---------- capabilities (admin) ----------
    seg = sh(s, "cap list", "admin")
    check(seg is not None and "cap_cap" in seg and "cap_net" in seg and "7 of 7 set" in seg,
          "caps: root starts with all 7 bits set")
    seg = sh(s, "cap drop cap_net", "admin")
    check(seg is not None and "cap: cap_net dropped" in seg, "caps: drop reports the bit")
    seg = sh(s, "fw enable", "admin")
    check(seg is not None and "capability cap_net is not set" in seg, "caps: root without cap_net is refused")
    check(logout_to_login(s), "caps: logout after drop")
    check(login(s, "admin", "pwadmin"), "caps: re-login as admin")
    seg = sh(s, "cap list", "admin")
    check(seg is not None and "cap_net" in seg and "7 of 7 set" in seg,
          "caps: dropped bit is restored by re-login (session-scoped)")
    seg = sh(s, "cap drop cap_net", "admin")
    seg = sh(s, "fw enable", "admin")
    check(seg is not None and "capability cap_net is not set" in seg, "caps: refusal repeats after re-drop")
    seg = sh(s, "cap grant cap_net", "admin")
    check(seg is not None and "cap: cap_net granted" in seg, "caps: grant reports the bit")
    seg = sh(s, "fw enable", "admin")
    check(seg is not None and "fw: enabled" in seg, "caps: root with the bit passes")
    seg = sh(s, "fw disable", "admin")
    check(seg is not None and "fw: disabled" in seg, "caps: firewall restored to disabled")
    seg = sh(s, "cap bogus", "admin")
    check(seg is not None and "Usage: cap" in seg, "caps: unknown subcommand prints usage")
    seg = sh(s, "mac status", "admin")
    check(seg is not None and "no policy loaded" in seg, "caps: MAC honestly reports no policy engine")
    # ---------- non-root unchanged ----------
    check(logout_to_login(s), "caps: logout to alice")
    check(login(s, "alice", "pwalice"), "caps: login as alice")
    seg = sh(s, "fw enable", "alice")
    check(seg is not None and "fw: root only" in seg, "caps: non-root refusal text unchanged")
    seg = sh(s, "cap list", "alice")
    check(seg is not None and "(none)" in seg and "0 of 7 set" in seg, "caps: non-root session has no bits")
    check(logout_to_login(s), "caps: logout from alice")
    check(login(s, "admin", "pwadmin"), "caps: back to admin")
    # ---------- demand paging ----------
    seg = sh(s, "vma", "admin")
    check(seg is not None and "demand faults handled 0" in seg, "paging: no faults before any VMA use")
    seg = sh(s, "run pagetest.elf", "admin")
    check(seg is not None and "pagetest: vma ok" in seg, "paging: VMA registered")
    check(seg is not None and "pagetest: zero page ok" in seg, "paging: fault inside VMA resumes with zeroed content")
    check(seg is not None and "pagetest: readback ok" in seg, "paging: written zero page reads back")
    check(seg is not None and "pagetest: second page ok" in seg, "paging: second page faults independently")
    check(seg is not None and "outside any VMA" in seg, "paging: fault outside any VMA fails (never silent)")
    check(seg is not None and "finished (status 139)" in seg, "paging: out-of-VMA fault ends the process with status 139")
    check(seg is not None and "bad access SURVIVED" not in seg, "paging: bad access never survives")
    check("Program pagetest.elf finished" in (seg or "") and wait_log("admin@nxts> ", 5, "prompt after fault"),
          "paging: shell prompt returns after the fault (kernel survives)")
    seg = sh(s, "runbg pagetest.elf", "admin")
    check(seg is not None and "Background job pagetest.elf started (pid 10" in seg, "paging: background pagetest starts")
    check(wait_log("Background job pagetest.elf (pid 10) finished", 30, "bg pagetest finished"),
          "paging: background fault reaped by the tick")
    seg = sh(s, "wait 10", "admin")
    check(seg is not None and "wait: job 10 done" in seg and "exit status 139" in seg,
          "paging: background fault reaps with status 139")
    seg = sh(s, "vma", "admin")
    m = re.search(r"demand faults handled (\d+), pages mapped (\d+)", seg or "")
    check(m is not None and int(m.group(1)) >= 4 and int(m.group(2)) == int(m.group(1)),
          "paging: fault/page counters agree (2 faults per pagetest run)")
    # ---------- swap: defined-only, honestly refused ----------
    seg = sh(s, "swapon", "admin")
    check(seg is not None and "swapon: refused" in seg and "no swap area configured" in seg,
          "swap: swapon refuses (no backing area)")
    seg = sh(s, "swapoff", "admin")
    check(seg is not None and "no swap area is active" in seg, "swap: swapoff reports nothing active")
    seg = sh(s, "swapinfo", "admin")
    check(seg is not None and "256 total, 0 in use" in seg and "no pages are swapped" in seg,
          "swap: slot allocator reports 256 slots, 0 in use, nothing swapped")
    seg = sh(s, "blk", "admin")
    check(seg is not None and "slot allocator ready" in seg, "swap: blk status names the allocator, claims no activation")
    # ---------- multi-session foundations ----------
    seg = sh(s, "sessions", "admin")
    check(seg is not None and "session 0: admin (uid 0) active (console)" in seg,
          "sessions: one active console session listed")
    seg = sh(s, "sessions new", "admin")
    check(seg is not None and "refused" in seg and "only one console" in seg,
          "sessions: additional session refused honestly")
    # ---------- help entries ----------
    for cmd, grp in (("cap", "session"), ("mac", "session"), ("sessions", "session"),
                     ("swapinfo", "fs"), ("vma", "diag")):
        seg = sh(s, f"help {cmd}", "admin")
        check(seg is not None and f"{cmd} ({grp})" in seg, f"help: {cmd} has a dedicated entry")
    # ---------- vruntime fairness ----------
    seg = sh(s, "nice -n 0 runbg longrun.elf", "admin")
    check(seg is not None and "nice: started longrun.elf with nice 0" in seg, "sched: nice 0 job starts")
    seg = sh(s, "nice -n 15 runbg longrun.elf", "admin")
    check(seg is not None and "nice: started longrun.elf with nice 15" in seg, "sched: nice 15 job starts")
    seg = sh(s, "cap show 10", "admin")
    check(seg is not None and "cap_cap" in seg and "cap_net" in seg,
          "caps: background job inherits the session mask")
    seg = sh(s, "sched", "admin")
    check(seg is not None and "nice 0" in seg and "nice 15" in seg, "sched: plain sched still shows nice values")
    time.sleep(28)
    seg = sh(s, "sched -v", "admin")
    m0 = re.search(r"pid 10  longrun\.elf  uid 0  nice 0  runs (\d+)", seg or "")
    m1 = re.search(r"pid 11  longrun\.elf  uid 0  nice 15  runs (\d+)", seg or "")
    check(m0 is not None and m1 is not None, "sched: both vruntime jobs still listed")
    if m0 is not None and m1 is not None:
        r0, r1 = int(m0.group(1)), int(m1.group(1))
        print(f"vruntime runs: nice0={r0} nice15={r1}")
        check(r1 > 0, "sched: high-nice job still gets runs (no starvation)")
        check(r0 > 3 * r1, "sched: low-nice job runs proportionally more (tolerance: >3x)")
    check(seg is not None and "weight 1024" in seg and "weight 36" in seg,
          "sched: vruntime weights shown (1024 for nice 0, 36 for nice 15)")
    seg = sh(s, "kill 10", "admin")
    check(seg is not None and "Killed background job pid 10" in seg, "sched: nice 0 job killed")
    seg = sh(s, "kill 11", "admin")
    check(seg is not None and "Killed background job pid 11" in seg, "sched: nice 15 job killed")
    seg = sh(s, "jobs", "admin")
    check(seg is not None and "(no background jobs)" in seg, "sched: job table empty after kills")
    # ---------- foreground Ctrl-C ----------
    send_verified(s, "run longrun.elf")
    check(wait_log("longrun start", 30, "fg longrun started"), "ctrl-c: foreground job starts")
    time.sleep(2)
    send_text_raw(s, "echo intact"); send_key(s, "ret", 1.0)
    time.sleep(0.5)
    send_key(s, "ctrl-c", 0.5)
    check(wait_log("interrupted (SIGINT)", 30, "fg interrupted"), "ctrl-c: foreground job interrupted")
    check(wait_from("admin@nxts> ", 30, "prompt after ctrl-c"), "ctrl-c: shell prompt returns")
    t = log_text()
    i_int = t.find("interrupted (SIGINT)")
    i_echo = t.find("\nintact\n", i_int)
    check(i_int >= 0 and i_echo > i_int, "ctrl-c: typed-ahead input survives (echo intact runs after)")
    check("Program longrun.elf finished" not in t, "ctrl-c: interrupted job never reports a normal finish")
    seg = sh(s, "jobs", "admin")
    check(seg is not None and "(no background jobs)" in seg, "ctrl-c: no stray jobs at the end")
finally:
    stop(qemu, s)

print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
