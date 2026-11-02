#!/usr/bin/env python3
"""Linux-comparability run, suite 1: system/session/proc/net/
fs/pkg surface (who, hostname, dmesg, log, last, nproc,
pci -v, lsusb, iostat, vmstat, sensors, uptime -p/-s, free -h,
sched/nice/renice, ln/readlink + link-following writes,
pwd, locale, ip addr/link/route, hosts + dns hosts-first,
pkg search, honest refusals) + sudo (member, wrong password,
-l, refused commands, non-member) across su switches.

One boot (disk from qemu_test_linuxcomp_setup.py): login as
admin (uid 0) for the root tests, su bob for the sudo tests,
su carol for the non-member test.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_linuxcomp.py <iso> <workdir>
"""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5"}

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

def wait_either(needles, timeout, label):
    for _ in range(int(timeout * 10)):
        t = log_text()
        for nd in needles:
            i = t.find(nd, POS[0])
            if i >= 0:
                POS[0] = i + len(nd)
                return nd
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return None

def boot(disk):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    POS[0] = 0
    qemu = subprocess.Popen(["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
            "-display", "none", "-serial", f"file:{SERIAL}",
            "-monitor", f"unix:{MON},server,nowait",
            "-drive", f"file={disk},format=raw,if=ide"])
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

def _current_line(t):
    # Job-aware (parity_fg lesson): a background job's print
    # between the prompt and the typed echo must not blind the
    # check, so the current line follows the LAST newline
    # (reset on newline) instead of stopping at the first.
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

def send_blind(s, txt):
    """Password-style send: no echo to verify against."""
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def send_text(s, txt):
    """Blind send for the login prompt: send_verified cannot work
    there (no @nxts> prompt exists yet to verify against), and
    its backspace retries would erase the typed username."""
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def sh(s, txt, user):
    before = POS[0]
    send_verified(s, txt)
    seg = None
    for _ in range(3):
        if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt}"):
            return None
        seg = log_text()[before:POS[0]]
        if f"{txt}\n" in seg:
            break
    return seg

def dmesg_sh(s, txt, user):
    """dmesg output contains old prompt-like strings (the ring
    logs every console line, including old prompts), so the
    plain sh() prompt-wait returns early and leaves POS
    mid-output. Instead: send, wait for quiescence with the
    real prompt at the tail, then re-sync POS to end-of-log
    and return the full slice."""
    before = POS[0]
    send_verified(s, txt)
    for _ in range(60):
        time.sleep(0.5)
        t = log_text()
        if t.endswith(f"{user}@nxts> ") and len(t) == len(log_text()):
            time.sleep(0.5)
            if len(log_text()) == len(t):
                break
    POS[0] = len(log_text())
    return log_text()[before:POS[0]]

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

def ordered(seg, needles, label):
    pos = -1
    good = seg is not None
    for nd in needles:
        i = seg.find(nd, pos + 1) if good else -1
        if i < 0: good = False; break
        pos = i
    check(good, label)

def login(s, user, pw):
    """Up to 3 attempts (sendkey flakes can corrupt a password).
    Success is the "Welcome, <user>." line, as in core_users."""
    for attempt in range(3):
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
        print(f"NOTE: login retry {user} (attempt {attempt + 1})")
    return False

def sudo_with_pw(s, cmd, pw, user):
    """Run `sudo <cmd>` as `user`, answering the password prompt
    with pw (once per prompt, up to 3 prompts). Returns the
    segment from the command to the returning prompt."""
    before = POS[0]
    send_verified(s, f"sudo {cmd}")
    for _ in range(3):
        got = wait_either(["Password: ", f"{user}@nxts> "], 30, f"sudo prompt {cmd}")
        if got == f"{user}@nxts> ":
            break
        if got is None:
            break
        send_blind(s, pw)
    seg = log_text()[before:POS[0]]
    return seg

qemu, s = boot(DISK)
try:
    check(login(s, "admin", "pwadmin"), "login as admin")
    seg = sh(s, "who", "admin")
    check(seg is not None and "admin" in seg and "console" in seg, "who shows session user on console")
    seg = sh(s, "hostname", "admin")
    check(seg is not None and "\nnxts\n" in seg, "hostname default is nxts")
    seg = sh(s, "hostname testhost", "admin")
    check(seg is not None and "hostname set to testhost" in seg, "hostname set (root)")
    seg = sh(s, "hostname", "admin")
    check(seg is not None and "\ntesthost\n" in seg, "hostname reads back")
    seg = dmesg_sh(s, "dmesg", "admin")
    check(seg is not None and "Welcome to nxtsOS" in seg, "dmesg shows boot log")
    seg = dmesg_sh(s, "dmesg -c", "admin")
    check(seg is not None and "dmesg: cleared" in seg, "dmesg -c clears (root)")
    seg = dmesg_sh(s, "dmesg", "admin")
    check(seg is not None and "Welcome to nxtsOS" not in seg and "dmesg: cleared" in seg,
          "dmesg after clear has no boot lines")
    seg = sh(s, "log", "admin")
    check(seg is not None and "login-ok" in seg, "log shows audit lines (root)")
    seg = sh(s, "log -n 2", "admin")
    check(seg is not None and "login-ok" in seg, "log -n 2 tails audit lines")
    seg = sh(s, "last", "admin")
    check(seg is not None and "login-ok" in seg, "last shows login lines (root)")
    seg = sh(s, "nproc", "admin")
    check(seg is not None and re.search(r"\n[1-9][0-9]*\n", seg or "") is not None, "nproc prints a cpu count >= 1")
    seg = sh(s, "pci -v", "admin")
    check(seg is not None and "BAR0" in seg and "BAR5" in seg, "pci -v shows BARs")
    seg = sh(s, "lsusb", "admin")
    check(seg is not None and "USB controllers on PCI:" in seg and "not enumerated" in seg,
          "lsusb lists controllers + honest device note")
    seg = sh(s, "iostat", "admin")
    check(seg is not None and "sectors read" in seg and "sectors total" in seg, "iostat shows disk counters")
    seg = sh(s, "vmstat", "admin")
    check(seg is not None and "Memory:" in seg and "swap: 0" in seg, "vmstat shows memory + no swap")
    seg = sh(s, "sensors", "admin")
    check(seg is not None and "no temperature" in seg and "No values are reported" in seg,
          "sensors reports absence, invents nothing")
    seg = sh(s, "uptime -p", "admin")
    check(seg is not None and "up " in seg and "day(s)" in seg and "minute(s)" in seg, "uptime -p pretty form")
    seg = sh(s, "uptime -s", "admin")
    check(seg is not None and re.search(r"\n20\d\d-\d\d-\d\d \d\d:\d\d:\d\d\n", seg or "") is not None,
          "uptime -s prints a boot date-time")
    seg = sh(s, "free -h", "admin")
    check(seg is not None and "MiB" in seg, "free -h prints MiB")
    seg = sh(s, "nice runbg longrun.elf", "admin")
    check(seg is not None and "nice: started longrun.elf with nice 0" in seg, "bare nice starts a job with nice 0")
    seg = sh(s, "kill %1", "admin")
    check(seg is not None, "kill %1 cleans up the bare-nice job")
    seg = sh(s, "nice -n 5 runbg longrun.elf", "admin")
    check(seg is not None and "nice: started longrun.elf with nice 5" in seg, "nice starts a job with nice 5")
    # The job's one "longrun start" print races send_verified's
    # echo check; let it flush before typing sched.
    time.sleep(2)
    seg = sh(s, "sched", "admin")
    check(seg is not None and "nice 5" in seg, "sched shows the nice value")
    seg = sh(s, "renice 10 %1", "admin")
    check(seg is not None and "nice 5 -> 10" in seg, "renice changes nice 5 -> 10")
    seg = sh(s, "sched", "admin")
    check(seg is not None and "nice 10" in seg, "sched shows reniced value")
    seg = sh(s, "kill %1", "admin")
    check(seg is not None, "kill %1 returns to prompt")
    seg = sh(s, "ln -s a.txt link1", "admin")
    check(seg is not None and "Linked link1 -> a.txt" in seg, "ln -s creates a link")
    seg = sh(s, "readlink link1", "admin")
    check(seg is not None and "\na.txt\n" in seg, "readlink prints the target")
    seg = sh(s, "cat link1", "admin")
    check(seg is not None and "alpha content" in seg, "cat follows the link")
    seg = sh(s, "write link1 beta content", "admin")
    check(seg is not None and "Wrote link1" in seg, "write through link accepted")
    seg = sh(s, "cat a.txt", "admin")
    check(seg is not None and "beta content" in seg, "write through link changed the target")
    seg = sh(s, "ln -s missing.txt dang", "admin")
    check(seg is not None and "Linked dang -> missing.txt" in seg, "dangling link created")
    seg = sh(s, "write dang hello", "admin")
    check(seg is not None and "Wrote dang" in seg, "write through dangling link creates target")
    seg = sh(s, "cat dang", "admin")
    check(seg is not None and "hello" in seg, "dangling link now reads its target")
    seg = sh(s, "ln -s loop2 loop1", "admin")
    seg = sh(s, "ln -s loop1 loop2", "admin")
    seg = sh(s, "cat loop1", "admin")
    check(seg is not None and "cannot read" in seg, "link loop fails visibly")
    seg = sh(s, "ln a.txt hard1", "admin")
    check(seg is not None and "Linked hard1 to a.txt" in seg, "plain ln creates a hard link (CORE_CLI section 15)")
    seg = sh(s, "cat hard1", "admin")
    check(seg is not None and "beta content" in seg, "hard link reads the shared data")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and "\n/\n" in seg, "pwd prints /")
    seg = sh(s, "locale", "admin")
    check(seg is not None and "LANG=C" in seg and "LC_ALL=C" in seg, "locale prints the honest C locale")
    seg = sh(s, "ip addr", "admin")
    check(seg is not None and "no IP address" in seg, "ip addr reports no address without dhcp")
    seg = sh(s, "ip link", "admin")
    check(seg is not None and "e1000" in seg and "up" in seg, "ip link shows the NIC")
    seg = sh(s, "ip route", "admin")
    check(seg is not None and "route: no IP address" in seg, "ip route reports no route without dhcp")
    seg = sh(s, "hosts", "admin")
    check(seg is not None and "10.0.2.99 testbox" in seg, "hosts lists hosts.txt")
    seg = sh(s, "dns testbox", "admin")
    check(seg is not None and "dns: testbox = 10.0.2.99 (hosts.txt)" in seg, "dns consults hosts.txt first")
    seg = sh(s, "pkg search calc", "admin")
    check(seg is not None and "calc 1.0" in seg, "pkg search finds calc in the index")
    seg = sh(s, "pkg search zzznope", "admin")
    check(seg is not None and "(no packages matching zzznope)" in seg, "pkg search reports no match")
    for cmd, needle in [("cd foo", "no such directory"), ("mkdir foo", "mkdir: created foo"),
                        ("tar", "DEFLATE"), ("iw", "no wireless"), ("crontab", "no daemon"),
                        ("bg", "use runbg"), ("awk", "pattern language")]:
        seg = sh(s, cmd, "admin")
        check(seg is not None and needle in seg and "Unknown command" not in seg,
              f"refusal for {cmd} ({needle})")
    # --- sudo tests as bob ---
    seg = sh(s, "su bob", "bob")
    check(seg is not None, "su bob (root needs no password)")
    seg = sh(s, "hostname other", "bob")
    check(seg is not None and "hostname: root only" in seg, "hostname set refused for non-root")
    seg = sh(s, "dmesg -c", "bob")
    check(seg is not None and "dmesg: root only" in seg, "dmesg -c refused for non-root")
    seg = sh(s, "log", "bob")
    check(seg is not None and "log: root only" in seg, "log refused for non-root")
    seg = sh(s, "nice -n -5 runbg longrun.elf", "bob")
    check(seg is not None and "negative nice needs root" in seg, "negative nice refused for non-root")
    seg = sh(s, "sudo logout", "bob")
    check(seg is not None and "session/interactive commands cannot run under sudo" in seg,
          "sudo refuses session commands without logging out")
    # Wrong password 3x: send sudo, answer each prompt wrong.
    before = POS[0]
    send_verified(s, "sudo log")
    for _ in range(3):
        got = wait_either(["Password: ", "bob@nxts> "], 30, "sudo wrong-pw prompt")
        if got == "bob@nxts> ":
            break
        if got is None:
            break
        send_blind(s, "wrongpw")
    wait_from("bob@nxts> ", 30, "bob prompt after wrong passwords")
    seg = log_text()[before:POS[0]]
    check("3 incorrect password attempts" in seg, "sudo wrong password 3x refused")
    seg = sudo_with_pw(s, "log", "pwbob", "bob")
    check("login-ok" in seg, "sudo log runs as root after correct password")
    seg = sudo_with_pw(s, "-l", "pwbob", "bob")
    check("User bob may run ALL commands as root" in seg, "sudo -l shows ALL after password check")
    # su from bob needs carol's password (echo off, so sh() cannot
    # be used: it would mistake the password prompt for a prompt).
    before = POS[0]
    send_verified(s, "su carol")
    got = wait_from("Password: ", 30, "su carol password prompt")
    if got:
        send_blind(s, "pwcarol")
        check(wait_from("carol@nxts> ", 30, "carol prompt after su"), "su carol with password")
    else:
        check(False, "su carol with password")
    seg = sh(s, "sudo log", "carol")
    check(seg is not None and "sudo: carol is not in the sudoers file" in seg,
          "sudo refused for non-member without a password prompt")
finally:
    stop(qemu, s)
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
