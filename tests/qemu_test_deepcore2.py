#!/usr/bin/env python3
"""Deep-core suite 2: fd open/read/write/lseek/close, pipe(),
brk, named FIFOs (blocking open pairing across two programs),
flock (NB failure + blocking acquisition), fd permission
rules, mkfifo + FIFO refusal by cat.
One boot (disk from qemu_test_deepcore2_setup.py): admin
for the fd/FIFO/flock tests, su bob for the perm test.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_deepcore2.py <iso> <workdir>
"""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5",
          ",": "comma", "(": "shift-9", ")": "shift-0"}
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEYMAP[_c] = "shift-" + _c.lower()

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
POS = [0]
NOK = [0]
NFAIL = [0]

def check(cond, label):
    if cond:
        NOK[0] += 1; print(f"ok: {label}")
    else:
        NFAIL[0] += 1; print(f"FAIL: {label}")

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

def wait_log(needle, timeout):
    for _ in range(int(timeout * 10)):
        if needle in log_text():
            return True
        time.sleep(0.1)
    return False

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
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def send_text(s, txt):
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

def login(s, user, pw):
    for attempt in range(3):
        if not wait_from("login: ", 60, f"login prompt {user}"):
            return False
        send_text(s, user)
        if not wait_from("Password: ", 30, f"password prompt {user}"):
            return False
        send_blind(s, pw)
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

def su_sh(s, target, pw):
    send_verified(s, f"su {target}")
    for _ in range(3):
        got = wait_either(["Password: ", f"{target}@nxts> "], 30, f"su {target}")
        if got == f"{target}@nxts> ":
            return True
        if got is None:
            return False
        send_blind(s, pw)
    return False

def main():
    qemu, s = boot(DISK)
    try:
        if not login(s, "admin", "pwadmin"):
            print("FAIL: login admin"); return 1
        check(True, "login admin")
        # mkfifo + FIFO refusal by whole-file tools.
        seg = sh(s, "mkfifo testfifo", "admin")
        check(seg is not None and "mkfifo: created testfifo" in seg, "mkfifo creates")
        seg = sh(s, "mkfifo testfifo", "admin")
        check(seg is not None and "mkfifo: cannot create testfifo" in seg,
              "mkfifo duplicate refused")
        seg = sh(s, "cat testfifo", "admin")
        check(seg is not None and "cat: cannot read testfifo" in seg,
              "cat refuses a FIFO")
        # fd + pipe + brk in one program.
        seg = sh(s, "run fdtest.elf", "admin")
        check(seg is not None and "fdtest: PASS" in seg, "fdtest PASS")
        check(seg is not None and "Program fdtest.elf finished" in seg and
              "(status" not in seg, "fdtest exits 0")
        seg = sh(s, "cat fdtest.txt", "admin")
        check(seg is not None and "\nhello-fd\n" in seg,
              "fd-written file readable via shell")
        # FIFO pairing: reader bg (blocks in open), writer fg.
        seg = sh(s, "runbg fiforeader.elf", "admin")
        check(seg is not None and "fiforeader.elf started" in seg, "reader starts")
        time.sleep(2)  # reader must be parked in open, shell responsive
        seg = sh(s, "jobs", "admin")
        check(seg is not None and "fiforeader.elf" in seg, "blocked reader still listed")
        seg = sh(s, "run fifowriter.elf", "admin")
        check(seg is not None and "fifowriter: done" in seg, "writer done")
        check(wait_log("fiforeader: got hello-fifo", 15),
              "reader got the FIFO message")
        check(re.search(r"Background job fiforeader\.elf \(pid \d+\) finished",
                        log_text()) is not None, "reader finished")
        # flock: locker bg holds 5 s; contender fg proves NB fail + blocking win.
        seg = sh(s, "runbg flocklock.elf", "admin")
        check(seg is not None and "flocklock.elf started" in seg, "locker starts")
        check(wait_log("flocklock: locked", 15), "locker holds the lock")
        seg = sh(s, "run flocktry.elf", "admin")
        check(seg is not None and "flocktry: NB would block" in seg,
              "NB lock fails while held")
        check(seg is not None and "flocktry: got lock" in seg,
              "blocking lock wins after release")
        check(wait_log("flocklock: unlocked", 10), "locker released")
        # Permissions as bob.
        check(su_sh(s, "bob", "pwbob"), "su bob")
        seg = sh(s, "run permtest.elf", "bob")
        check(seg is not None and "permtest: secret denied" in seg,
              "fd open of admin 600 file denied")
        check(seg is not None and "permtest: PASS" in seg, "permtest PASS")
        check(su_sh(s, "admin", "pwadmin"), "su admin back")
        seg = sh(s, "cat bobfile.txt", "admin")
        check(seg is not None and "\nbobdata\n" in seg,
              "bob fd-created file readable")
        print(f"DEEPCORE2: {NOK[0]} checks passed, {NFAIL[0]} failed")
        if NFAIL[0] == 0:
            print("PASS")
            return 0
        print("FAIL")
        return 1
    finally:
        stop(qemu, s)

if __name__ == "__main__":
    sys.exit(main())
