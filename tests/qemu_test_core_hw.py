#!/usr/bin/env python3
"""Core hardware/resources test (family (a)) + date (family (f)).

Covers the deliverable smoke from the design run as a real
test: cpu/pci/disk/mem/ticks/uptime/sysinfo/ps/top, grouped
forms (diag cpu, system uptime, system sysinfo, proc ps,
system date), help entries, and the date command's format.
Top's liveness is proven by advancing uptime seconds across
refreshes, not by a single screenshot; its quit is proven by
"top: quit" + a returning prompt. Uses the verified sender
from the firewall test: QEMU sendkey occasionally doubles a
key, so commands are typed without Enter, the echo is
verified, and only then is Enter sent — a garble is
backspaced and retyped, never executed.
Boots (all on the same ISO):
  1 (fresh blank disk, setup root): full command surface.
  2 (no drive, CD-ROM only): disk reports ATA present but
     filesystem not mounted; top/sysinfo show the same
     no-filesystem lines.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_core_hw.py <iso> <workdir>
<workdir> is created by tests/qemu_test_core_hw_setup.py.
"""
import os, re, shutil, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
BLANK = os.path.join(WORK, "blank.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "/": "slash", ":": "shift-semicolon"}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION = open(os.path.join(ROOT, "VERSION")).read().strip()

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

def boot(disk):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    POS[0] = 0
    args = ["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
            "-display", "none", "-serial", f"file:{SERIAL}",
            "-monitor", f"unix:{MON},server,nowait"]
    if disk:
        args += ["-drive", f"file={disk},format=raw,if=ide,index=0"]
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

def _current_line(t):
    idx = t.rfind("@nxts> ")
    raw = t[idx + len("@nxts> "):] if idx >= 0 else ""
    out = []
    for ch in raw:
        if ch == "\b":
            if out: out.pop()
        elif ch == "\n" or ch == "\r":
            break
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

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

def fresh_blank(name):
    dst = os.path.join(WORK, name)
    shutil.copyfile(BLANK, dst)
    return dst

def top_run(s, user):
    """Start top, wait for 2+ refreshes, quit with q.
    Returns (headers, quit_ok): headers = list of uptime
    totals in seconds parsed from refresh lines."""
    send_verified(s, "top")
    time.sleep(2.5)
    s.sendall(b"sendkey q\n"); time.sleep(1.0)
    quit_ok = wait_from("top: quit", 15, "top quit")
    if quit_ok:
        quit_ok = wait_from(f"{user}@nxts> ", 30, "prompt after top")
    t = log_text()
    secs = []
    for m in re.finditer(r"nxtsOS top - uptime (\d+) day\(s\) (\d+):(\d+):(\d+)", t):
        d, h, mi, sec = map(int, m.groups())
        secs.append(d * 86400 + h * 3600 + mi * 60 + sec)
    return secs, quit_ok

# ---- Boot 1: full surface on a blank disk ----
qemu, s = boot(fresh_blank("hw1.img"))
try:
    check(wait_from("root@nxts> ", 60, "boot 1 prompt"), "boot 1 prompt")
    seg = sh(s, "cpu", "root")
    check(seg is not None and re.search(r"CPU vendor: \S+", seg) is not None, "cpu vendor")
    check(seg is not None and "CPU brand: " in seg, "cpu brand")
    check(seg is not None and re.search(r"CPU family \d+ model \d+ stepping \d+", seg) is not None, "cpu family/model/stepping")
    check(seg is not None and "cpuid not available" not in seg, "cpu cpuid present")
    seg = sh(s, "pci", "root")
    check(seg is not None and "PCI bus 0:" in seg, "pci header")
    check(seg is not None and "8086:1237" in seg and "1234:1111" in seg, "pci host bridge + vga")
    check(seg is not None and re.search(r"\(\d+ PCI device\(s\)\)", seg) is not None, "pci count line")
    check(seg is not None and "BAR0 0x" in seg, "pci bar0")
    seg = sh(s, "disk", "root")
    m = re.search(r"Disk: (\d+) sectors total \((\d+) MiB\), (\d+) sectors free \((\d+) MiB\)", seg or "")
    check(m is not None and int(m.group(1)) == 32768 and int(m.group(3)) < int(m.group(1)), "disk sectors form")
    seg = sh(s, "mem", "root")
    check(seg is not None and re.search(r"Memory: total \d+ frames \(\d+ KiB\), free \d+ frames", seg) is not None, "mem frames")
    seg = sh(s, "ticks", "root")
    check(seg is not None and re.search(r"Timer ticks: \d+ \(\d+ seconds at 100 Hz\)", seg) is not None, "ticks")
    seg = sh(s, "uptime", "root")
    check(seg is not None and re.search(r"Uptime: \d+ day\(s\) \d+:\d+:\d+ \(0 background job\(s\)\)", seg) is not None, "uptime")
    seg = sh(s, "sysinfo", "root")
    check(seg is not None and f"nxtsOS v{VERSION}" in seg, "sysinfo version")
    check(seg is not None and "CPU: " in seg and "Memory: " in seg and "Disk: " in seg and "Net: " in seg and "Jobs: " in seg and "session: " in seg, "sysinfo sections")
    seg = sh(s, "date", "root")
    m = re.search(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", seg or "")
    check(m is not None and 2000 <= int(m.group(1)) <= 2099 and 1 <= int(m.group(2)) <= 12 and 1 <= int(m.group(3)) <= 31 and int(m.group(4)) <= 23 and int(m.group(5)) <= 59 and int(m.group(6)) <= 59, "date format + ranges")
    seg = sh(s, "ps", "root")
    check(seg is not None and "Session: root uid 0" in seg and "(no background jobs)" in seg, "ps session + no jobs")
    secs, quit_ok = top_run(s, "root")
    check(len(secs) >= 2 and secs[-1] > secs[0], "top refreshes advance uptime")
    check(quit_ok, "top quits cleanly on q")
    # grouped forms
    seg = sh(s, "diag cpu", "root")
    check(seg is not None and "CPU vendor: " in seg, "grouped diag cpu")
    seg = sh(s, "diag pci", "root")
    check(seg is not None and "PCI bus 0:" in seg, "grouped diag pci")
    seg = sh(s, "diag disk", "root")
    check(seg is not None and "sectors total" in seg, "grouped diag disk")
    seg = sh(s, "system uptime", "root")
    check(seg is not None and "Uptime: " in seg, "grouped system uptime")
    seg = sh(s, "system sysinfo", "root")
    check(seg is not None and f"nxtsOS v{VERSION}" in seg, "grouped system sysinfo")
    seg = sh(s, "system date", "root")
    check(seg is not None and re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", seg or "") is not None, "grouped system date")
    seg = sh(s, "proc ps", "root")
    check(seg is not None and "Session: root uid 0" in seg, "grouped proc ps")
    # help entries
    seg = sh(s, "help diag", "root")
    check(seg is not None and "cpu" in seg and "pci" in seg and "disk" in seg, "help diag lists group")
    seg = sh(s, "help cpu", "root")
    check(seg is not None and "cpu" in seg and "CPUID" in seg, "help cpu dedicated entry")
    seg = sh(s, "help date", "root")
    check(seg is not None and "date" in seg and "RTC" in seg, "help date dedicated entry")
finally:
    stop(qemu, s)

# ---- Boot 2: CD-ROM only, no filesystem ----
qemu, s = boot(None)
try:
    check(wait_from("root@nxts> ", 60, "boot 2 prompt"), "boot 2 prompt")
    seg = sh(s, "disk", "root")
    check(seg is not None and "Disk: ATA device present, filesystem not mounted (no disk or bad filesystem)" in seg, "disk unmounted message")
    seg = sh(s, "sysinfo", "root")
    check(seg is not None and "Disk: filesystem not mounted" in seg, "sysinfo unmounted disk")
    secs, quit_ok = top_run(s, "root")
    check(quit_ok, "top quits without filesystem")
    check("Disk: filesystem not mounted" in log_text(), "top unmounted disk line")
finally:
    stop(qemu, s)

print("CORE_HW TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
