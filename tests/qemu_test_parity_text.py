#!/usr/bin/env python3
"""Parity run, family 4: text tools (grep, sort, wc, head,
tail, diff) + the text help group.

One boot (text disk, setup root): help index lists the
text group and help text names grep/diff; group dispatch
(`text grep`, `text sort`) works; sort byte order incl.
case and multi-digit numbers; grep substring (NOT regex),
case-sensitive default, -i/-v/-n/-c, combined flags,
multi-file prefixes, missing-file continuation; wc default
and flag subsets plus a multi-file total; head/tail -n,
default, obsolete -N, -n 0, multi-file headers; diff
change/add/delete hunks, identical files (no output),
over-cap refusals (sort/diff, no partial output); a line
longer than the 1024-byte read window still greps and
counts; no-file-no-stdin usage errors return promptly
(they must not hang waiting for a stdin stream).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_parity_text.py <iso> <workdir>
<workdir> is created by tests/qemu_test_parity_text_setup.py.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
TEXT = os.path.join(WORK, "text.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash"}

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

def ordered(seg, needles, label):
    pos = -1
    good = seg is not None
    for nd in needles:
        i = seg.find(nd, pos + 1) if good else -1
        if i < 0: good = False; break
        pos = i
    check(good, label)

qemu, s = boot(TEXT)
try:
    check(wait_from("root@nxts> ", 60, "boot prompt"), "boot prompt")
    seg = sh(s, "help", "root")
    check(seg is not None and "text:" in seg, "help index lists text group")
    seg = sh(s, "help text", "root")
    check(seg is not None and "grep" in seg and "diff" in seg, "help text lists tools")
    seg = sh(s, "sort fruits.txt", "root")
    ordered(seg, ["\nCherry\n", "\napple\n", "\nbanana\n"], "sort byte order with case")
    check(seg is not None and seg.count("apple\n") == 2, "sort keeps duplicates")
    seg = sh(s, "sort nums.txt", "root")
    ordered(seg, ["\n1\n", "\n10\n", "\n2\n"], "sort numeric strings in byte order")
    seg = sh(s, "grep error log.txt", "root")
    check(seg is not None and "disk full" not in seg, "grep case-sensitive by default")
    seg = sh(s, "grep -i error log.txt", "root")
    check(seg is not None and "disk full" in seg and "timeout" in seg and "low mem" not in seg,
          "grep -i matches both cases")
    seg = sh(s, "grep -v info log.txt", "root")
    check(seg is not None and "disk full" in seg and "low mem" in seg and "timeout" in seg
          and "info: ok" not in seg, "grep -v inverts")
    seg = sh(s, "grep -n warning log.txt", "root")
    check(seg is not None and "2:warning: low mem" in seg, "grep -n prefixes line numbers")
    seg = sh(s, "grep -c error log.txt", "root")
    check(seg is not None and "\n0\n" in seg, "grep -c counts zero case-sensitively")
    seg = sh(s, "grep -ci error log.txt", "root")
    check(seg is not None and "\n2\n" in seg, "grep combined -ci flags")
    seg = sh(s, "grep apple fruits.txt nums.txt", "root")
    check(seg is not None and "fruits.txt:apple" in seg and "nums.txt:" not in seg,
          "grep multi-file prefixes, silent file has no lines")
    seg = sh(s, "grep apple missing.txt fruits.txt", "root")
    check(seg is not None and "grep: cannot read missing.txt" in seg and "fruits.txt:apple" in seg,
          "grep missing file reports and continues")
    seg = sh(s, "wc words.txt", "root")
    check(seg is not None and "2 5 24 words.txt" in seg, "wc default counts")
    seg = sh(s, "wc -l words.txt", "root")
    check(seg is not None and "2 words.txt" in seg, "wc -l only")
    seg = sh(s, "wc -w words.txt", "root")
    check(seg is not None and "5 words.txt" in seg, "wc -w only")
    seg = sh(s, "wc -c words.txt", "root")
    check(seg is not None and "24 words.txt" in seg, "wc -c only")
    seg = sh(s, "wc words.txt lines.txt", "root")
    check(seg is not None and "7 10 39 total" in seg, "wc multi-file total")
    seg = sh(s, "wc missing.txt", "root")
    check(seg is not None and "wc: cannot read missing.txt" in seg, "wc missing file reports")
    seg = sh(s, "head -n 2 lines.txt", "root")
    check(seg is not None and "\nl1\nl2\n" in seg and "l3" not in seg, "head -n 2")
    seg = sh(s, "tail -n 2 lines.txt", "root")
    check(seg is not None and "\nl4\nl5\n" in seg and "l3" not in seg, "tail -n 2")
    seg = sh(s, "head lines.txt", "root")
    check(seg is not None and "l1" in seg and "l5" in seg, "head default prints all 5")
    seg = sh(s, "tail lines.txt", "root")
    check(seg is not None and "l1" in seg and "l5" in seg, "tail default prints all 5")
    seg = sh(s, "head -2 lines.txt", "root")
    check(seg is not None and "\nl1\nl2\n" in seg and "l3" not in seg, "head obsolete -N form")
    seg = sh(s, "head -n 0 lines.txt", "root")
    check(seg is not None and "l1" not in seg, "head -n 0 prints nothing")
    seg = sh(s, "head -n 1 lines.txt words.txt", "root")
    check(seg is not None and "==> lines.txt <==" in seg and "==> words.txt <==" in seg
          and "\nl1\n" in seg and "hello world" in seg, "head multi-file headers")
    seg = sh(s, "diff da.txt db.txt", "root")
    ordered(seg, ["2c2", "< b", "---", "> X", "4c4", "< d", "---", "> e"], "diff change hunks")
    seg = sh(s, "diff adda.txt addb.txt", "root")
    check(seg is not None and "2a3" in seg and "> c" in seg, "diff add hunk")
    seg = sh(s, "diff dela.txt delb.txt", "root")
    check(seg is not None and "2d1" in seg and "< b" in seg, "diff delete hunk")
    seg = sh(s, "diff same.txt same2.txt", "root")
    check(seg is not None and "< " not in seg and "\n> " not in seg, "diff identical files silent")
    seg = sh(s, "sort over.txt", "root")
    check(seg is not None and "sort: too many lines (max 256)" in seg and "n256" not in seg,
          "sort over-cap refuses without partial output")
    seg = sh(s, "diff over.txt over.txt", "root")
    check(seg is not None and "diff: too many lines (max 256)" in seg,
          "diff over-cap refuses")
    seg = sh(s, "grep second wide.txt", "root")
    check(seg is not None and "\nsecond\n" in seg, "grep finds line past the read window")
    seg = sh(s, "wc -l wide.txt", "root")
    check(seg is not None and "2 wide.txt" in seg, "wc counts lines across windows")
    seg = sh(s, "grep aaaa wide.txt", "root")
    check(seg is not None and "a" * 50 in seg, "grep long line returns its first chunk")
    seg = sh(s, "grep apple", "root")
    check(seg is not None and "Usage: grep" in seg, "grep no file no stdin is usage, not a hang")
    seg = sh(s, "sort", "root")
    check(seg is not None and "Usage: sort" in seg, "sort no file no stdin is usage, not a hang")
    seg = sh(s, "text grep apple fruits.txt", "root")
    check(seg is not None and "\napple\n" in seg, "group dispatch text grep works")
    seg = sh(s, "text sort nums.txt", "root")
    ordered(seg, ["\n1\n", "\n10\n", "\n2\n"], "group dispatch text sort works")
finally:
    stop(qemu, s)
print("PARITY_TEXT TEST PASS" if ok else "PARITY_TEXT TEST FAIL")
sys.exit(0 if ok else 1)
