#!/usr/bin/env python3
"""Linux-comparability run, suite 2: chaining + $? + test,
scripts (sh/source, if/for/while), text tools 2 (regex grep,
sed, tr, cut, uniq, tee, seq, basename, dirname, more),
and globbing.

One boot (disk from qemu_test_linuxcomp2_setup.py, setup-mode
root, no login). The `more` check drives the pager: 25 lines
means one --More-- prompt (space continues, then EOF).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_linuxcomp2.py <iso> <workdir>
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "*": "shift-8",
          "?": "shift-slash", "$": "shift-4", "|": "shift-backslash",
          "&": "shift-7", ";": "semicolon", ">": "shift-dot",
          "<": "shift-comma", "(": "shift-9", ")": "shift-0",
          "[": "bracket_left", "]": "bracket_right", "!": "shift-1",
          "=": "equal", "+": "shift-equal", "^": "shift-6", ",": "comma"}
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

def sh(s, txt, user="root"):
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

qemu, s = boot(DISK)
try:
    check(wait_from("root@nxts> ", 60, "boot prompt"), "boot prompt")
    # --- chaining + $? ---
    seg = sh(s, "true && echo yes-and")
    check(seg is not None and "yes-and" in seg, "true && runs the second command")
    seg = sh(s, "false && echo no-and")
    # The typed command echo itself contains "no-and"; only an
    # actual output line would appear at a line start.
    check(seg is not None and "\nno-and\n" not in seg, "false && skips the second command")
    seg = sh(s, "false || echo yes-or")
    check(seg is not None and "yes-or" in seg, "false || runs the second command")
    seg = sh(s, "true || echo no-or")
    check(seg is not None and "\nno-or\n" not in seg, "true || skips the second command")
    seg = sh(s, "echo one; echo two")
    ordered(seg, ["one", "two"], "; sequences both commands")
    seg = sh(s, "false; echo $?")
    check(seg is not None and "\n1\n" in seg, "$? is 1 after false")
    seg = sh(s, "boguscmd; echo $?")
    check(seg is not None and "Unknown command: boguscmd" in seg and "\n127\n" in seg,
          "$? is 127 after an unknown command")
    seg = sh(s, "true; echo $?")
    check(seg is not None and "\n0\n" in seg, "$? is 0 after true")
    # --- test ---
    seg = sh(s, "test -f words.txt && echo file-yes")
    check(seg is not None and "file-yes" in seg, "test -f true for an existing file")
    seg = sh(s, "test -f nope.txt || echo file-no")
    check(seg is not None and "file-no" in seg, "test -f false for a missing file")
    seg = sh(s, "test hello = hello && echo str-yes")
    check(seg is not None and "str-yes" in seg, "test string =")
    seg = sh(s, "test 3 -gt 2 && echo num-yes")
    check(seg is not None and "num-yes" in seg, "test numeric -gt")
    seg = sh(s, "test ! -f nope.txt && echo neg-yes")
    check(seg is not None and "neg-yes" in seg, "test ! negation")
    seg = sh(s, "[ 1 -eq 1 ] && echo bracket-yes")
    check(seg is not None and "bracket-yes" in seg, "[ ... ] form works")
    seg = sh(s, "test -n hello && echo n-yes")
    check(seg is not None and "n-yes" in seg, "test -n non-empty string")
    seg = sh(s, "test hello != world && echo neq-yes")
    check(seg is not None and "neq-yes" in seg, "test string !=")
    # --- script ---
    seg = sh(s, "sh demo.sh")
    ordered(seg, ["start", "if-yes", "loop-a", "loop-b", "loop-c", "var-hello",
                  "loop-once", "done"], "script runs if/for/while in order")
    check(seg is not None and "if-no" not in seg and "never" not in seg,
          "script skips untaken branches")
    seg = sh(s, "test -f flag || echo flag-gone")
    check(seg is not None and "flag-gone" in seg, "script while loop removed its flag file")
    seg = sh(s, "sh nope.sh")
    check(seg is not None and "sh: cannot read nope.sh" in seg, "sh missing file fails visibly")
    # --- regex grep ---
    seg = sh(s, "grep h.llo words.txt")
    check(seg is not None and "hello world" in seg, "grep regex . matches")
    seg = sh(s, "grep ^foo words.txt")
    check(seg is not None and "foo bar" in seg and "foo baz" in seg, "grep regex ^ anchor")
    seg = sh(s, "grep world$ words.txt")
    check(seg is not None and "hello world" in seg and "foo bar" not in seg, "grep regex $ anchor")
    seg = sh(s, "grep f[o]o words.txt")
    check(seg is not None and "foo bar" in seg, "grep character class")
    seg = sh(s, "grep -F h.llo words.txt")
    check(seg is not None and "hello world" not in seg, "grep -F treats . literally")
    seg = sh(s, "grep fo+ words.txt")
    check(seg is not None and "foo bar" in seg and "foo baz" in seg, "grep + quantifier")
    seg = sh(s, "grep hellow? words.txt")
    check(seg is not None and "hello world" in seg, "grep ? quantifier")
    seg = sh(s, "grep foo words.txt; echo $?")
    check(seg is not None and "\n0\n" in seg, "grep exit status 0 on match")
    seg = sh(s, "grep zzz words.txt; echo $?")
    check(seg is not None and "\n1\n" in seg, "grep exit status 1 on no match")
    # --- sed ---
    seg = sh(s, "sed s/foo/FOO/ words.txt")
    check(seg is not None and "FOO bar" in seg and "hello world" in seg, "sed substitution")
    seg = sh(s, "sed s/o/0/g words.txt")
    check(seg is not None and "f00 bar" in seg and "hell0 w0rld" in seg, "sed global substitution")
    seg = sh(s, "sed -n 2p words.txt")
    check(seg is not None and "hello world" in seg and "foo bar" not in seg, "sed -n line print")
    seg = sh(s, "sed -n 1,2p words.txt")
    check(seg is not None and "foo bar" in seg and "hello world" in seg and "foo baz" not in seg,
          "sed -n range print")
    seg = sh(s, "sed /hello/p words.txt")
    check(seg is not None and seg.count("hello world") == 2, "sed /re/p prints matched lines twice")
    seg = sh(s, "sed 2d words.txt")
    check(seg is not None and "hello world" not in seg and "foo bar" in seg, "sed delete")
    seg = sh(s, "sed s/foo/&-&/ words.txt")
    check(seg is not None and "foo-foo bar" in seg, "sed & expands to the whole match")
    # --- tr / cut / uniq / tee / seq / basename / dirname ---
    seg = sh(s, "cat words.txt | tr a-z A-Z")
    check(seg is not None and "FOO BAR" in seg and "HELLO WORLD" in seg, "tr translates ranges")
    seg = sh(s, "cat words.txt | tr -d o")
    check(seg is not None and "f bar" in seg and "hell wrld" in seg, "tr -d deletes")
    seg = sh(s, "cat pairs.txt | cut -d : -f 2")
    ordered(seg, ["\n1\n", "\n2\n", "\n3\n"], "cut -d : -f 2")
    seg = sh(s, "cat pairs.txt | cut -d : -f 1,3")
    check(seg is not None and "a:x" in seg and "b:y" in seg, "cut field list")
    seg = sh(s, "cat words.txt | cut -c 1-3")
    check(seg is not None and "foo" in seg and "hel" in seg, "cut -c range")
    seg = sh(s, "uniq dup.txt")
    check(seg is not None and seg.count("one") == 1 and seg.count("two") == 1
          and "three" in seg, "uniq collapses consecutive duplicates")
    seg = sh(s, "uniq -c dup.txt")
    check(seg is not None and "2 one" in seg and "3 two" in seg, "uniq -c counts")
    seg = sh(s, "cat words.txt | tee teed.txt")
    check(seg is not None and "foo bar" in seg, "tee echoes stdin to stdout")
    seg = sh(s, "cat teed.txt")
    check(seg is not None and "foo bar" in seg and "hello world" in seg, "tee wrote the file")
    seg = sh(s, "seq 3")
    ordered(seg, ["\n1\n", "\n2\n", "\n3\n"], "seq 3")
    seg = sh(s, "seq 2 2 6")
    ordered(seg, ["\n2\n", "\n4\n", "\n6\n"], "seq first step last")
    seg = sh(s, "seq 3 -1 1")
    ordered(seg, ["\n3\n", "\n2\n", "\n1\n"], "seq negative step")
    seg = sh(s, "basename hello.txt")
    check(seg is not None and "\nhello.txt\n" in seg, "basename flat name")
    seg = sh(s, "dirname hello.txt")
    check(seg is not None and "\n/\n" in seg, "dirname flat name is /")
    # --- more pager: 25 lines, one --More-- prompt, space continues ---
    before = POS[0]
    send_verified(s, "more page.txt")
    got = wait_from("--More--", 30, "more prompt")
    check(got, "more pages after 20 lines")
    if got:
        s.sendall(b"sendkey spc\n"); time.sleep(1)
        check(wait_from("root@nxts> ", 30, "prompt after more"), "more finishes after space")
        seg = log_text()[before:POS[0]]
        check("line01" in seg and "line25" in seg, "more shows first and last page lines")
    # --- globbing ---
    seg = sh(s, "cat g*.txt")
    check(seg is not None and "glob one" in seg and "glob two" in seg, "glob cat expands *.txt")
    seg = sh(s, "cat *.log")
    check(seg is not None and "not a txt file" in seg, "glob *.log matches other.log")
    seg = sh(s, "cat nomatch*.txt")
    check(seg is not None and "cannot read" in seg, "non-matching glob stays literal and fails visibly")
finally:
    stop(qemu, s)
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
