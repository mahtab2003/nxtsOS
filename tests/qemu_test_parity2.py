#!/usr/bin/env python3
"""Parity run, family 3: env vars, aliases, su/exit/uname/
free/killall, df/du/find/touch/man, cat multi-file.

Boots (all on the same ISO):
  1 (files disk, setup root): export/unset/$VAR/${VAR}
     expansion (incl. mid-word, spaced values, unset ->
     empty, bad-name and missing-= usages); alias define/
     list/quote-strip/one-level-only/unalias/group-wins-over-
     alias (bare `fs` aliases, `fs ls` still dispatches);
     uname, uname -a, free, man; df/du/find/touch; cat
     multi-file incl. a missing middle file.
  2 (users disk): login admin -> su alice (root, no
     password) -> whoami; su bob (password) -> whoami;
     su root refused upfront (root is not a login account);
     su ghost refused; su alice with a wrong password
     refused and the session stays bob; touch permission
     checks as alice; exit logs out to the login prompt.
     Passwords are sent raw (no echo verification — echo is
     off, so verification is impossible by design).
  3 (top disk): runbg longrun.elf twice -> killall longrun.elf kills
     both (retry up to 3 times: slow only runs ~5 s);
     killall of an unknown name refused.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_parity2.py <iso> <workdir>
<workdir> is created by tests/qemu_test_parity2_setup.py.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
FILES = os.path.join(WORK, "files.img")
USERS = os.path.join(WORK, "users2.img")
TOPD = os.path.join(WORK, "top2.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash"}
# QEMU sendkey drops bare uppercase letters and '$' (proven
# 2026-10-30: "echo $FOO" echoed as "echo "): shifted chars
# must use their shift- forms, '=' is "equal", "'" is
# "apostrophe", braces are shift-bracket_*. Without these,
# every env/alias command mistypes and its check fails.
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEYMAP[_c] = "shift-" + _c.lower()
KEYMAP.update({"$": "shift-4", "'": "apostrophe", '"': "shift-apostrophe",
               "=": "equal", "{": "shift-bracket_left", "}": "shift-bracket_right",
               "(": "shift-9", ")": "shift-0", "+": "shift-equal", "?": "shift-slash",
               "*": "shift-8", "&": "shift-7", "%": "shift-5", "#": "shift-3",
               "@": "shift-2", "!": "shift-1", "<": "shift-comma", ">": "shift-dot",
               "|": "shift-backslash", "~": "shift-grave_accent"})

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
            # A newline here is intervening output (a background
            # job's print, or a submitted line): the current line
            # is whatever follows it, not what precedes it.
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
        if _attempt < 2:
            for _ in range(len(txt) + 2):
                s.sendall(b"sendkey backspace\n"); time.sleep(0.1)
            time.sleep(0.5)
    # Final attempt: the line still holds the typed text (no
    # erase after it), so Enter submits the command even when
    # echo verification was blind. A corrupted submit fails
    # loudly (Unknown command) instead of silently never running.
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

def send_raw(s, txt):
    """Send text + Enter with no echo verification (for
    echo-off prompts like Password:)."""
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    time.sleep(0.4)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def wait_either(needles, timeout):
    for _ in range(int(timeout * 10)):
        t = log_text()
        for nd in needles:
            i = t.find(nd, POS[0])
            if i >= 0:
                POS[0] = i + len(nd)
                return nd
        time.sleep(0.1)
    return None

def send_login_user(s, user):
    """Type a username at the login prompt with echo
    verification. The generic send_verified() is blind here:
    it checks the current line after the last "@nxts> ",
    which never appears at a login prompt, so it always
    'fails' and retypes through 3 erase cycles — and any
    lost backspace in those cycles corrupts the name
    (proven 2026-10-30: raw single typing logs in, the
    verified sender produced "Login incorrect" + lockout).
    The kernel echoes the username, so the text after the
    last "login: " marker (backspaces interpreted) IS a
    real echo check. Passwords stay send_raw: echo is off
    there, so no verification is possible by design."""
    for _attempt in range(3):
        for ch in user:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        time.sleep(0.5)
        t = log_text()
        idx = t.rfind("login: ")
        raw = t[idx + len("login: "):] if idx >= 0 else ""
        echo = []
        for ch in raw:
            if ch == "\b":
                if echo: echo.pop()
            elif ch == "\n" or ch == "\r":
                break
            else:
                echo.append(ch)
        if "".join(echo) == user:
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            return True
        for _ in range(len(user) + 2):
            s.sendall(b"sendkey backspace\n"); time.sleep(0.1)
        time.sleep(0.5)
    s.sendall(b"sendkey ret\n"); time.sleep(1)
    return False

def login(s, user, pw):
    for _ in range(2):
        if not wait_from("login: ", 60, f"login prompt {user}"): return False
        send_login_user(s, user)
        if not wait_from("Password: ", 30, f"password prompt {user}"): return False
        send_raw(s, pw)
        got = wait_either([f"{user}@nxts> ", "Login incorrect"], 30)
        if got == f"{user}@nxts> ": return True
        if got is None: return False
    return False

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

# ---- Boot 1: env, alias, misc, fs tools ----
qemu, s = boot(FILES)
try:
    check(wait_from("root@nxts> ", 60, "boot 1 prompt"), "boot 1 prompt")
    seg = sh(s, "export FOO=bar", "root")
    seg = sh(s, "echo $FOO", "root")
    check(seg is not None and "\nbar\n" in seg, "echo $FOO expands")
    seg = sh(s, "echo pre-$FOO-post", "root")
    check(seg is not None and "\npre-bar-post\n" in seg, "expansion mid-word")
    seg = sh(s, "echo ${FOO}", "root")
    check(seg is not None and "\nbar\n" in seg, "echo ${FOO} expands")
    seg = sh(s, "echo $UNSET_X", "root")
    check(seg is not None and "echo $UNSET_X\n\n" in seg, "unset variable expands to empty")
    seg = sh(s, "export FOO=bar baz", "root")
    seg = sh(s, "echo $FOO", "root")
    check(seg is not None and "\nbar baz\n" in seg, "export value with spaces")
    seg = sh(s, "export", "root")
    check(seg is not None and "FOO=bar baz" in seg, "bare export lists variables")
    seg = sh(s, "unset FOO", "root")
    seg = sh(s, "echo $FOO", "root")
    check(seg is not None and "echo $FOO\n\n" in seg, "unset removes the variable")
    seg = sh(s, "export 1BAD=x", "root")
    check(seg is not None and "Usage: export NAME=VALUE" in seg, "export bad name refused")
    seg = sh(s, "export FOO", "root")
    check(seg is not None and "Usage: export NAME=VALUE" in seg, "export without = refused")
    seg = sh(s, "alias greet echo hello", "root")
    seg = sh(s, "greet", "root")
    check(seg is not None and "\nhello\n" in seg, "alias expands and runs")
    seg = sh(s, "alias", "root")
    check(seg is not None and "alias greet='echo hello'" in seg, "bare alias lists aliases")
    seg = sh(s, "alias q 'echo quoted'", "root")
    seg = sh(s, "q", "root")
    check(seg is not None and "\nquoted\n" in seg, "alias quote-strip round-trips")
    seg = sh(s, "alias a b", "root")
    seg = sh(s, "alias b echo loop", "root")
    seg = sh(s, "a", "root")
    check(seg is not None and "Unknown command: b" in seg, "alias expansion is one level only")
    seg = sh(s, "unalias greet", "root")
    seg = sh(s, "greet", "root")
    check(seg is not None and "Unknown command: greet" in seg, "unalias removes the alias")
    seg = sh(s, "unalias nosuch", "root")
    check(seg is not None and "unalias: nosuch: not found" in seg, "unalias missing name reported")
    seg = sh(s, "alias fs echo aliased", "root")
    seg = sh(s, "fs", "root")
    check(seg is not None and "\naliased\n" in seg, "alias fires for a bare group name")
    seg = sh(s, "fs ls", "root")
    check(seg is not None and "a.txt" in seg and "aliased" not in seg, "group dispatch wins over alias")
    seg = sh(s, "uname", "root")
    check(seg is not None and "\nnxtsOS\n" in seg, "uname prints sysname")
    seg = sh(s, "uname -a", "root")
    check(seg is not None and "nxtsOS v1.1.5 i386" in seg, "uname -a prints version + machine")
    seg = sh(s, "free", "root")
    check(seg is not None and "Memory:" in seg, "free aliases mem")
    seg = sh(s, "man echo", "root")
    check(seg is not None and "echo (system)" in seg and "Usage: echo <text>" in seg, "man prints dedicated help")
    seg = sh(s, "man nosuch", "root")
    check(seg is not None and "man: no such command nosuch" in seg, "man unknown command reported")
    seg = sh(s, "df", "root")
    check(seg is not None and "total 16 MiB" in seg and "2 files" in seg, "df reports size + file count")
    seg = sh(s, "du a.txt b.txt", "root")
    check(seg is not None and "a.txt: 6 bytes" in seg and "b.txt: 10 bytes" in seg and "du: total 16 bytes" in seg, "du per-file + total")
    seg = sh(s, "du", "root")
    check(seg is not None and "du: total 16 bytes" in seg, "bare du totals readable files")
    seg = sh(s, "du missing.txt", "root")
    check(seg is not None and "du: cannot stat missing.txt" in seg, "du missing file reported")
    seg = sh(s, "find .txt", "root")
    check(seg is not None and "a.txt" in seg and "b.txt" in seg, "find substring lists matches")
    seg = sh(s, "find a", "root")
    check(seg is not None and "a.txt" in seg and "b.txt" not in seg, "find narrows to one match")
    seg = sh(s, "find zzz", "root")
    check(seg is not None and "(no files)" in seg, "find no match reports empty")
    seg = sh(s, "find", "root")
    check(seg is not None and "a.txt" in seg and "b.txt" in seg, "bare find lists all")
    seg = sh(s, "touch new.txt", "root")
    check(seg is not None and "touch: new.txt" in seg, "touch creates a file")
    seg = sh(s, "stat new.txt", "root")
    check(seg is not None and "0 bytes" in seg, "touched file is empty")
    seg = sh(s, "touch new.txt", "root")
    check(seg is not None and "touch: new.txt (exists)" in seg, "touch existing file is a no-op")
    seg = sh(s, "cat a.txt b.txt", "root")
    check(seg is not None and "alpha" in seg and "beta beta" in seg, "cat concatenates files")
    seg = sh(s, "cat a.txt missing.txt b.txt", "root")
    check(seg is not None and "cat: cannot read missing.txt" in seg and "beta beta" in seg, "cat continues past a missing file")
finally:
    stop(qemu, s)

# ---- Boot 2: su, touch permissions, exit ----
qemu, s = boot(USERS)
try:
    check(login(s, "admin", "pwadmin"), "boot 2 login admin")
    send_verified(s, "su alice")
    check(wait_from("alice@nxts> ", 30, "alice prompt after su"), "su alice switches prompt")
    seg = sh(s, "whoami", "alice")
    check(seg is not None and "alice uid 1000" in seg, "su alice switches session (root, no password)")
    # Retry the blind password send: a single sendkey doubling in
    # an echo-off password reads as "incorrect password" and the
    # whole bob section cascades (proven by a focused repro on
    # the final ISO: fresh disk, su bob succeeds first try).
    # su records no fails, so retries cannot lock the account.
    bob_prompt = False
    bob_ok = False
    for _attempt in range(3):
        send_verified(s, "su bob")
        if not wait_from("Password: ", 30, "su bob password prompt"):
            break
        bob_prompt = True
        send_raw(s, "pwbob")
        got = wait_either(["bob@nxts> ", "su: incorrect password"], 30)
        if got == "bob@nxts> ":
            bob_ok = True
            break
        print(f"NOTE: su bob password retry {_attempt + 1}")
    check(bob_prompt, "su bob prompts for password")
    check(bob_ok, "su bob switches session on password")
    seg = sh(s, "whoami", "bob")
    check(seg is not None and "bob uid 1001" in seg, "whoami shows bob after su")
    seg = sh(s, "su root", "bob")
    check(seg is not None and "su: root is not a login account" in seg, "su to root refused upfront")
    seg = sh(s, "su ghost", "bob")
    check(seg is not None and "su: no such user ghost" in seg, "su unknown user refused")
    send_verified(s, "su alice")
    check(wait_from("Password: ", 30, "su alice password prompt"), "su alice prompts for password")
    send_raw(s, "wrongpw")
    check(wait_from("su: incorrect password", 30, "su wrong password message"), "su wrong password refused")
    seg = sh(s, "whoami", "bob")
    check(seg is not None and "bob uid 1001" in seg, "failed su keeps the session")
    seg = sh(s, "touch sec.txt", "bob")
    check(seg is not None and "touch: cannot touch sec.txt" in seg, "touch refuses unreadable file")
    seg = sh(s, "touch own.txt", "bob")
    check(seg is not None and "touch: own.txt (exists)" in seg, "touch existing readable file is a no-op")
    send_verified(s, "exit")
    check(wait_from("login: ", 30, "login prompt after exit"), "exit logs out to login prompt")
finally:
    stop(qemu, s)

# ---- Boot 3: killall ----
qemu, s = boot(TOPD)
try:
    check(wait_from("root@nxts> ", 60, "boot 3 prompt"), "boot 3 prompt")
    killed_ok = False
    for _attempt in range(3):
        sh(s, "runbg longrun.elf", "root")
        sh(s, "runbg longrun.elf", "root")
        seg = sh(s, "killall longrun.elf", "root")
        if seg is not None and "killall: killed 2 job(s)" in seg:
            killed_ok = True
            break
        time.sleep(0.5)
    check(killed_ok, "killall kills both longrun jobs")
    seg = sh(s, "jobs", "root")
    check(seg is not None and "(no background jobs)" in seg, "jobs empty after killall")
    seg = sh(s, "killall nosuch.elf", "root")
    check(seg is not None and "killall: no job named nosuch.elf" in seg, "killall unknown name reported")
finally:
    stop(qemu, s)

print("PARITY2 TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
