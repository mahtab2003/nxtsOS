#!/usr/bin/env python3
"""Parity run, family 2: shell line editing, history, completion.

Boots (all on the same ISO, shell.img with alpha.txt):
  1 (history, setup root): echo alpha, echo beta, echo beta
     again (duplicate, not recorded), an empty Enter (not
     recorded), then Up Up Up + Enter (stays at the oldest,
     executes echo alpha), then a partial line + Up + Down +
     Enter (pending restore, executes echo partial), then
     `history` (exact numbered list incl. the history command
     itself — the line is recorded when Enter is pressed, so
     it lists itself; documented, not hidden), then
     `history -c` + `history` (only "1  history" remains).
  2 (line editing, setup root): each case types keys, presses
     Enter, and asserts on the COMMAND OUTPUT in the segment
     after Enter — never on the serial echo, because mid-line
     edits redraw buffer-only and the serial log shows the raw
     typed chars, not the final line. Cases: Left+insert,
     Ctrl-U, Ctrl-W, Ctrl-A + Ctrl-E, Del, Home + End,
     Ctrl-K, Ctrl-C line cancel.
  3 (completion, setup root): "ec" Tab -> echo (proven by
     " done" executing); "grou" Tab -> "group" (proven by
     "Unknown command: group"); "group" Tab lists all four
     group* commands to the serial log; "cat al" Tab ->
     alpha.txt (proven by its content); "echo zzz" Tab is a
     no-op (line intact).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_parity_shell.py <iso> <workdir>
<workdir> is created by tests/qemu_test_parity_shell_setup.py.
"""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "shell.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash"}
# QEMU sendkey drops bare uppercase letters, '$', and '!'
# (proven 2026-10-30): shifted chars need their shift- forms.
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEYMAP[_c] = "shift-" + _c.lower()
KEYMAP.update({"$": "shift-4", "!": "shift-1", "'": "apostrophe",
               '"': "shift-apostrophe", "=": "equal",
               "{": "shift-bracket_left", "}": "shift-bracket_right"})

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

def send_key(s, key, delay=0.2):
    s.sendall(f"sendkey {key}\n".encode()); time.sleep(delay)

def send_text_raw(s, txt):
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    time.sleep(0.4)

def run_edited(s, actions, user="root"):
    """Apply key actions at a fresh prompt, press Enter, and
    return the COMMAND OUTPUT region: from the Enter echo
    newline through the next prompt. The raw segment from
    mark would include the typed echo, which still shows
    deleted text (a Delete/^U/^K absence check on it can
    never pass); the output region excludes typed echo, so
    absence checks on it are meaningful. The first newline
    in the segment is the Enter echo (typing and buffer-only
    redraws emit no serial newlines)."""
    mark = len(log_text())
    for kind, val in actions:
        if kind == "type":
            send_text_raw(s, val)
        else:
            send_key(s, val, delay=0.35)
    send_key(s, "ret", delay=1.0)
    if not wait_from(f"{user}@nxts> ", 30, "prompt after edited line"):
        return None
    seg = log_text()[mark:POS[0]]
    idx = seg.find("\n")
    return seg[idx:] if idx >= 0 else seg

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

# ---- Boot 1: history ----
qemu, s = boot(DISK)
try:
    check(wait_from("root@nxts> ", 60, "boot 1 prompt"), "boot 1 prompt")
    for cmd in ("echo alpha", "echo beta", "echo beta"):
        seg = sh(s, cmd, "root")
        check(seg is not None, f"history setup: {cmd}")
    send_key(s, "ret", delay=1.0)  # empty Enter: not recorded
    wait_from("root@nxts> ", 30, "prompt after empty Enter")
    # Up Up Up stays at the oldest (alpha), Enter executes it.
    seg = run_edited(s, [("key", "up"), ("key", "up"), ("key", "up")])
    check(seg is not None and "\nalpha\n" in seg, "Up past oldest stays, executes echo alpha")
    # Partial line + Up + Down restores the partial line.
    mark = len(log_text())
    send_text_raw(s, "echo partial")
    send_key(s, "up", delay=0.5)
    send_key(s, "down", delay=0.5)
    send_key(s, "ret", delay=1.0)
    wait_from("root@nxts> ", 30, "prompt after pending restore")
    seg = log_text()[mark:POS[0]]
    check("\npartial\n" in seg, "Down past newest restores pending line")
    seg = sh(s, "history", "root")
    check(seg is not None and "1  echo alpha" in seg, "history lists first entry numbered")
    check(seg is not None and "2  echo beta" in seg, "history lists second entry numbered")
    check(seg is not None and "3  echo beta" not in seg, "duplicate echo beta not recorded twice")
    check(seg is not None and "3  echo alpha" in seg, "re-executed echo alpha recorded once")
    check(seg is not None and "4  echo partial" in seg, "pending line recorded on Enter")
    check(seg is not None and "5  history" in seg, "history command lists itself (recorded on Enter)")
    seg = sh(s, "history -c", "root")
    check(seg is not None and "history: cleared" in seg, "history -c clears")
    seg = sh(s, "history", "root")
    check(seg is not None and "1  history" in seg, "history after clear shows only itself")
    check(seg is not None and "echo alpha" not in seg, "history after clear drops old entries")
    seg = sh(s, "ver", "root")
    check(seg is not None and "nxtsOS v1.1.5" in seg, "ver prints version")
    seg = sh(s, "history", "root")
    check(seg is not None and "nxtsOS v1.1.5" not in seg, "history output has no version leak")
finally:
    stop(qemu, s)

# ---- Boot 2: line editing ----
qemu, s = boot(DISK)
try:
    check(wait_from("root@nxts> ", 60, "boot 2 prompt"), "boot 2 prompt")
    seg = run_edited(s, [("type", "echo ac"), ("key", "left"), ("type", "b")])
    check(seg is not None and "\nabc\n" in seg, "Left + insert executes edited line")
    seg = run_edited(s, [("type", "echo junk"), ("key", "ctrl-u"), ("type", "echo ok")])
    check(seg is not None and "\nok\n" in seg and "junk" not in seg, "Ctrl-U kills whole line")
    seg = run_edited(s, [("type", "echo foo bar"), ("key", "ctrl-w")])
    check(seg is not None and "\nfoo\n" in seg and "bar" not in seg, "Ctrl-W deletes word before cursor")
    seg = run_edited(s, [("type", "world"), ("key", "ctrl-a"), ("type", "echo "), ("key", "ctrl-e"), ("type", "!")])
    check(seg is not None and "\nworld!\n" in seg, "Ctrl-A + Ctrl-E move across the line")
    seg = run_edited(s, [("type", "echo abXc"), ("key", "left"), ("key", "left"), ("key", "delete")])
    check(seg is not None and "\nabc\n" in seg and "X" not in seg, "Delete removes char at cursor")
    seg = run_edited(s, [("type", "ab"), ("key", "home"), ("type", "echo "), ("key", "end"), ("type", "!")])
    check(seg is not None and "\nab!\n" in seg, "Home + End move across the line")
    seg = run_edited(s, [("type", "echo ok trailing")] + [("key", "left")] * 9 + [("key", "ctrl-k")])
    check(seg is not None and "\nok\n" in seg and "trailing" not in seg, "Ctrl-K kills to end of line")
    # Ctrl-C: the cancelled line must not execute.
    mark = len(log_text())
    send_text_raw(s, "echo cancelled")
    send_key(s, "ctrl-c", delay=1.0)
    wait_from("root@nxts> ", 30, "prompt after Ctrl-C")
    send_text_raw(s, "echo after")
    send_key(s, "ret", delay=1.0)
    wait_from("root@nxts> ", 30, "prompt after Ctrl-C follow-up")
    seg = log_text()[mark:POS[0]]
    check("\ncancelled\n" not in seg and "\nafter\n" in seg, "Ctrl-C cancels the line")
finally:
    stop(qemu, s)

# ---- Boot 3: completion ----
qemu, s = boot(DISK)
try:
    check(wait_from("root@nxts> ", 60, "boot 3 prompt"), "boot 3 prompt")
    seg = run_edited(s, [("type", "ec"), ("key", "tab"), ("type", " done")])
    check(seg is not None and "\ndone\n" in seg and "Unknown command" not in seg, "Tab completes command name")
    seg = run_edited(s, [("type", "grou"), ("key", "tab")])
    check(seg is not None and "Unknown command: group" in seg, "Tab completes common prefix of group commands")
    mark = len(log_text())
    send_text_raw(s, "group")
    send_key(s, "tab", delay=1.0)
    time.sleep(0.5)
    seg = log_text()[mark:]
    check("groupadd" in seg and "groupdel" in seg, "Tab lists multiple matches")
    # Resync past the listing's reprinted prompt: wait_from
    # searches from POS, and the reprint would match first,
    # pinning every later prompt wait to a stale position
    # (the follow-up and the next two cases then read empty
    # segments). From here on, waits find true new prompts.
    POS[0] = len(log_text())
    send_key(s, "ctrl-u", delay=0.5)
    send_text_raw(s, "echo listed")
    send_key(s, "ret", delay=1.0)
    wait_from("root@nxts> ", 30, "prompt after listing follow-up")
    seg = log_text()[mark:POS[0]]
    check("\nlisted\n" in seg, "line intact after candidate listing")
    seg = run_edited(s, [("type", "cat al"), ("key", "tab")])
    check(seg is not None and "alpha-content" in seg, "Tab completes file name")
    seg = run_edited(s, [("type", "echo zzz"), ("key", "tab")])
    check(seg is not None and "\nzzz\n" in seg and "Unknown command" not in seg, "Tab with no match leaves line intact")
finally:
    stop(qemu, s)

print("PARITY_SHELL TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
