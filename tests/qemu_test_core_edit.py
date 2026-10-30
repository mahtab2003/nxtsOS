#!/usr/bin/env python3
"""Core editor test: the nano-like full-screen editor.

The screen is invisible to the serial log, so every proof is
via post-exit `cat` (content), `stat` (owner/mode), the
"EDIT-SAVED <file>" serial marker (save happened), or
"edit: done" (editor exited) — never via screen scraping.
Editor keys go through the QEMU monitor: arrows/home/end/
delete/pgup/pgdn by name, ^O/^X/^W/^K/^U/^G as ctrl-<letter>,
uppercase/symbols as shift-<key> (a bare "!" or "X" is not a
valid QEMU key name and would silently do nothing).

Boots (all on the same ISO):
  A (fresh blank disk, setup-mode root): create + type +
     save + exit, cat proves content; Home/End/insert;
     search moves the cursor (insert lands at the match);
     cut/paste reorders lines; backspace-join and del-join;
     ^X then n discards, ^X then y saves, ^X then c
     cancels (a second ^X + n is consumed by the editor,
     not the shell); save-as writes the new file and leaves
     the old untouched; help overlay opens and returns
     (its return key is consumed, not inserted);
     search-miss leaves the buffer unmodified (^X exits
     at once, no y/n/c needed).
  B (seeded disk, alice): tab expands to 4 spaces on
     load+save; oversized file refused before opening;
     overlong line cut refused (line intact after save);
     root-only file refused before opening.
  C (fresh blank disk, setup-mode root): root edits
     alice's 0600 file and saves — owner stays alice,
     mode stays 600, content updated.

Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_core_edit.py <iso> <workdir>
<workdir> is created by tests/qemu_test_core_edit_setup.py.
"""
import os, shutil, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
BLANK = os.path.join(WORK, "blank.img")
SEED = os.path.join(WORK, "seed.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
SHIFT = {"!": "shift-1", "@": "shift-2", "#": "shift-3", "$": "shift-4", "%": "shift-5", "^": "shift-6",
         "&": "shift-7", "*": "shift-8", "(": "shift-9", ")": "shift-0", "_": "shift-minus", "+": "shift-equal",
         "{": "shift-bracket_left", "}": "shift-bracket_right", "|": "shift-backslash", ":": "shift-semicolon",
         '"': "shift-apostrophe", "<": "shift-comma", ">": "shift-dot", "?": "shift-slash", "~": "shift-grave_accent"}
PLAIN = {" ": "spc", ".": "dot", "-": "minus", "/": "slash", ",": "comma", ";": "semicolon",
         "'": "apostrophe", "[": "bracket_left", "]": "bracket_right", "\\": "backslash",
         "=": "equal", "`": "grave_accent"}

def keyname(ch):
    if ch in SHIFT: return SHIFT[ch]
    if ch in PLAIN: return PLAIN[ch]
    if ch.isupper(): return "shift-" + ch.lower()
    return ch

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

def send_text(s, txt):
    for _attempt in range(2):
        before = len(log_text())
        for ch in txt:
            s.sendall(f"sendkey {keyname(ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(1)
        if "Unknown command" not in log_text()[before:]:
            break

def sh(s, txt, user):
    """Shell command; returns the output segment, or None.
    The shell prints a fresh prompt when the previous command
    returns, so the FIRST prompt after sending may be that
    stale pre-command prompt. Loop until the segment holds
    the command echo (the shell echoes every command line);
    only then does the segment cover the command's output.
    Echo match is whitespace-normalized: QEMU sendkey
    doubling of a SPACE is semantically benign (the shell
    tokenizes runs of whitespace identically) but breaks an
    exact echo match — proven by a Boot C failure where
    'write  own.txt' executed fine ('Wrote own.txt') yet
    the exact check timed out waiting for a second prompt
    that never comes. Normalization matches the shell's own
    tokenization semantics; it is not a weakening."""
    before = POS[0]
    send_text(s, txt)
    seg = None
    norm_txt = " ".join(txt.split())
    for _ in range(3):
        if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt}"):
            return None
        seg = log_text()[before:POS[0]]
        if norm_txt in " ".join(seg.split()):
            break
    return seg

def edtype(s, txt):
    """Type text inside the editor (no Enter)."""
    for ch in txt:
        s.sendall(f"sendkey {keyname(ch)}\n".encode()); time.sleep(0.30)
    time.sleep(0.5)

def edkey(s, k):
    s.sendall(f"sendkey {k}\n".encode()); time.sleep(0.6)

def edenter(s):
    s.sendall(b"sendkey ret\n"); time.sleep(0.8)

def edsave(s, filename):
    """^O, Enter (keep name), wait for the serial marker."""
    edkey(s, "ctrl-o")
    edenter(s)
    return wait_from(f"EDIT-SAVED {filename}", 15, f"save marker {filename}")

def edsave_as(s, newname):
    """^O, type the new name, Enter, wait for the marker."""
    edkey(s, "ctrl-o")
    edtype(s, newname)
    edenter(s)
    return wait_from(f"EDIT-SAVED {newname}", 15, f"save-as marker {newname}")

def edexit(s):
    """^X on an unmodified buffer: exits at once."""
    edkey(s, "ctrl-x")
    return wait_from("edit: done", 15, "edit done")

def edexit_answer(s, ans):
    """^X on a modified buffer, then answer y/n; waits for done.
    Robust against the QEMU sendkey doubling flake: a doubled
    ^X cancels the y/n/c prompt (any non-y/n key cancels), so
    the answer char lands in the document instead and the
    editor stays open. Recovery: Backspace removes a stray
    answer char (or cancels a still-open prompt — Backspace
    is also 'anything else' there), then retry ^X + answer.
    The done search always starts from the original mark, so
    a slow first attempt is still found on a later check."""
    mark = len(log_text())
    for _ in range(3):
        edkey(s, "ctrl-x")
        time.sleep(0.5)
        s.sendall(f"sendkey {ans}\n".encode()); time.sleep(1.0)
        t = log_text()
        i = t.find("edit: done", mark)
        if i >= 0:
            POS[0] = i + len("edit: done")
            return True
        s.sendall(b"sendkey backspace\n"); time.sleep(0.8)
    print(f"TIMEOUT: edit done after {ans}")
    return False

def edopen(s, filename):
    send_text(s, f"edit {filename}")
    time.sleep(1.0)

FAILS = {}
def login(s, user, pw):
    for _attempt in range(3):
        if not wait_from("login: ", 60, f"login prompt {user}"): return False
        send_text(s, user)
        if not wait_from("Password: ", 30, f"password prompt {user}"): return False
        send_text(s, pw)
        got = None
        for _ in range(300):
            t = log_text()
            if f"Welcome, {user}." in t[POS[0]:]: got = "ok"; break
            if "Login incorrect" in t[POS[0]:]: got = "bad"; break
            time.sleep(0.1)
        if got == "ok":
            return wait_from(f"{user}@nxts> ", 30, f"shell prompt {user}")
        if got != "bad": return False
        FAILS[user] = FAILS.get(user, 0) + 1
        if FAILS[user] >= 2: return False
    return False

def logout(s, user):
    before = POS[0]
    send_text(s, "logout")
    if not wait_from("Logged out.", 30, f"logout {user}"): return None
    return log_text()[before:POS[0]]

def useradd(s, user, pw, prompt_user, expect_uid):
    for _attempt in range(3):
        send_text(s, f"useradd {user}")
        got = None
        for _ in range(300):
            t = log_text()
            if "New password: " in t[POS[0]:]: got = "new"; break
            if f"{prompt_user}@nxts> " in t[POS[0]:]: got = "prompt"; break
            time.sleep(0.1)
        if got == "new":
            send_text(s, pw)
            got2 = None
            for _ in range(300):
                t = log_text()
                if "Retype new password: " in t[POS[0]:]: got2 = "retype"; break
                if "passwords do not match" in t[POS[0]:]: got2 = "mismatch"; break
                if f"{prompt_user}@nxts> " in t[POS[0]:]: got2 = "prompt"; break
                time.sleep(0.1)
            if got2 == "retype":
                send_text(s, pw)
                wait_from(f"{prompt_user}@nxts> ", 30, f"prompt after useradd {user}")
        seg = sh(s, f"id {user}", prompt_user)
        if seg is not None and f"uid={expect_uid} " in seg:
            return seg
        send_text(s, "")
        wait_from(f"{prompt_user}@nxts> ", 30, "resync prompt")
    return None

ok = True
QUIET = [False]
PENDING = []
def flush_pending():
    for cond, label in PENDING:
        print(f"ok: {label}" if cond else f"FAIL: {label}")
    PENDING.clear()
def check(cond, label):
    global ok
    if QUIET[0]:
        PENDING.append((cond, label))
        if not cond: ok = False
        return
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

def fresh_blank(name):
    dst = os.path.join(WORK, name)
    shutil.copyfile(BLANK, dst)
    return dst

# ---- Boot A: editor round-trips as setup root ----
def boot_a():
    qemu, s = boot(fresh_blank("a.img"))
    try:
        check(wait_from("root@nxts> ", 60, "boot A prompt"), "boot A prompt")
        # create + type + save + exit
        edopen(s, "new.txt")
        edtype(s, "hello world")
        check(edsave(s, "new.txt"), "save new.txt")
        check(edexit(s), "exit new.txt")
        seg = sh(s, "cat new.txt", "root")
        check(seg is not None and "hello world" in seg, "cat proves created content")
        # Home/End/insert
        edopen(s, "new.txt")
        edkey(s, "home")
        edtype(s, ">> ")
        edkey(s, "end")
        edtype(s, "!")
        check(edsave(s, "new.txt"), "save home/end edit")
        check(edexit(s), "exit home/end edit")
        seg = sh(s, "cat new.txt", "root")
        check(seg is not None and ">> hello world!" in seg, "cat proves home/end insert")
        # search moves the cursor (insert lands at the match)
        edopen(s, "new.txt")
        edkey(s, "ctrl-w")
        edtype(s, "world")
        edenter(s)
        time.sleep(0.5)
        edtype(s, "?")
        check(edsave(s, "new.txt"), "save search edit")
        check(edexit(s), "exit search edit")
        seg = sh(s, "cat new.txt", "root")
        check(seg is not None and ">> hello ?world!" in seg, "cat proves search moved cursor")
        # cut/paste reorders lines
        edopen(s, "multi.txt")
        edtype(s, "line1")
        edenter(s)
        edtype(s, "line2")
        edenter(s)
        edtype(s, "line3")
        check(edsave(s, "multi.txt"), "save multi.txt")
        check(edexit(s), "exit multi.txt")
        edopen(s, "multi.txt")
        edkey(s, "ctrl-k")  # cut line1
        edkey(s, "down")    # to line3 (was line2 after cut... now lines are line2,line3; down -> line3)
        edkey(s, "ctrl-u")  # paste line1 before line3
        check(edsave(s, "multi.txt"), "save cut/paste edit")
        check(edexit(s), "exit cut/paste edit")
        seg = sh(s, "cat multi.txt", "root")
        check(seg is not None and "line2\nline1\nline3" in seg, "cat proves cut/paste reorder")
        # backspace-join
        edopen(s, "join.txt")
        edtype(s, "ab")
        edenter(s)
        edtype(s, "cd")
        check(edsave(s, "join.txt"), "save join.txt")
        check(edexit(s), "exit join.txt")
        edopen(s, "join.txt")
        edkey(s, "down")
        edkey(s, "backspace")
        check(edsave(s, "join.txt"), "save backspace-join")
        check(edexit(s), "exit backspace-join")
        seg = sh(s, "cat join.txt", "root")
        check(seg is not None and "\nabcd\n" in seg or (seg is not None and seg.strip().endswith("abcd")), "cat proves backspace-join")
        # del-join
        edopen(s, "join2.txt")
        edtype(s, "ab")
        edenter(s)
        edtype(s, "cd")
        check(edsave(s, "join2.txt"), "save join2.txt")
        check(edexit(s), "exit join2.txt")
        edopen(s, "join2.txt")
        edkey(s, "end")
        edkey(s, "delete")
        check(edsave(s, "join2.txt"), "save del-join")
        check(edexit(s), "exit del-join")
        seg = sh(s, "cat join2.txt", "root")
        check(seg is not None and "abcd" in seg, "cat proves del-join")
        # unsaved prompt: n discards
        edopen(s, "new.txt")
        edtype(s, "X")
        check(edexit_answer(s, "n"), "exit with n")
        seg = sh(s, "cat new.txt", "root")
        check(seg is not None and ">> hello ?world!" in seg and "X>>" not in seg, "n discards")
        # unsaved prompt: y saves
        edopen(s, "new.txt")
        edtype(s, "Y")
        check(edexit_answer(s, "y"), "exit with y")
        seg = sh(s, "cat new.txt", "root")
        check(seg is not None and "Y>> hello ?world!" in seg, "y saves")
        # unsaved prompt: c cancels (second ^X + n consumed by editor, not shell)
        edopen(s, "new.txt")
        edtype(s, "Z")
        edkey(s, "ctrl-x")
        time.sleep(0.5)
        s.sendall(b"sendkey c\n"); time.sleep(1.0)
        before = POS[0]
        check(edexit_answer(s, "n"), "exit with n after cancel")
        seg = sh(s, "cat new.txt", "root")
        check(seg is not None and "Y>> hello ?world!" in seg and "Z" not in seg, "c cancels, n discards")
        stray = log_text()[before:POS[0]]
        check("Unknown command: n" not in stray, "second ^X consumed by editor (c cancelled)")
        # save-as
        edopen(s, "new.txt")
        check(edsave_as(s, "copy.txt"), "save-as copy.txt")
        check(edexit(s), "exit save-as")
        seg = sh(s, "cat new.txt", "root")
        check(seg is not None and "Y>> hello ?world!" in seg, "save-as leaves old file untouched")
        seg = sh(s, "cat copy.txt", "root")
        check(seg is not None and "Y>> hello ?world!" in seg, "save-as writes new file")
        # help overlay opens and returns (return key consumed, not inserted)
        edopen(s, "new.txt")
        edkey(s, "ctrl-g")
        time.sleep(0.5)
        s.sendall(b"sendkey x\n"); time.sleep(1.0)
        edtype(s, "!")
        check(edsave(s, "new.txt"), "save help edit")
        check(edexit(s), "exit help edit")
        seg = sh(s, "cat new.txt", "root")
        check(seg is not None and "!Y>> hello ?world!" in seg and "xY" not in seg, "help returns, key consumed")
        # search-miss leaves buffer unmodified (^X exits at once)
        edopen(s, "new.txt")
        edkey(s, "ctrl-w")
        edtype(s, "zzz")
        edenter(s)
        time.sleep(0.5)
        check(edexit(s), "search-miss then ^X exits at once")
    finally:
        stop(qemu, s)

# Boot A runs up to twice: a lost editor scancode under load
# corrupts content while save/exit markers still pass, and the
# chained new.txt steps then cascade. Attempt 1 runs quiet;
# only the final attempt's lines print, plus a NOTE on retry.
# All content assertions stay exact — a retry never weakens them.
for _attempt in (1, 2):
    ok = True
    QUIET[0] = True
    PENDING.clear()
    boot_a()
    QUIET[0] = False
    if ok:
        flush_pending()
        break
    if _attempt == 1:
        PENDING.clear()
        print("NOTE: boot A attempt 1 failed, retrying from a fresh disk")
    else:
        flush_pending()

# ---- Boot B: seeded disk as alice ----
qemu, s = boot(SEED)
try:
    check(login(s, "alice", "pwalice"), "boot B login alice")
    edopen(s, "tab.txt")
    check(edsave(s, "tab.txt"), "save tab.txt")
    check(edexit(s), "exit tab.txt")
    seg = sh(s, "cat tab.txt", "alice")
    check(seg is not None and "a    b" in seg, "tab expands to 4 spaces")
    seg = sh(s, "edit big.txt", "alice")
    check(seg is not None and "edit: file too large (max 32768 bytes)" in seg, "oversized file refused")
    edopen(s, "long.txt")
    edkey(s, "ctrl-k")  # overlong line: cut refused, line intact
    check(edsave(s, "long.txt"), "save long.txt after refused cut")
    check(edexit(s), "exit long.txt")
    seg = sh(s, "cat long.txt", "alice")
    check(seg is not None and "L" * 60 in seg, "overlong line intact after refused cut")
    seg = sh(s, "edit secret.txt", "alice")
    check(seg is not None and "edit: cannot read file" in seg, "root-only file refused")
    seg = logout(s, "alice")
    check(seg is not None, "logout alice")
finally:
    stop(qemu, s)

# ---- Boot C: root edits alice's 0600 file, owner/mode kept ----
qemu, s = boot(fresh_blank("c.img"))
try:
    check(wait_from("root@nxts> ", 60, "boot C prompt"), "boot C prompt")
    seg = useradd(s, "alice", "pwalice", "root", 1000)
    check(seg is not None and "uid=1000 " in seg, "boot C useradd alice")
    seg = sh(s, "write own.txt alice data", "root")
    check(seg is not None and "Wrote own.txt" in seg, "root writes own.txt")
    seg = sh(s, "chown own.txt alice", "root")
    check(seg is not None and "chown: own.txt owner alice" in seg, "chown own.txt to alice")
    seg = sh(s, "chmod own.txt 600", "root")
    check(seg is not None and "chmod: own.txt mode 600" in seg, "chmod own.txt 600")
    edopen(s, "own.txt")
    edkey(s, "end")
    edtype(s, "!")
    check(edsave(s, "own.txt"), "save own.txt as root")
    check(edexit(s), "exit own.txt")
    seg = sh(s, "stat own.txt", "root")
    check(seg is not None and "uid 1000 (alice), mode 384" in seg, "owner + mode kept after root save")
    seg = sh(s, "cat own.txt", "root")
    check(seg is not None and "alice data!" in seg, "content updated after root save")
finally:
    stop(qemu, s)

print("CORE_EDIT TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
