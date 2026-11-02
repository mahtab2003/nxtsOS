#!/usr/bin/env python3
"""Core user-management test: useradd/userdel, groups, id,
chown, stat, and the failed-login record drop.

Boots (all on the same ISO):
  A (fresh blank disk, setup-mode root): useradd carol
     (password prompts, echo off) + duplicates/usage/bad-name
     refusals; groupadd/groupmod/groups/id round-trip incl.
     already-member / not-a-member / no-such-user /
     no-such-group / usage refusals; groupdel; userdel
     root/ghost refusals; logout -> login as carol works
     (setup-mode transition); passwd for the added user
     works; non-root useradd/userdel/groupadd/groupdel/
     groupmod/chown all refused with "root only".
  B (fresh blank disk, setup-mode root): chown round-trip
     (root file -> carol -> root -> carol; no-such-user and
     missing-file refusals); bob reads the world-readable
     file but cannot overwrite it (non-owner, other-write
     clear); bob can stat a readable file but not the
     root-only users.txt; carol (owner after chown) writes.
  C1 (admin disk): alice fails login 3x -> "Too many failed
     attempts. System halted." (fails.txt now holds alice:3).
  C2 (SAME disk as C1): admin (uid 0, named session) cannot
     delete itself ("cannot delete the session user");
     fails.txt shows alice:3; admin deletes alice and
     fails.txt no longer mentions alice (record dropped);
     re-added alice logs in with the new password (no
     inherited lockout).
  D (fresh blank disk, setup-mode root): 8 useradds fill
     MAX_USERS; the 9th is refused with "user limit
     reached (8)" before any password prompt.

Password-prompt helpers retry the whole flow (up to 3 attempts)
on sendkey flakes: a doubled key during a password prompt
desyncs naive prompt matching (a doubled Enter makes the
Retype read consume an empty line instantly, so the second
password send lands at the command prompt as a stray
command), so each prompt step is guarded with wait_either,
attempts resync with a bare Enter, and useradd success is
proven by an independent `id` command, not by the prompt
segment. Login retries on "Login incorrect" at most twice
per user per boot (a third recorded failure would lock the
account, and a third failed attempt in one login loop halts
the machine).
Parity-run hardening: cmd() now uses the echo-aware verified
sender (the old send_text only noticed "Unknown command", so
a doubled key inside an argument silently ran the wrong
command — e.g. a corrupted "userdel alice" left fails.txt
unchanged and the drop check failed downstream); the drop
check itself is line-based (content lines only, not a
substring over the whole segment).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_core_users.py <iso> <workdir>
<workdir> is created by tests/qemu_test_core_users_setup.py.
"""
import os, shutil, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
BLANK = os.path.join(WORK, "blank.img")
ADMIN = os.path.join(WORK, "admin.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus", ":": "shift-semicolon",
          "/": "slash", "%": "shift-5"}
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEYMAP[_c] = "shift-" + _c.lower()
KEYMAP.update({"$": "shift-4", "!": "shift-1", "'": "apostrophe",
               '"': "shift-apostrophe", "=": "equal"})

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
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(1)
        if "Unknown command" not in log_text()[before:]:
            break

def _current_line(t):
    # Current shell line: text after the last prompt, with
    # backspaces interpreted and job output (a newline) resetting
    # the line — the parity-suite verified-sender pattern.
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
    # Echo-verified send: type, check the echo matches exactly
    # (catches a dropped/doubled key, including inside an
    # argument, where the old send_text only noticed "Unknown
    # command"), erase and retype between attempts, and on the
    # final attempt submit anyway so a failure is loud (an
    # "Unknown command" line) instead of silently never run.
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
    s.sendall(b"sendkey ret\n"); time.sleep(1)
    return False

def cmd(s, txt, user):
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
        print(f"NOTE: login retry {user} (recorded failures {FAILS[user]})")
        if FAILS[user] >= 2:
            print(f"FAIL: too many login failures for {user}, refusing a third")
            return False
    return False

def logout(s, user):
    before = POS[0]
    send_text(s, "logout")
    if not wait_from("Logged out.", 30, f"logout {user}"): return None
    return log_text()[before:POS[0]]

def wait_either(needles, timeout, label):
    for _ in range(int(timeout * 10)):
        t = log_text()
        best = None
        for n in needles:
            i = t.find(n, POS[0])
            if i >= 0 and (best is None or i < best[1]):
                best = (n, i)
        if best:
            POS[0] = best[1] + len(best[0])
            return best[0]
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return None

def resync_prompt(s, user):
    """Send a bare Enter and wait for a command prompt. If the
    shell is at a password prompt, the empty line fails that
    prompt (empty/mismatch) and returns to the command prompt;
    if already at a command prompt, it is a harmless empty
    command. Either way a shell session ends at a command
    prompt. Returns True if the prompt was seen."""
    send_text(s, "")
    return wait_from(f"{user}@nxts> ", 30, "resync prompt")

def useradd(s, user, pw, prompt_user, expect_uid):
    """Add a user, retrying the whole flow on sendkey flakes.
    A doubled key during a password prompt desyncs naive
    prompt-segment matching (a doubled Enter makes the Retype
    read consume an empty line instantly, so the second
    password send lands at the command prompt as a stray
    command). So: guard each prompt step with wait_either
    (abort the attempt as soon as a failure line appears),
    resync with a bare Enter between attempts, and prove
    success with an independent `id` command, not with the
    prompt segment. Returns the `id` segment on success,
    None after 3 attempts."""
    for attempt in range(3):
        send_text(s, f"useradd {user}")
        got = wait_either(["New password: ", f"{prompt_user}@nxts> "], 30, f"new-pw {user}")
        if got == "New password: ":
            send_text(s, pw)
            got2 = wait_either(["Retype new password: ", "passwords do not match",
                                "empty password not allowed", f"{prompt_user}@nxts> "],
                               30, f"retype {user}")
            if got2 == "Retype new password: ":
                send_text(s, pw)
                wait_from(f"{prompt_user}@nxts> ", 30, f"prompt after useradd {user}")
        # Independent verification, immune to prompt-segment desync.
        seg = cmd(s, f"id {user}", prompt_user)
        if seg is not None and f"uid={expect_uid} " in seg:
            return seg
        print(f"NOTE: useradd {user} attempt {attempt+1} not verified, resyncing")
        resync_prompt(s, prompt_user)
    return None

def passwd_change(s, cur, new, prompt_user):
    """Change the session user's password, retrying the whole
    flow on sendkey flakes (same doubled-key hazard as
    useradd: guard each prompt step, resync between attempts).
    Returns the segment containing "Password changed" on
    success, None after 3 attempts."""
    for attempt in range(3):
        before = POS[0]
        send_text(s, "passwd")
        got = wait_either(["Current password: ", f"{prompt_user}@nxts> "], 30, "current-pw prompt")
        if got != "Current password: ":
            resync_prompt(s, prompt_user); continue
        send_text(s, cur)
        got = wait_either(["New password: ", "passwd: incorrect password",
                           f"{prompt_user}@nxts> "], 30, "passwd new prompt")
        if got != "New password: ":
            resync_prompt(s, prompt_user); continue
        send_text(s, new)
        got = wait_either(["Retype new password: ", "passwd: empty password not allowed",
                           f"{prompt_user}@nxts> "], 30, "passwd retype prompt")
        if got != "Retype new password: ":
            resync_prompt(s, prompt_user); continue
        send_text(s, new)
        if not wait_from(f"{prompt_user}@nxts> ", 30, "prompt after passwd"):
            resync_prompt(s, prompt_user); continue
        seg = log_text()[before:POS[0]]
        if "Password changed for" in seg:
            return seg
        print(f"NOTE: passwd attempt {attempt+1} not verified, resyncing")
        resync_prompt(s, prompt_user)
    return None

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

def fresh_blank(name):
    dst = os.path.join(WORK, name)
    shutil.copyfile(BLANK, dst)
    return dst

# ---- Boot A: user/group management as setup root, then carol ----
qemu, s = boot(fresh_blank("a.img"))
try:
    check(wait_from("root@nxts> ", 60, "boot A prompt"), "boot A prompt")
    seg = useradd(s, "carol", "pwcarol", "root", 1000)
    check(seg is not None and "uid=1000 " in seg, "useradd carol")
    seg = cmd(s, "useradd carol", "root")
    check(seg is not None and "useradd: user carol already exists" in seg, "useradd duplicate refused")
    seg = cmd(s, "useradd bad:name", "root")
    check(seg is not None and "useradd: bad name bad:name" in seg, "useradd colon name refused")
    seg = cmd(s, "useradd", "root")
    check(seg is not None and "Usage: useradd <user>" in seg, "useradd no-arg usage")
    seg = cmd(s, "useradd a b", "root")
    check(seg is not None and "Usage: useradd <user>" in seg, "useradd extra-arg usage")
    seg = cmd(s, "groupadd staff", "root")
    check(seg is not None and "Added group staff (gid 1000)" in seg, "groupadd staff")
    seg = cmd(s, "groupadd staff", "root")
    check(seg is not None and "groupadd: group staff already exists" in seg, "groupadd duplicate refused")
    seg = cmd(s, "groupadd bad:name", "root")
    check(seg is not None and "groupadd: bad name bad:name" in seg, "groupadd colon name refused")
    seg = cmd(s, "groupmod staff add carol", "root")
    check(seg is not None and "Added carol to staff" in seg, "groupmod add")
    seg = cmd(s, "groupmod staff add carol", "root")
    check(seg is not None and "already a member" in seg, "groupmod add existing member reported")
    seg = cmd(s, "groupmod staff add ghost", "root")
    check(seg is not None and "groupmod: no such user ghost" in seg, "groupmod unknown user refused")
    seg = cmd(s, "groupmod nosuch add carol", "root")
    check(seg is not None and "groupmod: no such group nosuch" in seg, "groupmod unknown group refused")
    seg = cmd(s, "groupmod staff bogus carol", "root")
    check(seg is not None and "Usage: groupmod <group> add|remove <user>" in seg, "groupmod bad op usage")
    seg = cmd(s, "groupmod staff", "root")
    check(seg is not None and "Usage: groupmod <group> add|remove <user>" in seg, "groupmod missing args usage")
    seg = cmd(s, "groups carol", "root")
    check(seg is not None and "carol: staff" in seg, "groups carol lists staff")
    seg = cmd(s, "id carol", "root")
    check(seg is not None and "uid=1000 groups=staff" in seg, "id carol")
    seg = cmd(s, "groups", "root")
    check(seg is not None and "root: none" in seg, "groups (root) is none")
    seg = cmd(s, "id", "root")
    check(seg is not None and "uid=0 groups=none" in seg, "id (root)")
    seg = cmd(s, "groups ghost", "root")
    check(seg is not None and "groups: no such user ghost" in seg, "groups unknown user refused")
    seg = cmd(s, "id ghost", "root")
    check(seg is not None and "id: no such user ghost" in seg, "id unknown user refused")
    seg = cmd(s, "groupmod staff remove carol", "root")
    check(seg is not None and "Removed carol from staff" in seg, "groupmod remove")
    seg = cmd(s, "groupmod staff remove carol", "root")
    check(seg is not None and "not a member" in seg, "groupmod remove non-member reported")
    seg = cmd(s, "groupmod staff add carol", "root")
    check(seg is not None and "Added carol to staff" in seg, "groupmod re-add")
    seg = cmd(s, "groupdel staff", "root")
    check(seg is not None and "Deleted group staff" in seg, "groupdel staff")
    seg = cmd(s, "id carol", "root")
    check(seg is not None and "uid=1000 groups=none" in seg, "id carol after groupdel")
    seg = cmd(s, "groupdel staff", "root")
    check(seg is not None and "groupdel: no such group staff" in seg, "groupdel missing group refused")
    seg = cmd(s, "userdel root", "root")
    check(seg is not None and "userdel: cannot delete root" in seg, "userdel root refused")
    seg = cmd(s, "userdel ghost", "root")
    check(seg is not None and "userdel: no such user ghost" in seg, "userdel unknown user refused")
    seg = logout(s, "root")
    check(seg is not None, "logout root after useradd")
    check(login(s, "carol", "pwcarol"), "login as added carol (setup-mode transition)")
    seg = passwd_change(s, "pwcarol", "pwcarol2", "carol")
    check(seg is not None and "Password changed for carol" in seg, "passwd for added user")
    seg = logout(s, "carol")
    check(seg is not None, "logout carol")
    check(login(s, "carol", "pwcarol2"), "login carol with new password")
    for txt, want in [("useradd dave", "useradd: root only"),
                      ("userdel carol", "userdel: root only"),
                      ("groupadd g2", "groupadd: root only"),
                      ("groupdel staff", "groupdel: root only"),
                      ("groupmod staff add carol", "groupmod: root only"),
                      ("chown users.txt carol", "chown: root only")]:
        seg = cmd(s, txt, "carol")
        check(seg is not None and want in seg, f"non-root {txt} refused")
    seg = cmd(s, "groups", "carol")
    check(seg is not None and "carol: none" in seg, "groups (carol) is none")
    seg = cmd(s, "id", "carol")
    check(seg is not None and "uid=1000 groups=none" in seg, "id (carol)")
    seg = logout(s, "carol")
    check(seg is not None, "logout carol final")
finally:
    stop(qemu, s)

# ---- Boot B: chown/stat round-trip ----
qemu, s = boot(fresh_blank("b.img"))
try:
    check(wait_from("root@nxts> ", 60, "boot B prompt"), "boot B prompt")
    seg = useradd(s, "carol", "pwcarol", "root", 1000)
    check(seg is not None and "uid=1000 " in seg, "boot B useradd carol")
    seg = useradd(s, "bob", "pwbob", "root", 1001)
    check(seg is not None and "uid=1001 " in seg, "boot B useradd bob")
    seg = cmd(s, "write doc.txt hello", "root")
    check(seg is not None and "Wrote doc.txt" in seg, "root writes doc.txt")
    seg = cmd(s, "stat doc.txt", "root")
    check(seg is not None and "doc.txt: 5 bytes, uid 0 (root), mode 420, 1 sectors" in seg, "stat root file")
    seg = cmd(s, "chown doc.txt carol", "root")
    check(seg is not None and "chown: doc.txt owner carol" in seg, "chown to carol")
    seg = cmd(s, "stat doc.txt", "root")
    check(seg is not None and "doc.txt: 5 bytes, uid 1000 (carol), mode 420, 1 sectors" in seg, "stat after chown")
    seg = cmd(s, "chown doc.txt ghost", "root")
    check(seg is not None and "chown: no such user ghost" in seg, "chown unknown user refused")
    seg = cmd(s, "chown missing.txt carol", "root")
    check(seg is not None and "chown: cannot chown missing.txt" in seg, "chown missing file refused")
    seg = cmd(s, "chown doc.txt root", "root")
    check(seg is not None and "chown: doc.txt owner root" in seg, "chown to root")
    seg = cmd(s, "chown doc.txt carol", "root")
    check(seg is not None and "chown: doc.txt owner carol" in seg, "chown back to carol")
    seg = logout(s, "root")
    check(seg is not None, "logout root boot B")
    check(login(s, "bob", "pwbob"), "login bob")
    seg = cmd(s, "cat doc.txt", "bob")
    check(seg is not None and "hello" in seg, "bob reads world-readable file")
    seg = cmd(s, "write doc.txt hacked", "bob")
    check(seg is not None and "cannot write doc.txt" in seg, "bob cannot overwrite non-owned file")
    seg = cmd(s, "stat doc.txt", "bob")
    check(seg is not None and "uid 1000 (carol)" in seg, "bob stats readable file")
    seg = cmd(s, "stat users.txt", "bob")
    check(seg is not None and "stat: cannot stat users.txt" in seg, "bob cannot stat root-only file")
    seg = logout(s, "bob")
    check(seg is not None, "logout bob")
    check(login(s, "carol", "pwcarol"), "login carol")
    seg = cmd(s, "write doc.txt world", "carol")
    check(seg is not None and "Wrote doc.txt" in seg, "owner writes after chown")
    seg = cmd(s, "cat doc.txt", "carol")
    check(seg is not None and "world" in seg, "owner read-back after chown")
    seg = logout(s, "carol")
    check(seg is not None, "logout carol boot B")
finally:
    stop(qemu, s)

# ---- Boot C1: lock alice out (3 failures -> halt) ----
admin_work = os.path.join(WORK, "admin_work.img")
shutil.copyfile(ADMIN, admin_work)
qemu, s = boot(admin_work)
try:
    check(wait_from("login: ", 60, "boot C1 login prompt"), "boot C1 login prompt")
    for i in range(3):
        send_text(s, "alice")
        check(wait_from("Password: ", 30, f"C1 password prompt {i+1}"), f"C1 password prompt {i+1}")
        send_text(s, "wrongpw")
        check(wait_from("Login incorrect", 30, f"C1 incorrect {i+1}"), f"C1 incorrect {i+1}")
    check(wait_from("Too many failed attempts. System halted.", 30, "C1 halt message"),
          "3 failures halt the machine")
    time.sleep(2)
    check(qemu.poll() is None, "halted VM stays present after lockout")
finally:
    stop(qemu, s)

# ---- Boot C2: same disk — admin deletes/re-adds alice ----
qemu, s = boot(admin_work)
try:
    check(login(s, "admin", "pwadmin"), "login admin (uid 0)")
    seg = cmd(s, "whoami", "admin")
    check(seg is not None and "admin uid 0" in seg, "whoami admin uid 0")
    seg = cmd(s, "userdel admin", "admin")
    check(seg is not None and "userdel: cannot delete the session user" in seg,
          "uid-0 session cannot delete itself")
    seg = cmd(s, "cat fails.txt", "admin")
    check(seg is not None and "alice:3" in seg, "fails.txt holds alice:3")
    seg = cmd(s, "userdel alice", "admin")
    check(seg is not None and "Deleted user alice" in seg, "admin deletes alice")
    seg = cmd(s, "cat fails.txt", "admin")
    # Line-based drop check (parity-run hardening): the old
    # substring check ("alice" not in seg) could false-positive
    # on any stray mention anywhere in the segment; a fails.txt
    # record IS one line, so only content lines count. Content
    # lines = seg lines minus the typed-echo first line and the
    # trailing prompt fragment.
    lines = []
    if seg is not None:
        parts = seg.split("\n")
        lines = parts[1:-1] if len(parts) >= 2 else []
    check(seg is not None and not any("alice" in ln for ln in lines), "fails record dropped on delete")
    seg = useradd(s, "alice", "pwalice2", "admin", 1000)
    check(seg is not None and "uid=1000 " in seg, "re-add alice")
    seg = logout(s, "admin")
    check(seg is not None, "logout admin")
    check(login(s, "alice", "pwalice2"), "re-added alice logs in (no inherited lockout)")
    seg = logout(s, "alice")
    check(seg is not None, "logout alice final")
finally:
    stop(qemu, s)

# ---- Boot D: MAX_USERS cap ----
qemu, s = boot(fresh_blank("d.img"))
try:
    check(wait_from("root@nxts> ", 60, "boot D prompt"), "boot D prompt")
    for i in range(1, 9):
        seg = useradd(s, f"u{i}", "pwtest", "root", 999 + i)
        check(seg is not None and f"uid={999 + i} " in seg, f"useradd u{i}")
    seg = cmd(s, "useradd u9", "root")
    check(seg is not None and "useradd: user limit reached (8)" in seg, "9th user refused")
finally:
    stop(qemu, s)

print("CORE_USERS TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
