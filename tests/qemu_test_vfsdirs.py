#!/usr/bin/env python3
"""Directories + VFS tree (CORE_CLI.md section 15.0): mkdir/nested
mkdir, cd/pwd (absolute, relative, .., .. at root), ls of cwd and
of a path, files inside subdirectories, rename across directories,
rmdir empty vs non-empty, hard links (shared writes, delete one
link, delete last link frees sectors), symlinks inside a
directory, old-disk mount compatibility (the setup disk is a
pre-VFS mkdisk image: every entry already has reserved[1] = 0),
permission refusals in a root-only directory, malformed paths,
sidecar timestamps, and persistence across a reboot.

Two boots on the same disk: Boot 1 does everything, Boot 2
proves the tree survived a reboot with no migration step.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_vfsdirs.py <iso> <workdir>
"""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5",
          "&": "shift-7", "|": "shift-backslash"}
# QEMU monitor key names are lowercase: an uppercase letter must be
# sent as shift-<lower>, or the keypress is dropped entirely (the
# run-1/run-2 link failures: "AAAA"/"BBBBBB" never reached the
# guest, so the file was never created and ln correctly said
# "not found" — a harness bug, not a kernel bug).
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

def send_text(s, txt):
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def sh(s, txt, user):
    before = POS[0]
    send_verified(s, txt)
    seg = None
    for _ in range(4):
        if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt}"):
            # No prompt at all: the monitor Enter may have been
            # dropped (documented sendkey flake). Resending a
            # bare Enter is harmless on an empty prompt line and
            # executes a still-pending command line.
            try: s.sendall(b"sendkey ret\n")
            except Exception: pass
            time.sleep(1)
            continue
        seg = log_text()[before:POS[0]]
        if f"{txt}\n" in seg:
            break
        # Prompt returned but our echo is not in the segment:
        # same recovery — a pending line gets executed.
        try: s.sendall(b"sendkey ret\n")
        except Exception: pass
        time.sleep(1)
    return seg

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

def login(s, user, pw):
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

def fs_free(s, user):
    """Free sectors from `fs` status output (None on failure)."""
    seg = sh(s, "fs", user)
    if seg is None: return None
    m = re.search(r"sectors total, (\d+) free", seg)
    return int(m.group(1)) if m else None

# ---------------- Boot 1 ----------------
qemu, s = boot(DISK)
try:
    check(login(s, "admin", "pwadmin"), "login as admin")
    # Old-disk compatibility: the setup disk is pre-VFS format.
    seg = sh(s, "cat root.txt", "admin")
    check(seg is not None and "old disk root file" in seg, "old-disk root file reads (no migration)")
    seg = sh(s, "ls", "admin")
    check(seg is not None and "root.txt" in seg, "old-disk ls lists root files")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and "\n/\n" in seg, "pwd starts at /")
    # mkdir + nested mkdir + cd/pwd.
    seg = sh(s, "mkdir a", "admin")
    check(seg is not None and "mkdir: created a" in seg, "mkdir a")
    seg = sh(s, "mkdir a/b", "admin")
    check(seg is not None and "mkdir: created a/b" in seg, "nested mkdir a/b")
    seg = sh(s, "mkdir a", "admin")
    check(seg is not None and "already exists" in seg, "mkdir refuses an existing child name")
    seg = sh(s, "cd a", "admin")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and "\n/a\n" in seg, "cd a (relative) + pwd /a")
    seg = sh(s, "cd b", "admin")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and "\n/a/b\n" in seg, "cd b (relative) + pwd /a/b")
    seg = sh(s, "cd ..", "admin")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and "\n/a\n" in seg, "cd .. goes to parent")
    seg = sh(s, "cd /a/b", "admin")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and "\n/a/b\n" in seg, "cd /a/b (absolute) + pwd")
    seg = sh(s, "cd ../..", "admin")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and "\n/\n" in seg, "cd ../.. from /a/b reaches /")
    seg = sh(s, "cd ..", "admin")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and seg is not None and "\n/\n" in seg, ".. at root stays at root")
    seg = sh(s, "cd missing", "admin")
    check(seg is not None and "no such directory" in seg, "cd to a missing directory refuses with a reason")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and "\n/\n" in seg, "failed cd leaves cwd unchanged")
    seg = sh(s, "cd", "admin")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and "\n/\n" in seg, "bare cd means /")
    # ls of cwd and of a path; ls of a file.
    seg = sh(s, "ls a", "admin")
    check(seg is not None and "b/" in seg, "ls a lists the child directory with a trailing /")
    seg = sh(s, "ls /a/b", "admin")
    check(seg is not None and "(no files)" in seg, "ls /a/b shows an empty directory")
    # Files inside a subdirectory.
    seg = sh(s, "mkdir sub", "admin")
    seg = sh(s, "write sub/real.txt inner content", "admin")
    check(seg is not None and "Wrote sub/real.txt" in seg, "write inside a subdirectory")
    seg = sh(s, "cat sub/real.txt", "admin")
    check(seg is not None and "inner content" in seg, "cat inside a subdirectory")
    seg = sh(s, "cd sub", "admin")
    seg = sh(s, "write rel.txt relative content", "admin")
    seg = sh(s, "cat rel.txt", "admin")
    check(seg is not None and "relative content" in seg, "write/cat with a relative path from inside a directory")
    seg = sh(s, "ls", "admin")
    check(seg is not None and "real.txt" in seg and "rel.txt" in seg, "ls of cwd lists subdirectory children")
    seg = sh(s, "ls real.txt", "admin")
    check(seg is not None and "real.txt" in seg and "(1 files)" in seg, "ls of a file path lists just that file")
    seg = sh(s, "cd /", "admin")
    # Rename across directories + into a directory + rename a directory.
    seg = sh(s, "mkdir d1", "admin")
    seg = sh(s, "mkdir d2", "admin")
    seg = sh(s, "write d1/f.txt cross content", "admin")
    seg = sh(s, "mv d1/f.txt d2/f.txt", "admin")
    check(seg is not None and "Renamed d1/f.txt to d2/f.txt" in seg, "rename across directories")
    seg = sh(s, "cat d2/f.txt", "admin")
    check(seg is not None and "cross content" in seg, "renamed file reads in its new directory")
    seg = sh(s, "cat d1/f.txt", "admin")
    check(seg is not None and "cannot read" in seg, "renamed file is gone from its old directory")
    seg = sh(s, "ls d1", "admin")
    check(seg is not None and "(no files)" in seg, "old directory is empty after the move")
    seg = sh(s, "write top.txt top content", "admin")
    seg = sh(s, "mv top.txt d2", "admin")
    check(seg is not None and "Renamed top.txt to d2" in seg, "mv into an existing directory moves the file into it")
    seg = sh(s, "cat d2/top.txt", "admin")
    check(seg is not None and "top content" in seg, "moved-into-directory file reads back")
    seg = sh(s, "mv d2 d3", "admin")
    check(seg is not None and "Renamed d2 to d3" in seg, "rename a directory")
    seg = sh(s, "ls d3", "admin")
    check(seg is not None and "f.txt" in seg and "top.txt" in seg, "renamed directory keeps its children")
    seg = sh(s, "mv d3 d3/inner", "admin")
    check(seg is not None and "cannot rename" in seg, "moving a directory into itself is refused")
    # rmdir: empty vs non-empty, rm of a directory.
    seg = sh(s, "mkdir keep", "admin")
    seg = sh(s, "write keep/f.txt keepme", "admin")
    seg = sh(s, "rmdir keep", "admin")
    check(seg is not None and "directory not empty" in seg, "rmdir refuses a non-empty directory")
    seg = sh(s, "rm keep", "admin")
    check(seg is not None and "is a directory (use rmdir)" in seg, "rm of a directory is refused with a reason")
    seg = sh(s, "rm keep/f.txt", "admin")
    seg = sh(s, "rmdir keep", "admin")
    check(seg is not None and "rmdir: removed keep" in seg, "rmdir removes an empty directory")
    seg = sh(s, "rmdir keep", "admin")
    check(seg is not None and "not found" in seg, "rmdir of a missing directory refuses")
    seg = sh(s, "rm sub", "admin")
    check(seg is not None and "is a directory" in seg, "rm of a non-empty directory is refused")
    # Hard links + sector accounting (warm-up write first, so the
    # sidecar file already exists and later writes are sector-neutral).
    seg = sh(s, "write warm.txt warm", "admin")
    f_base = fs_free(s, "admin")
    check(f_base is not None, "fs free-sector baseline reads")
    seg = sh(s, "write linksrc.txt AAAA", "admin")
    f1 = fs_free(s, "admin")
    check(f1 is not None and f_base is not None and f1 == f_base - 1, "creating a 1-sector file costs exactly 1 free sector")
    seg = sh(s, "ln linksrc.txt linkdst.txt", "admin")
    check(seg is not None and "Linked linkdst.txt to linksrc.txt" in seg, "ln creates a hard link")
    f2 = fs_free(s, "admin")
    check(f2 is not None and f2 == f1, "hard link costs no new data sector")
    seg = sh(s, "write linkdst.txt BBBBBB", "admin")
    seg = sh(s, "cat linksrc.txt", "admin")
    check(seg is not None and "BBBBBB" in seg, "write via one link is visible via the other")
    seg = sh(s, "stat linksrc.txt", "admin")
    check(seg is not None and "6 bytes" in seg, "shared write updates the size seen via both links")
    f3 = fs_free(s, "admin")
    check(f3 is not None and f3 == f1, "shared write is sector-neutral (new sector, old freed)")
    seg = sh(s, "rm linksrc.txt", "admin")
    seg = sh(s, "cat linkdst.txt", "admin")
    check(seg is not None and "BBBBBB" in seg, "deleting one link leaves the data via the other")
    f4 = fs_free(s, "admin")
    check(f4 is not None and f4 == f1, "deleting one link frees no sector")
    seg = sh(s, "rm linkdst.txt", "admin")
    f5 = fs_free(s, "admin")
    check(f5 is not None and f_base is not None and f5 == f_base, "deleting the last link frees the sector")
    seg = sh(s, "ln sub/real.txt sub/hard.txt", "admin")
    seg = sh(s, "cat sub/hard.txt", "admin")
    check(seg is not None and "inner content" in seg, "hard link inside a directory reads the shared data")
    seg = sh(s, "ln sub/real.txt sub", "admin")
    check(seg is not None and "cannot link" in seg, "hard link over an existing name is refused")
    seg = sh(s, "ln sub sublink", "admin")
    check(seg is not None and "cannot link" in seg, "hard link to a directory is refused")
    # Symlinks inside a directory (relative + absolute + loop + write-through).
    seg = sh(s, "ln -s real.txt sub/alias", "admin")
    check(seg is not None and "Linked sub/alias -> real.txt" in seg, "symlink inside a directory (relative target)")
    seg = sh(s, "cat sub/alias", "admin")
    check(seg is not None and "inner content" in seg, "relative symlink resolves from its parent directory")
    seg = sh(s, "readlink sub/alias", "admin")
    check(seg is not None and "\nreal.txt\n" in seg, "readlink prints the stored target")
    seg = sh(s, "ln -s /sub/real.txt absalias", "admin")
    seg = sh(s, "cat absalias", "admin")
    check(seg is not None and "inner content" in seg, "absolute symlink target resolves from root")
    seg = sh(s, "write sub/alias changed content", "admin")
    seg = sh(s, "cat sub/real.txt", "admin")
    check(seg is not None and "changed content" in seg, "write through a directory symlink changes the target")
    seg = sh(s, "ln -s loop2 sub/loop1", "admin")
    seg = sh(s, "ln -s loop1 sub/loop2", "admin")
    seg = sh(s, "cat sub/loop1", "admin")
    check(seg is not None and "cannot read" in seg, "symlink loop inside a directory fails visibly")
    # Sidecar timestamps + touch + test -d/-f.
    seg = sh(s, "stat sub/real.txt", "admin")
    check(seg is not None and re.search(r"mtime [1-9][0-9]* ticks, atime [1-9][0-9]* ticks", seg or "") is not None,
          "stat shows nonzero sidecar mtime/atime ticks after writes and reads")
    seg = sh(s, "touch sub/real.txt", "admin")
    check(seg is not None and "(exists)" in seg, "touch of an existing file reports exists")
    seg = sh(s, "test -d sub && echo YESDIR", "admin")
    check(seg is not None and "YESDIR" in seg, "test -d is true for a directory")
    seg = sh(s, "test -d sub/real.txt || echo NOTDIR", "admin")
    check(seg is not None and "NOTDIR" in seg, "test -d is false for a file")
    seg = sh(s, "test -f sub/real.txt && echo ISFILE", "admin")
    check(seg is not None and "ISFILE" in seg, "test -f is true for a file")
    # Malformed paths.
    seg = sh(s, "cat a//b", "admin")
    check(seg is not None and "cannot read" in seg, "empty component (//) is refused")
    seg = sh(s, "ls sub/", "admin")
    check(seg is not None and "invalid path" in seg, "trailing slash is refused as a malformed path")
    seg = sh(s, "mkdir aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "admin")
    check(seg is not None and "invalid path" in seg, "overlong component (32 chars) is refused")
    seg = sh(s, "ls x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x/x", "admin")
    check(seg is not None and "invalid path" in seg, "too many components (17) are refused")
    seg = sh(s, "cat /nope/deep.txt", "admin")
    check(seg is not None and "cannot read" in seg, "path through a missing directory is refused")
    # Permission refusals in a root-only directory.
    seg = sh(s, "cd /", "admin")
    seg = sh(s, "mkdir priv", "admin")
    seg = sh(s, "chmod priv 0700", "admin")
    seg = sh(s, "su alice", "alice")
    check(seg is not None, "su alice (root needs no password)")
    seg = sh(s, "ls priv", "alice")
    check(seg is not None and "permission denied" in seg, "non-root cannot list a root-only directory")
    seg = sh(s, "ls /priv", "alice")
    check(seg is not None and "permission denied" in seg, "non-root cannot list a root-only directory by absolute path")
    seg = sh(s, "write priv/secret.txt hi", "alice")
    check(seg is not None and "permission denied" in seg, "non-root cannot write inside a root-only directory")
    seg = sh(s, "mkdir priv/x", "alice")
    check(seg is not None and "permission denied" in seg, "non-root cannot mkdir inside a root-only directory")
    seg = sh(s, "cd priv", "alice")
    check(seg is not None and "permission denied" in seg, "non-root cannot cd into a root-only directory")
    seg = sh(s, "ls", "alice")
    check(seg is not None and "root.txt" in seg, "non-root root listing still works")
    # logout ends the session, so sh() (which waits for a shell
    # prompt) is the wrong helper here: just type it and let
    # login() wait for the login prompt from the same position.
    send_verified(s, "logout")
    time.sleep(1)
    check(login(s, "admin", "pwadmin"), "login as admin after logout")
    seg = sh(s, "pwd", "admin")
    check(seg is not None and "\n/\n" in seg, "cwd resets to / on login")
    seg = sh(s, "ls", "admin")
    check(seg is not None and "sub/" in seg and "a/" in seg and "d3/" in seg, "final root listing shows the created directories")
finally:
    stop(qemu, s)

# ---------------- Boot 2: persistence, no migration ----------------
qemu, s = boot(DISK)
try:
    check(login(s, "admin", "pwadmin"), "Boot 2: login as admin")
    seg = sh(s, "ls", "admin")
    check(seg is not None and "sub/" in seg and "a/" in seg and "d3/" in seg, "Boot 2: directories survived the reboot")
    seg = sh(s, "cat sub/real.txt", "admin")
    check(seg is not None and "changed content" in seg, "Boot 2: subdirectory file content survived")
    seg = sh(s, "cat sub/alias", "admin")
    check(seg is not None and "changed content" in seg, "Boot 2: directory symlink survived")
    seg = sh(s, "cat root.txt", "admin")
    check(seg is not None and "old disk root file" in seg, "Boot 2: old-disk root file still reads")
    seg = sh(s, "cat d3/f.txt", "admin")
    check(seg is not None and "cross content" in seg, "Boot 2: cross-directory rename survived")
finally:
    stop(qemu, s)
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
