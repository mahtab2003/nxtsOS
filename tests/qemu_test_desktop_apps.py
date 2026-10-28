#!/usr/bin/env python3
"""Phase 10 apps test (v0.10.0, mode 5).
Boot 1 (setup mode, no login): install calc.nxpkg + term.nxpkg.
Boot 2: desktopappstest — launcher column 2 (Editor, Monitor,
Network, Web, Viewer, Console, Packages, Repo, Clock), then
Files: notes.txt -> Editor, New-file flow, Editor scroll
(16 newlines + Up/Down buttons), close Editor, pic.bmp -> Viewer,
then Files scroll (close Viewer, Files icon, Dn button, row 7
= filler1.txt -> Editor), then Files delete (close Editor,
Files icon, Delete twice on filler1.txt, row 7 = filler2.txt
-> Editor, proving the list reloaded and shifted), then Files
rename (close Editor, Files icon, row 7 = filler2.txt, rename
field, type "renamed.txt", Rename, row 7 = renamed.txt ->
Editor, proving the rename + reload) and its negative control
(rename renamed.txt to the existing filler3.txt -> refused),
then Files copy (Copy button with the still-held "filler3.txt"
-> refused, then field cleared, "copied.txt", Copy -> copied,
row 7 = copied.txt -> Editor, proving the copy exists with
its content), then Files refresh (copied.txt -> Editor, New
twice, "refreshed.txt", Save — a file created on disk while
the Files window behind it is stale — close Editor, Files
icon, Refresh -> refreshed, nine Dn clicks to scroll 10,
row 7 = refreshed.txt -> Editor, proving the refresh picked
up the outside-window save). Boot 2 waits 120 s for its final
marker: 244 autotest steps at 30 ticks each take ~74 s, past
the 60 s the 187-step script needed.
The Repo window is proven against a real signed stored index
(version 2, calc 1.0 + term 1.0) from the setup disk. The Clock
window is proven by its open marker + time/uptime prints.
Usage: python3 tests/qemu_test_desktop_apps.py <iso> <workdir>
<workdir> is created by tests/qemu_test_desktop_apps_setup.py.
Exit 0 only if all checks pass."""
import os, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

def boot(actions, wait_marker=None, wait_timeout=60):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:18", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
    ])
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
            return False, log_text()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
        def send_text(txt):
            # Monitor sendkey occasionally doubles a key; retry once
            # if the shell reports the mistyped command as unknown.
            for _attempt in range(2):
                before = len(log_text())
                for ch in txt:
                    s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
                s.sendall(b"sendkey ret\n"); time.sleep(1)
                if "Unknown command" not in log_text()[before:]:
                    break
        for txt in actions:
            send_text(txt); time.sleep(1)
        if wait_marker:
            wait_for(lambda t: wait_marker in t, wait_timeout, wait_marker)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return True, log_text()

ok = True
_, log1 = boot(["pkg install calc.nxpkg", "pkg install term.nxpkg"],
               wait_marker="Installed term 1.0")
for m in ["Installed calc 1.0", "Installed term 1.0"]:
    f = m in log1; print(f"{'PASS' if f else 'FAIL'} install: {m}"); ok = ok and f

_, log2 = boot(["desktopappstest"], wait_marker="editor: opened refreshed.txt",
               wait_timeout=120)
for m in ["Desktop notification: Console started",
          "term: window opened",
          "Desktop: Packages opened",
          "packages: calc 1.0",
          "packages: term 1.0",
          "Desktop: Repo opened",
          "repo: index version 2",
          "repo: calc 1.0",
          "repo: term 1.0",
          "monitor: mem used ",
          "Desktop: Clock opened",
          "clock: time ",
          "clock: date ",
          "clock: uptime ",
          "editor: opened notes.txt",
          "editor: status 2 lines 41 bytes",
          "editor: new confirm 2 lines 41 bytes",
          "editor: new file",
          "editor: status 0 lines 0 bytes",
          "editor: saved fresh.txt 0 bytes",
          "editor: scroll 1",
          "editor: scroll btn 3",
          "editor: scroll btn 4",
          "viewer: opened pic.bmp 64x64",
          "files: scroll 1",
          "editor: opened filler1.txt",
          "editor: status 1 lines 17 bytes",
          "files: delete confirm filler1.txt",
          "files: deleted filler1.txt",
          "editor: opened filler2.txt",
          "files: renamed filler2.txt to renamed.txt",
          "editor: opened renamed.txt",
          "files: rename failed renamed.txt",
          "files: copy failed renamed.txt",
          "files: copied renamed.txt to copied.txt",
          "editor: opened copied.txt",
          "editor: saved refreshed.txt 0 bytes",
          "files: refreshed",
          "files: scroll 10",
          "editor: opened refreshed.txt"]:
    f = m in log2; print(f"{'PASS' if f else 'FAIL'} apps: {m}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log2; print(f"{'PASS' if f else 'FAIL'} apps: absent {bad}"); ok = ok and f
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
