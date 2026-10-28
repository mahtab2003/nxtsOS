"""Repo-window Fetch test: a desktop-only user must be able to
download a package file from the Repo window without installing it.
Single boot, one persistent disk, one HTTP server (slirp host
10.0.2.2). Boot: dhcp (NO shell pkg repo — the desktop Set is the
configuration), then desktoprepofetchtest — the kernel autotest mode
22 script: Start, launcher Repo row (Repo opens with no repository
set and no stored index), Fetch with no selection (refused), Set repo
with an empty field (refused), field click, type "10.0.2.2:18088",
Set repo (configures it), Update (fetches the 1-package index), row 0
select (sysinfo), Fetch (downloads sysinfo.nxpkg to disk), row 0
select again, Fetch again (refused: file already exists — the
negative control proving the first fetch really wrote the file),
Terminal icon (desktop exits). The harness then runs `ls` + `pkg
list` on the shell: ls must show sysinfo.nxpkg and pkg list must
still report no packages installed, proving fetch is not install.
The Update and Fetch downloads block the desktop loop, so the script
holds the release over a wide step range after each (Web test
pattern).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_repo_fetch.py <iso> <workdir>
<workdir> is created by tests/qemu_test_repo_fetch_setup.py.
The sender verifies the shell's echo of each command and
retypes once on mismatch (the QEMU sendkey-doubling flake
class from the repo test); login typing is not echoed.
"""
import os, shutil, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
SERVED = os.path.join(WORK, "served")
PORT = 18088
REPO = f"10.0.2.2:{PORT}"

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

if os.path.isdir(SERVED): shutil.rmtree(SERVED)
shutil.copytree(os.path.join(WORK, "repo_v1"), SERVED)
server = subprocess.Popen([sys.executable, "-m", "http.server", str(PORT),
                           "--bind", "127.0.0.1", "--directory", SERVED],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
ok = True
try:
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "vnc=:22", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
    ])
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        ok &= wait_for(lambda t: "root@nxts> " in t, 60, "shell prompt")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
        try: s.recv(4096)
        except socket.timeout: pass
        def send_text(txt):
            for _attempt in range(2):
                before = len(log_text())
                for ch in txt:
                    s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
                s.sendall(b"sendkey ret\n"); time.sleep(1)
                if "Unknown command" not in log_text()[before:]:
                    break
        send_text("dhcp"); time.sleep(1)
        send_text("desktoprepofetchtest")
        ok &= wait_for(lambda t: "desktoprepofetchtest returned" in t, 150, "desktoprepofetchtest returned")
        # Desktop has exited (Terminal icon); the shell prompt is back.
        time.sleep(4)
        send_text("ls"); time.sleep(1)
        send_text("pkg list"); time.sleep(2)
        s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
finally:
    server.terminate()
log = log_text()
for m in ["Desktop: Repo opened",
          "repo: fetch needs selection",
          "repo: set needs url",
          "Repository set to 10.0.2.2:18088",
          "repo: set 10.0.2.2:18088",
          "Repository index updated: 1 package(s), version 1",
          "repo: index version 1",
          "repo: sysinfo 1.0",
          "repo: selected sysinfo",
          "Fetched sysinfo 1.0",
          "repo: fetched sysinfo",
          "pkg fetch: file already exists (remove it first)",
          "repo: fetch failed sysinfo",
          "desktoprepofetchtest returned"]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} marker: {m}"); ok = ok and f
# Filesystem + registry proofs: the post-desktop `ls` output shows
# sysinfo.nxpkg (the file the desktop Fetch wrote — no desktop marker
# names the .nxpkg file, so only ls proves it), and the post-desktop
# `pkg list` still reports no packages installed, proving fetch did
# not install anything (position-checked: after the test's return
# line, so these are the post-desktop outputs, not earlier prints).
ret_pos = log.find("desktoprepofetchtest returned")
tail = log[ret_pos:] if ret_pos >= 0 else ""
f = "sysinfo.nxpkg" in tail
print(f"{'PASS' if f else 'FAIL'} ls after desktop: sysinfo.nxpkg"); ok = ok and f
f = "(no packages installed)" in tail
print(f"{'PASS' if f else 'FAIL'} pkg list after desktop: no packages installed"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} no {bad}"); ok = ok and f
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
