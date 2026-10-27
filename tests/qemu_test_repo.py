#!/usr/bin/env python3
"""Phase 11 repo test (3 boots, one persistent disk, one HTTP
server whose served directory is rewritten between boots).
Boot 1 (serves repo_v1): dhcp, pkg repo, pkg update (v1),
repo-install hello, fetch + local-install greet, both run.
Boot 2 (serves repo_v2): pkg update (v2), repo-install hello
upgrades 1.0 -> 1.1, hello runs as v1.1.
Boot 3 (serves repo_v1 again, then repo_v2, then
repo_tampered mid-boot): pkg update refuses the stale v1
index, pkg fetch hello (after re-serving v2, so the v2
file is actually available) still uses the stored v2
index (proves it survived the stale refusal), pkg
update refuses the tampered v2 index on signature
grounds, and a repo-install of badsig (wrong-key
package, correct index hash) is refused on signature
grounds. Note: fetching against the stale v1 server
with a v2 index correctly fails closed (v1 lacks the
v2 file, so the download is a 404 and the hash check
refuses it) — that is why v2 is re-served first.
Usage: python3 tests/qemu_test_repo.py <iso> <workdir>
<workdir> is created by tests/qemu_test_repo_setup.py.
Exit 0 only if all checks pass.
"""
import os, shutil, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
SERVED = os.path.join(WORK, "served")
PORT = 18082
REPO = f"10.0.2.2:{PORT}"

def serve(name):
    if os.path.isdir(SERVED): shutil.rmtree(SERVED)
    shutil.copytree(os.path.join(WORK, name), SERVED)
    time.sleep(0.5)

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus", ":": "shift-semicolon"}
def boot_and_run(actions, prompt="root@nxts> "):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "none", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={DISK},format=raw,if=ide,index=0",
        # Default user networking: guest 10.0.2.2 reaches the host
        # loopback (where the test HTTP server listens) already.
    ])
    ok = True
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        ok &= wait_for(lambda t: prompt in t, 60, "shell prompt")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
        try: s.recv(4096)
        except socket.timeout: pass
        def send_text(txt):
            # QEMU monitor sendkey occasionally delivers a key twice
            # (seen: "greet.nxppkg" for "greet.nxpkg"), which garbles
            # a command into a valid-looking but wrong one that the
            # old "Unknown command" retry could not catch. So verify
            # the shell's echo of the line: poll up to 15 s for the
            # exact "prompt + command" text. The echo appears when
            # the shell reads the line, before it executes, so a
            # slow previous command only delays the echo, it does
            # not fake it. If the echo is wrong or missing after a
            # new prompt (the garbled line already ran), retype
            # once: a doubled character never yields a different
            # valid package name or file in this test, so the
            # garbled run was a harmless no-op and the retry is
            # safe.
            def type_cmd(t):
                for ch in t:
                    s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
                s.sendall(b"sendkey ret\n"); time.sleep(1)
            before = len(log_text())
            type_cmd(txt)
            for _ in range(150):
                fresh = log_text()[before:]
                if f"{prompt}{txt}" in fresh: return
                if fresh.count(prompt) >= 1: break
                time.sleep(0.1)
            if f"{prompt}{txt}" not in log_text()[before:]:
                before2 = len(log_text())
                type_cmd(txt)
                for _ in range(150):
                    if f"{prompt}{txt}" in log_text()[before2:]: break
                    time.sleep(0.1)
        for act in actions:
            if isinstance(act, tuple) and act[0] == "serve":
                serve(act[1]); continue
            send_text(act); time.sleep(1)
        time.sleep(1); s.close()
    finally:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    return ok, log_text()

def check(log, marker, should, ok):
    found = marker in log
    good = found if should else not found
    print(f"{'PASS' if good else 'FAIL'}: {'found' if should else 'absent'} {marker}")
    return ok and good

serve("repo_v1")
server = subprocess.Popen([sys.executable, "-m", "http.server", str(PORT),
                           "--bind", "127.0.0.1", "--directory", SERVED],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
ok = True
try:
    ok, log1 = boot_and_run([
        "dhcp", f"pkg repo {REPO}", "pkg repo", "pkg update",
        "pkg install hello", "run hello.elf",
        "pkg fetch greet", "pkg install greet.nxpkg", "run greet.elf",
    ])
    print("--- boot 1 log ---"); print(log1)
    for m, s in [(f"Repository set to {REPO}", True), (f"Repository: {REPO}", True),
                 ("Repository index updated: 3 package(s), version 1", True),
                 ("Installed hello 1.0", True), ("Hello from ELF", True),
                 ("Fetched greet 1.0", True), ("Installed greet 1.0", True),
                 ("Greetings from greet", True)]:
        ok = check(log1, m, s, ok)
    serve("repo_v2")
    ok, log2 = boot_and_run(["dhcp", "pkg update", "pkg install hello", "run hello.elf"])
    print("--- boot 2 log ---"); print(log2)
    for m, s in [("Repository index updated: 3 package(s), version 2", True),
                 ("Upgraded hello to 1.1", True), ("Hello v1.1", True)]:
        ok = check(log2, m, s, ok)
    serve("repo_v1")
    ok, log3 = boot_and_run([
        "dhcp", "pkg update",
        ("serve", "repo_v2"), "pkg fetch hello",
        ("serve", "repo_tampered"), "pkg update", "pkg install badsig",
    ])
    print("--- boot 3 log ---"); print(log3)
    for m, s in [("stale index refused", True), ("Fetched hello 1.1", True),
                 ("index signature invalid", True), ("bad package signature", True)]:
        ok = check(log3, m, s, ok)
finally:
    server.terminate()
    try: server.wait(timeout=5)
    except subprocess.TimeoutExpired: server.kill()
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
