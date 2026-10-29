#!/usr/bin/env python3
"""Shell `cp` test: the sector-by-sector fs_copy_as primitive must
copy a file byte-exactly (same content, new name, source untouched),
including a binary file no cat/write roundtrip could reproduce, and
must refuse a missing source, an existing destination (never
overwrites), and a copy onto itself.
Single boot, one persistent disk, no network.
Boot: ls, cp alpha.txt beta.txt, cat beta.txt (original content),
sha256 alpha.txt + sha256 beta.txt (hashes must match), cp
missing.txt new.txt (refused), cp beta.txt keep.txt (refused),
cp beta.txt beta.txt (refused), cp bin.dat bin2.dat, sha256
bin.dat + sha256 bin2.dat (hashes must match — the binary proof),
ls (alpha.txt still present, beta.txt 14 bytes, bin2.dat 256 bytes).
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_cp.py <iso> <workdir>
<workdir> is created by tests/qemu_test_cp_setup.py.
The sender verifies the shell's echo of each command and
retypes once on mismatch (the QEMU sendkey-doubling flake
class from the repo test); login typing is not echoed.
A doubled successful cp prints a "cannot copy" refusal for the
second run (destination now exists) — the test asserts the
"Copied" marker, never the absence of that refusal.
"""
import os, re, socket, subprocess, sys, time
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
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus", ":": "shift-semicolon"}

ok = True
for p in (SERIAL, MON):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "none", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    prompt = "root@nxts> "
    ok &= wait_for(lambda t: prompt in t, 60, "shell prompt")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    def send_text(txt):
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
    for act in ["ls", "cp alpha.txt beta.txt", "cat beta.txt",
                "sha256 alpha.txt", "sha256 beta.txt",
                "cp missing.txt new.txt", "cp beta.txt keep.txt",
                "cp beta.txt beta.txt", "cp bin.dat bin2.dat",
                "sha256 bin.dat", "sha256 bin2.dat"]:
        send_text(act); time.sleep(1)
    before_final_ls = len(log_text())
    send_text("ls"); time.sleep(1)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()
log = log_text()
print("--- boot log ---"); print(log)
def check(marker, should):
    global ok
    found = marker in log
    good = found if should else not found
    print(f"{'PASS' if good else 'FAIL'}: {'found' if should else 'absent'} {marker}")
    ok = ok and good
for m in ["Copied alpha.txt to beta.txt",
          "alpha content",
          "cp: cannot copy missing.txt to new.txt",
          "cp: cannot copy beta.txt to keep.txt",
          "cp: cannot copy beta.txt to beta.txt",
          "Copied bin.dat to bin2.dat"]:
    check(m, True)
hashes = {}
for line in log.splitlines():
    m = re.match(r"^([0-9a-f]{64})  (\S+)$", line)
    if m and m.group(2) not in hashes:
        hashes[m.group(2)] = m.group(1)
for a, b in [("alpha.txt", "beta.txt"), ("bin.dat", "bin2.dat")]:
    good = a in hashes and hashes.get(a) == hashes.get(b)
    print(f"{'PASS' if good else 'FAIL'}: sha256 {a} == sha256 {b} ({hashes.get(a)} vs {hashes.get(b)})")
    ok = ok and good
final_ls = log[before_final_ls:]
for m in ["alpha.txt"]:
    found = m in final_ls
    print(f"{'PASS' if found else 'FAIL'}: final ls shows {m}")
    ok = ok and found
# List-view format (Work D, v1.1.3): ls pads the name column to 24,
# so "beta.txt" is followed by 16 spaces, not 2 as in the old
# "%s  %u bytes" format. Match name + one-or-more spaces + size:
# same assertion (row present with the right size), valid on both
# formats. The old exact-2-space substrings failed on the new
# layout even though the rows were present and correct (cp itself
# is proven by the Copied markers + identical sha256 hashes above).
for pat, desc in [(r"beta\.txt +14 bytes", "beta.txt 14 bytes"),
                  (r"bin2\.dat +256 bytes", "bin2.dat 256 bytes")]:
    found = re.search(pat, final_ls) is not None
    print(f"{'PASS' if found else 'FAIL'}: final ls shows {desc}")
    ok = ok and found
for m in ["EXCEPTION", "PANIC", "page fault"]:
    check(m, False)
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
