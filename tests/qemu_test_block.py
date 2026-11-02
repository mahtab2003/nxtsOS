#!/usr/bin/env python3
"""Block-device layer (CORE_CLI.md section 15.1): the request
queue (ordering + adjacent-request merging, proven by sector
counters: merged vs unmerged), async completion (a queued
multi-sector read completes with correct data), PIO fallback
reporting, LBA48 capability reporting (honest per IDENTIFY:
yes or no, never invented), fsck on a good disk (clean) and
on a deliberately corrupted disk (orphan reported, nothing
changed), second-mount refusal, umount/swapon/swapoff
refusals with reasons, dedicated help entries, and a
filesystem write/read/delete round-trip through the new
layer. Two boots on the same disk; Boot 2's disk is corrupted
on the host (one free data sector's bitmap bit set) before
booting, and the test verifies after shutdown that the bit
is still set (fsck repaired nothing).

Usage: python3 tests/qemu_test_block.py <iso> <workdir>
Exit 0 only if all checks pass.
"""
import os, re, socket, struct, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5",
          "&": "shift-7", "|": "shift-backslash"}
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
            try: s.sendall(b"sendkey ret\n")
            except Exception: pass
            time.sleep(1)
            continue
        seg = log_text()[before:POS[0]]
        if f"{txt}\n" in seg:
            break
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
    return False

def corrupt_one_free_sector():
    """Set the bitmap bit of one free data sector; return
    (sector, file_offset) so the caller can verify it later."""
    with open(DISK, "r+b") as f:
        sb = f.read(512)
        magic, ver, total, bsec, dsec, dsecs, dstart, maxf = struct.unpack("<8s7I", sb[:36])
        assert magic == b"NXTSFS01", magic
        f.seek(512)
        bitmap = bytearray(f.read(bsec * 512))
        for sec in range(dstart, total):
            if not (bitmap[sec // 8] >> (sec % 8)) & 1:
                bitmap[sec // 8] |= (1 << (sec % 8))
                f.seek(512)
                f.write(bitmap)
                return sec, 512 + sec // 8, sec % 8
    raise SystemExit("no free data sector to corrupt")

# ---------------- Boot 1 ----------------
qemu, s = boot(DISK)
try:
    check(login(s, "admin", "pwadmin"), "login as admin")
    seg = sh(s, "blk", "admin")
    check(seg is not None and "Block device 0: present" in seg, "blk reports the device present")
    m = re.search(r"Block LBA48: (yes|no)", seg or "")
    check(m is not None, "blk reports LBA48 capability honestly (yes or no)")
    if m: print(f"NOTE: QEMU device LBA48 = {m.group(1)}")
    check(seg is not None and "Block DMA: PIO active" in seg, "blk reports PIO as the active path (DMA not faked)")
    check(seg is not None and "Block PIO fallback:" in seg, "blk reports the PIO fallback mechanism")
    check(seg is not None and "Block queue: capacity 16" in seg, "blk reports queue capacity 16")
    check(seg is not None and "Swap: defined, inactive" in seg, "blk reports swap defined but inactive")
    seg = sh(s, "blk merge", "admin")
    m = re.search(r"blk merge: requests 2, merged (\d+), commands (\d+), magic (\w+)", seg or "")
    check(m is not None and m.group(1) == "1" and m.group(2) == "1" and m.group(3) == "OK",
          "adjacent queue merge: 2 requests, merged 1, commands 1, magic OK")
    seg = sh(s, "blk two", "admin")
    m = re.search(r"blk merge: requests 2, merged (\d+), commands (\d+), magic (\w+)", seg or "")
    check(m is not None and m.group(1) == "0" and m.group(2) == "2" and m.group(3) == "OK",
          "non-adjacent queue: 2 requests, merged 0, commands 2 (merge contrast)")
    seg = sh(s, "blk async", "admin")
    check(seg is not None and "blk async: queued multi-sector read" in seg
          and "blk async: completed, magic OK" in seg,
          "async multi-sector read queues then completes with correct data")
    seg = sh(s, "fsck", "admin")
    import re as _re
    _m = _re.search(r"fsck: ([0-9]+) directory entries checked", seg or "")
    check(seg is not None and "fsck: superblock OK" in seg and "fsck: clean" in seg
          and _m is not None and int(_m.group(1)) >= 2,
          "fsck on a good disk reports clean with real entries checked")
    seg = sh(s, "mount", "admin")
    check(seg is not None and "/ on device 0 (nxtsFS, mounted)" in seg, "mount lists the one nxtsFS mount")
    seg = sh(s, "mount /dev/sdb", "admin")
    check(seg is not None and "second mount refused" in seg and "only one block device" in seg,
          "second mount refused with a reason")
    seg = sh(s, "umount /", "admin")
    check(seg is not None and "cannot unmount" in seg, "umount of the boot filesystem refused")
    seg = sh(s, "swapon", "admin")
    check(seg is not None and "swapon: refused" in seg and "demand paging" in seg,
          "swapon refused: swap defined but inactive until paging")
    seg = sh(s, "swapoff", "admin")
    check(seg is not None and "no swap area is active" in seg, "swapoff reports no active swap")
    seg = sh(s, "help blk", "admin")
    check(seg is not None and "blk (fs)" in seg and "Usage: blk [merge|two|async]" in seg,
          "help blk gives a dedicated entry")
    seg = sh(s, "help fsck", "admin")
    check(seg is not None and "fsck (fs)" in seg, "help fsck gives a dedicated entry")
    seg = sh(s, "help mount", "admin")
    check(seg is not None and "mount (fs)" in seg, "help mount gives a dedicated entry")
    seg = sh(s, "fs blk", "admin")
    check(seg is not None and "Block device 0: present" in seg, "group dispatch fs blk works")
    seg = sh(s, "write blkrt.txt roundtrip data", "admin")
    check(seg is not None and "Wrote blkrt.txt" in seg, "write through the block layer")
    seg = sh(s, "cat blkrt.txt", "admin")
    check(seg is not None and "roundtrip data" in seg, "read through the block layer returns the written data")
    seg = sh(s, "iostat", "admin")
    m = re.search(r"sectors written (\d+)", seg or "")
    check(m is not None and int(m.group(1)) > 0, "iostat shows sectors written through the queue")
    seg = sh(s, "rm blkrt.txt", "admin")
    seg = sh(s, "cat blkrt.txt", "admin")
    check(seg is not None and "cannot read" in seg, "deleted file no longer reads")
finally:
    stop(qemu, s)

# ---------------- Boot 2: corrupted disk ----------------
orphan_sec, orphan_off, orphan_bit = corrupt_one_free_sector()
print(f"NOTE: corrupted bitmap bit for data sector {orphan_sec}")
qemu, s = boot(DISK)
try:
    check(login(s, "admin", "pwadmin"), "Boot 2: login as admin")
    seg = sh(s, "fsck", "admin")
    check(seg is not None and "orphan sector" in seg, "Boot 2: fsck reports the orphan sector")
    check(seg is not None and "inconsistency(s) found" in seg and "no changes made" in seg,
          "Boot 2: fsck reports inconsistencies and no changes made")
    check(seg is not None and "fsck: clean" not in seg, "Boot 2: fsck does not call the corrupted disk clean")
    seg = sh(s, "cat root.txt", "admin")
    check(seg is not None and "block test root file" in seg, "Boot 2: files still read after the fsck scan")
finally:
    stop(qemu, s)

with open(DISK, "rb") as f:
    f.seek(orphan_off)
    still = (f.read(1)[0] >> orphan_bit) & 1
check(still == 1, "fsck changed nothing: the corrupted bitmap bit is still set after shutdown")
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
