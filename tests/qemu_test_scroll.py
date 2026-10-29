#!/usr/bin/env python3
"""Work D test: terminal scrollback + list views + echo/ver.
Boot (no login, setup mode) with a disk carrying spin.elf:
runbg spin.elf, jobs (header + row + footer), ls (header + row +
footer), pkg list (zero case preserved), echo a full 80-W row,
help x2 (scrolls the W row off the live screen), sendkey pgup
(screendump must contain a row whose white-pixel count equals
80 x the 'W' glyph bit count from font_data.h), sendkey pgdn
(screendump must NOT contain such a row: live view restored).
ver + help text checks run on the serial log.
Usage: python3 tests/qemu_test_scroll.py <iso> <workdir>
Exit 0 only if all checks pass."""
import os, re, socket, subprocess, sys, time
ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
PPM1 = os.path.join(WORK, "scroll-pgup.ppm")
PPM2 = os.path.join(WORK, "scroll-live.ppm")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus"}

def sendkey_name(ch):
    # QEMU sendkey rejects bare capitals: uppercase needs shift-.
    if ch.isupper(): return f"shift-{ch.lower()}"
    return KEYMAP.get(ch, ch)

def glyph_bits(ch):
    text = open(os.path.join(ROOT, "kernel", "font_data.h")).read()
    glyphs = re.findall(r"\{((?:0x[0-9a-f]+,?)+)\}", text)
    assert len(glyphs) == 256, f"font glyphs: {len(glyphs)}"
    row = [int(x, 16) for x in glyphs[ord(ch)].split(",")]
    return sum(bin(b).count("1") for b in row)

# Build spin.elf (yield-forever job, prints nothing) + disk, as in
# the webpanic desktop test.
os.makedirs(WORK, exist_ok=True)
r = subprocess.run(["gcc", "-m32", "-ffreestanding", "-nostdlib", "-fno-pic",
                    "-I", os.path.join(ROOT, "userland"),
                    "-c", os.path.join(ROOT, "tests", "spin.c"),
                    "-o", os.path.join(WORK, "spin.o")],
                   capture_output=True, text=True)
assert r.returncode == 0, r.stderr
r = subprocess.run(["ld", "-m", "elf_i386", "-T", os.path.join(ROOT, "userland", "linker.ld"),
                    os.path.join(ROOT, "build", "user_start.o"), os.path.join(WORK, "spin.o"),
                    "-o", os.path.join(WORK, "spin.elf")],
                   capture_output=True, text=True)
assert r.returncode == 0, r.stderr
r = subprocess.run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
                    DISK, "--add", f"spin.elf:{os.path.join(WORK, 'spin.elf')}"],
                   capture_output=True, text=True)
assert r.returncode == 0, r.stderr

for p in (SERIAL, MON):
    try: os.unlink(p)
    except FileNotFoundError: pass
qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "vnc=:20", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-drive", f"file={DISK},format=raw,if=ide,index=0",
])
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    if not wait_for(lambda t: "root@nxts> " in t, 60, "prompt"):
        print("RESULT: FAIL"); sys.exit(1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(MON); s.recv(4096)
    def send_text(txt):
        for ch in txt:
            s.sendall(f"sendkey {sendkey_name(ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(0.5)
    def send_key(name):
        s.sendall(f"sendkey {name}\n".encode()); time.sleep(1)
    def screendump(path):
        time.sleep(1)
        s.sendall(f"screendump {path}\n".encode()); time.sleep(1)
    send_text("runbg spin.elf"); time.sleep(1)
    send_text("jobs"); time.sleep(1)
    send_text("ls"); time.sleep(1)
    send_text("pkg list"); time.sleep(1)
    send_text("ver"); time.sleep(1)
    send_text("echo " + "W" * 80); time.sleep(1)
    send_text("help"); time.sleep(1)
    send_text("help"); time.sleep(1)
    send_text("kill 10"); time.sleep(1)
    send_key("pgup")
    screendump(PPM1)
    send_key("pgdn")
    screendump(PPM2)
    s.close()
finally:
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

ok = True
log = log_text()
for m in ["PID  NAME  UID", "pid 10  spin.elf  uid 0", "(1 background job(s))",
          "NAME                    SIZE  UID  MODE", "spin.elf",
          "(1 files)", "(no packages installed)", "nxtsOS v1.1.3",
          "Command groups: system, session, fs, proc, pkg, net, crypto, diag, gui, test", "W" * 80]:
    f = m in log; print(f"{'PASS' if f else 'FAIL'} serial: {m[:48]}"); ok = ok and f
for bad in ["EXCEPTION", "PANIC", "page fault"]:
    f = bad not in log; print(f"{'PASS' if f else 'FAIL'} serial: absent {bad}"); ok = ok and f

def row_white_counts(path):
    from PIL import Image
    im = Image.open(path); px = im.load()
    counts = []
    for r in range(25):
        n = 0
        for yy in range(r * 16, r * 16 + 16):
            for xx in range(800):
                if px[xx, yy][:3] == (255, 255, 255): n += 1
        counts.append(n)
    return counts

try:
    want = 80 * glyph_bits("W")
    print(f"W-row white pixels expected: {want}")
    c1 = row_white_counts(PPM1)
    f = want in c1; print(f"{'PASS' if f else 'FAIL'} pgup: W row present in history view (rows={c1})"); ok = ok and f
    c2 = row_white_counts(PPM2)
    f = want not in c2; print(f"{'PASS' if f else 'FAIL'} pgdn: W row absent in live view (rows={c2})"); ok = ok and f
except Exception as e:
    print("FAIL screendump analysis:", e); ok = False
print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
