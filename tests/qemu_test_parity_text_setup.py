#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_parity_text.py.
Usage: python3 tests/qemu_test_parity_text_setup.py <workdir>
Creates text.img (all root-owned 644) with:
  fruits.txt, nums.txt, log.txt, words.txt, lines.txt,
  wide.txt (one 1200-byte line, spans the 1024-byte read
  window), over.txt (257 lines, over the sort/diff cap),
  da/db.txt (change hunks), adda/addb.txt (add hunk),
  dela/delb.txt (delete hunk), same/same2.txt (identical).
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

def w(name, data):
    with open(os.path.join(WORK, name), "wb") as f:
        f.write(data)

w("fruits.txt", b"banana\napple\nCherry\napple\n")
w("nums.txt", b"10\n2\n1\n")
w("log.txt", b"Error: disk full\nwarning: low mem\nERROR: timeout\ninfo: ok\n")
w("words.txt", b"hello world\nfoo bar baz\n")
w("lines.txt", b"l1\nl2\nl3\nl4\nl5\n")
w("wide.txt", b"a" * 1200 + b"\nsecond\n")
w("over.txt", b"".join(b"n%03d\n" % i for i in range(257)))
w("da.txt", b"a\nb\nc\nd\n")
w("db.txt", b"a\nX\nc\ne\n")
w("adda.txt", b"a\nb\n")
w("addb.txt", b"a\nb\nc\n")
w("dela.txt", b"a\nb\nc\n")
w("delb.txt", b"a\nc\n")
w("same.txt", b"x\ny\n")
w("same2.txt", b"x\ny\n")
args = ["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
        os.path.join(WORK, "text.img")]
for name in ("fruits.txt", "nums.txt", "log.txt", "words.txt", "lines.txt",
             "wide.txt", "over.txt", "da.txt", "db.txt", "adda.txt",
             "addb.txt", "dela.txt", "delb.txt", "same.txt", "same2.txt"):
    args += ["--add", f"{name}:{os.path.join(WORK, name)}:644:0"]
run(args)
print("parity_text test fixtures ready in", WORK)
