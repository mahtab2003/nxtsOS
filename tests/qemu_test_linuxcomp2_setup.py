#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_linuxcomp2.py.
Usage: python3 tests/qemu_test_linuxcomp2_setup.py <workdir>
Creates disk.img (all root-owned 644, setup-mode boot: no
users.txt) with:
  words.txt (sed/tr/cut/uniq/grep fixtures),
  pairs.txt (cut -d : fixture),
  dup.txt (uniq fixture),
  demo.sh (script: comments, if, for, while, chaining),
  g1.txt, g2.txt, other.log (glob fixtures),
  page.txt (25 lines, for more).
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

w("words.txt", b"foo bar\nhello world\nfoo baz\n")
w("pairs.txt", b"a:1:x\nb:2:y\nc:3:z\n")
w("dup.txt", b"one\none\ntwo\ntwo\ntwo\nthree\n")
w("demo.sh", b"# demo script\n"
             b"echo start\n"
             b"if true\n"
             b"echo if-yes\n"
             b"else\n"
             b"echo if-no\n"
             b"endif\n"
             b"if false\n"
             b"echo never\n"
             b"endif\n"
             b"for v in a b c\n"
             b"echo loop-$v\n"
             b"endfor\n"
             b"export word=hello\n"
             b"echo var-$word\n"
             b"write flag yes\n"
             b"while test -f flag\n"
             b"echo loop-once\n"
             b"rm flag\n"
             b"endwhile\n"
             b"echo done\n")
w("g1.txt", b"glob one\n")
w("g2.txt", b"glob two\n")
w("other.log", b"not a txt file\n")
w("page.txt", b"".join(b"line%02d\n" % i for i in range(1, 26)))
args = ["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
        os.path.join(WORK, "disk.img")]
for name in ("words.txt", "pairs.txt", "dup.txt", "demo.sh", "g1.txt",
             "g2.txt", "other.log", "page.txt"):
    args += ["--add", f"{name}:{os.path.join(WORK, name)}:644:0"]
run(args)
print("linuxcomp2 test fixtures ready in", WORK)
