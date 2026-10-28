#!/usr/bin/env python3
"""Phase 12 chunk: kernel `hostmatch` self-test.

Boots the guest (no network needed: the self-test calls the
real verify_host on fabricated leaf structs) and runs the
`hostmatch` shell command. PASS requires "hostmatch: 0
failures" + "hostmatch PASS" and no PANIC/EXCEPTION/page
fault. This is the wildcard verification that can run in
this sandbox: guest DNS over slirp UDP is blocked, so a
live wildcard-SAN handshake cannot run here (see
AUTONOMOUS.md); the end-to-end case awaits a peer-harness
TLS proxy test.

Usage: qemu_test_tls_hostmatch.py <iso> <workdir>
Exit 0 on PASS, 1 on FAIL. Always terminates QEMU.
"""
import os, socket, subprocess, sys, time

ISO, WORK = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)

def sh(args):
    subprocess.run(args, check=True, capture_output=True)

def main():
    with open(f"{WORK}/pub.txt", "w") as f:
        f.write("public data\n")
    sh(["python3", "tools/mkdisk.py", f"{WORK}/plain.img",
        "--add", f"public.txt:{WORK}/pub.txt"])
    serial = f"{WORK}/b1.log"
    mon = f"{WORK}/b1.mon"
    for p in (serial, mon):
        try: os.unlink(p)
        except FileNotFoundError: pass
    q = subprocess.Popen(["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d",
                          "-m", "128", "-display", "none",
                          "-serial", f"file:{serial}",
                          "-monitor", f"unix:{mon},server,nowait",
                          "-drive", f"file={WORK}/plain.img,format=raw,if=ide,index=0",
                          "-netdev", "user,id=n0", "-device", "e1000,netdev=n0"])
    try:
        for _ in range(100):
            if os.path.exists(mon): break
            time.sleep(0.1)
        for _ in range(600):
            try:
                if "nxts> " in open(serial, errors="replace").read(): break
            except FileNotFoundError: pass
            time.sleep(0.1)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(mon); s.settimeout(2)
        try: s.recv(4096)
        except socket.timeout: pass
        def sk(k):
            s.sendall(f"sendkey {k}\n".encode()); time.sleep(0.12)
        def cmd(c, w):
            for ch in c:
                sk({" ": "spc", ".": "dot", "/": "slash"}.get(ch, ch))
            sk("ret"); time.sleep(w)
        cmd("hostmatch", 10)
        s.close()
    finally:
        q.terminate(); q.wait(timeout=10)
    log = open(serial, errors="replace").read()
    ok = ("hostmatch: 0 failures" in log and "hostmatch PASS" in log
          and "PANIC" not in log and "EXCEPTION" not in log
          and "page fault" not in log)
    print(f"HOSTMATCH {'PASS' if ok else 'FAIL'}")
    if not ok:
        print(log[-2000:])
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
