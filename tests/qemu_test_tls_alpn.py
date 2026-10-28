#!/usr/bin/env python3
"""Phase 12 chunk: ALPN negotiation over a real handshake.

A local TLS 1.2 server (ECDHE-RSA-AES128-GCM-SHA256, the
kernel's ECDHE path) offers ALPN ["http/1.1"]. The guest
runs `https 10.0.2.2 / 18549` over slirp (TCP works here;
only guest DNS over slirp UDP is blocked). PASS requires
the body NXTS-TLS-OK plus the server-side record
selected_alpn_protocol() == "http/1.1", proving the
ClientHello ALPN extension was sent, parsed, and
selected — and that the ClientHello change did not
regress the handshake. No PANIC/EXCEPTION/page fault.
Port 18549 avoids the cron suites' fixed ports
(8443, 18441-18444, 18543-18548).

Usage: qemu_test_tls_alpn.py <iso> <workdir>
Exit 0 on PASS, 1 on FAIL. Always terminates QEMU.
"""
import os, socket, subprocess, sys, threading, time, ssl

ISO, WORK = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)
BODY = b"NXTS-TLS-OK\n"
ALPN = {}

def sh(args):
    subprocess.run(args, check=True, capture_output=True)

def main():
    sh(["openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", f"{WORK}/ss-key.pem", "-out", f"{WORK}/ss-cert.pem",
        "-days", "2", "-nodes", "-subj", "/CN=10.0.2.2",
        "-addext", "subjectAltName=IP:10.0.2.2",
        "-addext", "basicConstraints=critical,CA:TRUE"])
    with open(f"{WORK}/pub.txt", "w") as f:
        f.write("public data\n")
    sh(["python3", "tools/mkdisk.py", f"{WORK}/plain.img",
        "--add", f"public.txt:{WORK}/pub.txt"])

    def serve():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.load_cert_chain(f"{WORK}/ss-cert.pem", f"{WORK}/ss-key.pem")
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 18549))
        srv.listen(5)
        srv.settimeout(300)
        while True:
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                return
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                ALPN["sel"] = tls.selected_alpn_protocol()
                tls.recv(4096)
                tls.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\n" + BODY)
                tls.close()
            except Exception:
                pass
    threading.Thread(target=serve, daemon=True).start()

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
        cmd("dhcp", 8)
        cmd("https 10.0.2.2 / 18549", 40)
        s.close()
    finally:
        q.terminate(); q.wait(timeout=10)
    log = open(serial, errors="replace").read()
    ok = ("https: 12 bytes" in log and "NXTS-TLS-OK" in log
          and ALPN.get("sel") == "http/1.1"
          and "PANIC" not in log and "EXCEPTION" not in log
          and "page fault" not in log)
    print(f"ALPN body={'PASS' if 'NXTS-TLS-OK' in log else 'FAIL'} "
          f"selected={ALPN.get('sel')!r} {'PASS' if ALPN.get('sel') == 'http/1.1' else 'FAIL'}")
    if not ok:
        print(log[-2000:])
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
