#!/usr/bin/env python3
"""Phase 9.2: guest TLS 1.2 client against a real TLS server.

Starts a python ssl server on the host (TLS 1.2 only, cipher
TLS_RSA_WITH_AES_128_GCM_SHA256, self-signed RSA-2048 cert with
SAN IP 10.0.2.2 and basicConstraints CA:TRUE, validity covering
today), boots the guest under QEMU slirp, runs `dhcp` then
`https 10.0.2.2 / 8443`, and asserts the known body comes back.
The guest reaches the host at 10.0.2.2 via slirp TCP proxying
(proven to work; slirp UDP/DNS is environment-blocked and is
not used here).

Usage: qemu_test_tls.py <iso> <ram_mb> <serial_log> <mon_sock>
Exit 0 on PASS, 1 on FAIL. Always terminates QEMU.
"""
import os, socket, subprocess, sys, time, ssl, threading

ISO, RAM, SERIAL, MON = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
WORK = os.path.dirname(os.path.abspath(SERIAL))
CERT = os.path.join(WORK, "tls-cert.pem")
KEY = os.path.join(WORK, "tls-key.pem")
BODY = b"NXTS-TLS-OK\n"

def main():
    # Self-signed cert: SAN IP 10.0.2.2 (the address the guest
    # connects to), CA:TRUE (the guest's TOFU root policy
    # requires the single self-signed cert to be a CA).
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", KEY, "-out", CERT, "-days", "2", "-nodes",
                    "-subj", "/CN=10.0.2.2",
                    "-addext", "subjectAltName=IP:10.0.2.2",
                    "-addext", "basicConstraints=critical,CA:TRUE"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("AES128-GCM-SHA256")
    ctx.load_cert_chain(CERT, KEY)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 8443))
    srv.listen(5)
    srv.settimeout(120)
    def serve():
        try:
            conn, _ = srv.accept()
            tls = ctx.wrap_socket(conn, server_side=True)
            tls.recv(4096)
            tls.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\n" + BODY)
            tls.close()
        except Exception:
            pass
    threading.Thread(target=serve, daemon=True).start()

    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    q = subprocess.Popen(["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d",
                          "-m", RAM, "-display", "none",
                          "-serial", f"file:{SERIAL}",
                          "-monitor", f"unix:{MON},server,nowait",
                          "-netdev", "user,id=n0", "-device", "e1000,netdev=n0"])
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        for _ in range(600):
            try:
                if "nxts> " in open(SERIAL, errors="replace").read(): break
            except FileNotFoundError: pass
            time.sleep(0.1)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(MON); s.settimeout(2)
        try: s.recv(4096)
        except socket.timeout: pass
        def sk(k):
            s.sendall(f"sendkey {k}\n".encode()); time.sleep(0.12)
        def cmd(c, w):
            for ch in c:
                sk({" ": "spc", ".": "dot", "/": "slash"}.get(ch, ch))
            sk("ret"); time.sleep(w)
        cmd("dhcp", 8)
        cmd("https 10.0.2.2 / 8443", 40)
        s.close()
    finally:
        q.terminate(); q.wait(timeout=10)
    log = open(SERIAL, errors="replace").read()
    ok = ("net: DHCP ok ip=10.0.2.15" in log and
          "https: 12 bytes" in log and "NXTS-TLS-OK" in log and
          "certificate refused" not in log)
    print("TLS TEST", "PASS" if ok else "FAIL")
    if not ok:
        i = log.find("https 10.0.2.2")
        print(log[i - 100:] if i >= 0 else log[-1500:])
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
