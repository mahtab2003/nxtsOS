#!/usr/bin/env python3
"""Phase 12 chunk 1: anchored TLS verification.

A local TLS 1.2 server presents a [leaf, intermediate] chain
(RSA suite, as the kernel speaks today). Three guest boots:
  1. disk carries tlsanchors.txt with the intermediate's modulus
     -> `httpsa` must succeed (anchor branch, not TOFU).
  2. disk carries tlsanchors.txt with a DIFFERENT modulus
     -> `httpsa` must print "certificate refused".
  3. server presents a single self-signed cert, disk carries no
     anchor file -> `httpsa` must print "certificate refused"
     (anchored mode never falls back to TOFU, even though the
     compiled-in WR1 anchor is present: the test cert is not WR1).
The guest reaches the host at 10.0.2.2 via slirp TCP proxying.

Usage: qemu_test_tls_anchor.py <iso> <workdir>
Exit 0 on PASS, 1 on FAIL. Always terminates QEMU.
Ports 18543 (chain) / 18544 (self-signed) avoid the cron suites'
fixed ports (8443, 18441-18444).
"""
import os, socket, subprocess, sys, time, ssl, threading

ISO, WORK = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)
BODY = b"NXTS-TLS-OK\n"

def sh(args):
    subprocess.run(args, check=True, capture_output=True)

def modhex(cert):
    out = subprocess.run(["openssl", "x509", "-in", cert, "-modulus", "-noout"],
                         check=True, capture_output=True, text=True).stdout
    return out.strip().split("=", 1)[1].strip()

def main():
    # Intermediate CA + leaf (SAN IP 10.0.2.2).
    sh(["openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", f"{WORK}/int-key.pem", "-out", f"{WORK}/int-cert.pem",
        "-days", "2", "-nodes", "-subj", "/CN=Test Anchor CA",
        "-addext", "basicConstraints=critical,CA:TRUE"])
    sh(["openssl", "req", "-newkey", "rsa:2048",
        "-keyout", f"{WORK}/leaf-key.pem", "-out", f"{WORK}/leaf.csr",
        "-nodes", "-subj", "/CN=10.0.2.2"])
    with open(f"{WORK}/leaf-ext.cnf", "w") as f:
        f.write("subjectAltName=IP:10.0.2.2\n")
    sh(["openssl", "x509", "-req", "-in", f"{WORK}/leaf.csr",
        "-CA", f"{WORK}/int-cert.pem", "-CAkey", f"{WORK}/int-key.pem",
        "-CAcreateserial", "-out", f"{WORK}/leaf-cert.pem", "-days", "2",
        "-extfile", f"{WORK}/leaf-ext.cnf"])
    with open(f"{WORK}/chain.pem", "w") as f:
        f.write(open(f"{WORK}/leaf-cert.pem").read())
        f.write(open(f"{WORK}/int-cert.pem").read())
    # Wrong anchor: an unrelated RSA key's modulus.
    sh(["openssl", "genrsa", "-out", f"{WORK}/wrong-key.pem", "2048"])
    sh(["openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", f"{WORK}/ss-key.pem", "-out", f"{WORK}/ss-cert.pem",
        "-days", "2", "-nodes", "-subj", "/CN=10.0.2.2",
        "-addext", "subjectAltName=IP:10.0.2.2",
        "-addext", "basicConstraints=critical,CA:TRUE"])
    with open(f"{WORK}/tlsanchors.txt", "w") as f:
        f.write(modhex(f"{WORK}/int-cert.pem") + "\n")
    wrong_mod = subprocess.run(["openssl", "rsa", "-in", f"{WORK}/wrong-key.pem",
                                "-modulus", "-noout"], check=True,
                               capture_output=True, text=True).stdout
    with open(f"{WORK}/wronganchors.txt", "w") as f:
        f.write(wrong_mod.strip().split("=", 1)[1].strip() + "\n")
    with open(f"{WORK}/pub.txt", "w") as f:
        f.write("public data\n")
    sh(["python3", "tools/mkdisk.py", f"{WORK}/good.img",
        "--add", f"tlsanchors.txt:{WORK}/tlsanchors.txt"])
    sh(["python3", "tools/mkdisk.py", f"{WORK}/wrong.img",
        "--add", f"tlsanchors.txt:{WORK}/wronganchors.txt"])
    sh(["python3", "tools/mkdisk.py", f"{WORK}/plain.img",
        "--add", f"public.txt:{WORK}/pub.txt"])

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("AES128-GCM-SHA256")
    ctx.load_cert_chain(f"{WORK}/chain.pem", f"{WORK}/leaf-key.pem")
    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx2.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx2.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx2.set_ciphers("AES128-GCM-SHA256")
    ctx2.load_cert_chain(f"{WORK}/ss-cert.pem", f"{WORK}/ss-key.pem")

    def serve(port, context):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(5)
        srv.settimeout(300)
        while True:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                return
            except Exception:
                return
            try:
                tls = context.wrap_socket(conn, server_side=True)
                tls.recv(4096)
                tls.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\n" + BODY)
                tls.close()
            except Exception:
                pass
    threading.Thread(target=serve, args=(18543, ctx), daemon=True).start()
    threading.Thread(target=serve, args=(18544, ctx2), daemon=True).start()

    def boot(disk, port, tag):
        serial = f"{WORK}/{tag}.log"
        mon = f"{WORK}/{tag}.mon"
        for p in (serial, mon):
            try: os.unlink(p)
            except FileNotFoundError: pass
        q = subprocess.Popen(["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d",
                              "-m", "128", "-display", "none",
                              "-serial", f"file:{serial}",
                              "-monitor", f"unix:{mon},server,nowait",
                              "-drive", f"file={disk},format=raw,if=ide,index=0",
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
            cmd(f"httpsa 10.0.2.2 / {port}", 40)
            s.close()
        finally:
            q.terminate(); q.wait(timeout=10)
        return open(serial, errors="replace").read()

    log1 = boot(f"{WORK}/good.img", 18543, "b1")
    log2 = boot(f"{WORK}/wrong.img", 18543, "b2")
    log3 = boot(f"{WORK}/plain.img", 18544, "b3")
    ok1 = ("httpsa: 12 bytes" in log1 and "NXTS-TLS-OK" in log1
           and "certificate refused" not in log1
           and "PANIC" not in log1 and "EXCEPTION" not in log1)
    ok2 = "certificate refused" in log2
    ok3 = "certificate refused" in log3
    print(f"TLS ANCHOR boot1(right anchor)={'PASS' if ok1 else 'FAIL'} "
          f"boot2(wrong anchor)={'PASS' if ok2 else 'FAIL'} "
          f"boot3(self-signed, no anchor)={'PASS' if ok3 else 'FAIL'}")
    if not (ok1 and ok2 and ok3):
        for name, log in (("b1", log1), ("b2", log2), ("b3", log3)):
            i = log.find("httpsa 10.0.2.2")
            print(f"--- {name} ---")
            print(log[i - 100:] if i >= 0 else log[-1200:])
    print("RESULT:", "PASS" if (ok1 and ok2 and ok3) else "FAIL")
    return 0 if (ok1 and ok2 and ok3) else 1

if __name__ == "__main__":
    sys.exit(main())
