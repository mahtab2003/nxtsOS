#!/usr/bin/env python3
"""Phase 9.3 adversarial network test (host-side, third-party style).

Phase A (socket peer harness, deterministic, no internet):
  A1. ARP/garbage flood: 300 frames (ARP requests, truncated
      frames, bad ethertypes, bad IP checksums, UDP to random
      ports) at the guest. Afterwards the guest must still
      answer a ping and print netinfo (RX ring not wedged).
  A2. Malformed DNS pointer: the peer answers a DNS query
      with an answer NAME that is a compression pointer to
      offset 255, past the end of the packet (0xC0 0xFF).
      The guest lookup must fail cleanly ("dns: lookup
      failed") and the shell must stay alive (netinfo
      afterwards). (A pointer loop to a valid offset cannot
      hang this parser: it only skips names and never follows
      pointers, so there is no loop to break — the bounds
      check is the real validation, and it is what is tested.)

Phase B (slirp + real TLS servers on the host):
  B1. Wrong-host cert (SAN IP 10.0.2.99, guest connects to
      10.0.2.2) -> "certificate refused".
  B2. Plain-HTTP server on the TLS port -> "https: failed"
      (handshake failure, NOT a certificate refusal).
  B3. Tampered-signature cert (one signature byte flipped)
      -> "certificate refused".
  B4. Expired cert (2020-2021 validity) -> "certificate refused".

Usage: security_test_net.py <iso> <workdir>
Exit 0 only if every check passes. Always terminates QEMU.
"""
import os, socket, struct, subprocess, sys, threading, time, ssl

ISO, WORK = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)

# ---------- shared helpers ----------
def csum(data):
    if len(data) % 2: data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def ip_pkt(dst_ip, src_ip, proto, payload):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload),
                      0x1234, 0, 64, proto, 0, src_ip, dst_ip)
    hdr = hdr[:10] + struct.pack(">H", csum(hdr)) + hdr[12:]
    return hdr + payload

def udp_pkt(dst_ip, src_ip, dport, sport, payload):
    seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ip_pkt(dst_ip, src_ip, 17, seg)

def eth(dst_mac, src_mac, etype, payload):
    return dst_mac + src_mac + struct.pack(">H", etype) + payload

def tcp_pkt(dst_ip, src_ip, dport, sport, seq, ack, flags, payload=b"", mss=False):
    hlen = 24 if mss else 20
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack,
                      (hlen // 4) << 4, flags, 4096, 0, 0)
    if mss: hdr += struct.pack(">BBH", 2, 4, 1460)
    pseudo = src_ip + dst_ip + struct.pack(">BBH", 0, 6, hlen + len(payload))
    chk = csum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack(">H", chk) + hdr[18:]
    return ip_pkt(dst_ip, src_ip, 6, hdr + payload)

PEER_MAC = bytes([0x52, 0x55, 0x0A, 0x00, 0x63, 0x01])
PEER_IP = bytes([192, 168, 99, 1])
GUEST_IP = bytes([192, 168, 99, 10])
NETMASK = bytes([255, 255, 255, 0])

class Peer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        deadline = time.time() + 15
        while True:
            try:
                self.sock.connect(("127.0.0.1", 12345)); break
            except OSError:
                if time.time() > deadline: raise
                time.sleep(0.2)
        self.sock.settimeout(0.5)
        self.rxbuf = b""
        self.guest_mac = None
        self.running = True
        self.dns_mode = "normal"  # or "loop"

    def send(self, frame):
        self.sock.sendall(struct.pack(">I", len(frame)) + frame)

    def recv_frame(self):
        while len(self.rxbuf) < 4:
            try: chunk = self.sock.recv(4096)
            except socket.timeout: return None
            if not chunk: return None
            self.rxbuf += chunk
        n = struct.unpack(">I", self.rxbuf[:4])[0]
        if n > 65536: raise ValueError(f"bad frame length {n}")
        while len(self.rxbuf) < 4 + n:
            try: chunk = self.sock.recv(4096)
            except socket.timeout: return None
            if not chunk: return None
            self.rxbuf += chunk
        frame = self.rxbuf[4:4 + n]
        self.rxbuf = self.rxbuf[4 + n:]
        return frame

    def dhcp_reply(self, req, mtype):
        xid = req[4:8]; chaddr = req[28:34]
        pkt = bytearray(300)
        pkt[0] = 2; pkt[1] = 1; pkt[2] = 6
        pkt[4:8] = xid
        pkt[16:20] = GUEST_IP
        pkt[20:24] = PEER_IP
        pkt[28:34] = chaddr
        pkt[236:240] = bytes([99, 130, 83, 99])
        opt = bytes([53, 1, mtype, 54, 4]) + PEER_IP
        opt += bytes([1, 4]) + NETMASK
        opt += bytes([3, 4]) + PEER_IP
        opt += bytes([6, 4]) + PEER_IP
        opt += bytes([51, 4, 0, 0, 0x0E, 0x10, 255])
        pkt[240:240 + len(opt)] = opt
        udp = udp_pkt(GUEST_IP, PEER_IP, 68, 67, bytes(pkt[:240 + len(opt)]))
        self.send(eth(chaddr, PEER_MAC, 0x0800, udp))

    def dns_reply(self, req_ip, req_udp, guest_mac):
        data = req_udp[8:]
        qid = data[:2]
        pos = 12
        while pos < len(data) and data[pos] != 0:
            pos += 1 + data[pos]
        pos += 1 + 4
        question = data[12:pos]
        sport = struct.unpack(">H", req_udp[0:2])[0]
        if self.dns_mode == "loop":
            # Answer NAME is a compression pointer to offset
            # 255, past the end of this ~50-byte packet. The
            # guest must reject the malformed pointer.
            resp = struct.pack(">HHHHHH", struct.unpack(">H", qid)[0],
                               0x8180, 1, 1, 0, 0) + question
            resp += bytes([0xC0, 0xFF])
            # NAME already emitted (the pointer); remaining
            # fields are TYPE, CLASS, TTL, RDLEN.
            resp += struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
        else:
            resp = struct.pack(">HHHHHH", struct.unpack(">H", qid)[0],
                               0x8180, 1, 1, 0, 0) + question
            resp += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + bytes([93, 184, 216, 34])
        udp = udp_pkt(req_ip, PEER_IP, sport, 53, resp)
        self.send(eth(guest_mac, PEER_MAC, 0x0800, udp))

    def run(self):
        while self.running:
            try: frame = self.recv_frame()
            except (OSError, ValueError): return
            if frame is None: continue
            if len(frame) < 14: continue
            etype = struct.unpack(">H", frame[12:14])[0]
            src_mac = frame[6:12]
            if self.guest_mac is None and src_mac != PEER_MAC:
                self.guest_mac = src_mac
            if etype == 0x0806 and len(frame) >= 42:
                arp = frame[14:]
                op = struct.unpack(">H", arp[6:8])[0]
                target = arp[24:28]
                if op == 1 and target == PEER_IP:
                    reply = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2)
                    reply += PEER_MAC + PEER_IP + src_mac + arp[14:18]
                    self.send(eth(src_mac, PEER_MAC, 0x0806, reply))
                continue
            if etype != 0x0800 or len(frame) < 34: continue
            ip = frame[14:]
            proto = ip[9]
            src_ip = ip[12:16]
            if proto == 1 and len(ip) >= 28:
                icmp = ip[20:]
                if icmp[0] == 8:
                    reply_icmp = bytes([0, 0, 0, 0]) + icmp[4:]
                    reply_icmp = reply_icmp[:2] + struct.pack(">H", csum(reply_icmp)) + reply_icmp[4:]
                    pkt = ip_pkt(src_ip, PEER_IP, 1, reply_icmp)
                    self.send(eth(src_mac, PEER_MAC, 0x0800, pkt))
                continue
            if proto == 17 and len(ip) >= 28:
                udp = ip[20:]
                sport, dport = struct.unpack(">HH", udp[0:4])
                payload = udp[8:]
                if dport == 67 and len(payload) >= 240:
                    mtype = None; pos = 240
                    while pos < len(payload):
                        code = payload[pos]
                        if code == 255: break
                        if code == 0: pos += 1; continue
                        if pos + 1 >= len(payload): break
                        ln = payload[pos + 1]
                        if code == 53 and ln == 1: mtype = payload[pos + 2]
                        pos += 2 + ln
                    if mtype == 1: self.dhcp_reply(payload, 2)
                    elif mtype == 3: self.dhcp_reply(payload, 5)
                elif dport == 53:
                    self.dns_reply(src_ip, udp, src_mac)
                continue

def boot_qemu(serial, mon, netdev_args):
    for p in (serial, mon):
        try: os.unlink(p)
        except FileNotFoundError: pass
    q = subprocess.Popen(["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d",
                          "-m", "128", "-display", "none",
                          "-serial", f"file:{serial}",
                          "-monitor", f"unix:{mon},server,nowait"] + netdev_args)
    return q

def wait_prompt(serial):
    for _ in range(600):
        try:
            if "nxts> " in open(serial, errors="replace").read(): return True
        except FileNotFoundError: pass
        time.sleep(0.1)
    return False

def mon_connect(mon):
    for _ in range(100):
        if os.path.exists(mon): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(mon); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    return s

KEYMAP = {".": "dot", "/": "slash", " ": "spc", "-": "minus"}
def type_cmd(s, cmd, wait):
    for ch in cmd:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.12)
    s.sendall(b"sendkey ret\n"); time.sleep(wait)

results = {}
def check(name, cond, detail=""):
    results[name] = bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}: {name} {detail}")

# ---------- Phase A ----------
print("=== Phase A: peer harness ===")
A_SERIAL = os.path.join(WORK, "a-serial.log")
A_MON = os.path.join(WORK, "a-mon.sock")
qa = boot_qemu(A_SERIAL, A_MON, ["-netdev", "socket,id=n0,listen=127.0.0.1:12345",
                                 "-device", "e1000,netdev=n0"])
peer = Peer()
threading.Thread(target=peer.run, daemon=True).start()
try:
    assert wait_prompt(A_SERIAL), "guest did not reach prompt"
    sa = mon_connect(A_MON)
    type_cmd(sa, "dhcp", 8)
    # A1: flood 300 hostile frames at the guest MAC.
    gm = peer.guest_mac
    assert gm is not None, "guest MAC unknown"
    for i in range(100):
        arp_req = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)
        arp_req += PEER_MAC + PEER_IP + gm + GUEST_IP
        peer.send(eth(gm, PEER_MAC, 0x0806, arp_req))
        peer.send(eth(gm, PEER_MAC, 0x0800, bytes([i % 256] * 20)))  # garbage IP
        peer.send(eth(gm, PEER_MAC, 0x88B5, bytes([0xAA] * 60)))  # unknown ethertype
        # Bad-checksum UDP to a random port.
        bad = ip_pkt(GUEST_IP, PEER_IP, 17, struct.pack(">HHHH", 1234, 9999, 12, 0) + b"junk")
        bad = bad[:24] + b"\x00\x00" + bad[26:]
        peer.send(eth(gm, PEER_MAC, 0x0800, bad))
    time.sleep(3)
    # Ping up to 3 times: a single frame can be lost to ring
    # overflow during a 400-frame flood; a wedged stack would
    # never answer, a live one answers on retry.
    for _ in range(3):
        type_cmd(sa, "ping 192.168.99.1", 6)
        if "ping: reply received" in open(A_SERIAL, errors="replace").read():
            break
    type_cmd(sa, "netinfo", 3)
    # A2: DNS pointer loop.
    peer.dns_mode = "loop"
    time.sleep(0.5)
    type_cmd(sa, "dns example.com", 8)
    type_cmd(sa, "netinfo", 3)
    sa.close()
finally:
    peer.running = False
    qa.terminate(); qa.wait(timeout=10)
log_a = open(A_SERIAL, errors="replace").read()
check("A1 flood: ping still replies", "ping: reply received" in log_a)
check("A1 flood: netinfo still works", "MAC" in log_a)
check("A2 DNS loop: lookup fails cleanly", "dns: lookup failed" in log_a)
check("A2 DNS loop: shell alive after", log_a.count("nxts> ") >= 5)

# ---------- Phase B ----------
print("=== Phase B: slirp TLS negatives ===")
B_SERIAL = os.path.join(WORK, "b-serial.log")
B_MON = os.path.join(WORK, "b-mon.sock")
# Certs: valid (SAN 10.0.2.2), wrong-host (SAN 10.0.2.99),
# tampered (valid cert, last signature byte flipped), expired.
def mkcert(cert, key, san, days=None, extra=None):
    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", key, "-out", cert, "-nodes",
           "-subj", "/CN=10.0.2.2",
           "-addext", f"subjectAltName=IP:{san}",
           "-addext", "basicConstraints=critical,CA:TRUE"]
    if days: cmd += ["-days", str(days)]
    subprocess.run(cmd, check=True, capture_output=True)
mkcert(os.path.join(WORK, "wrong-cert.pem"), os.path.join(WORK, "wrong-key.pem"), "10.0.2.99", days=2)
mkcert(os.path.join(WORK, "valid-cert.pem"), os.path.join(WORK, "valid-key.pem"), "10.0.2.2", days=2)
# Tampered: flip the last byte of the DER signature.
import base64
pem = open(os.path.join(WORK, "valid-cert.pem")).read()
body = "".join(l for l in pem.splitlines() if "BEGIN" not in l and "END" not in l)
der = bytearray(base64.b64decode(body))
der[-1] ^= 0xFF
tb64 = base64.encodebytes(bytes(der)).decode()
open(os.path.join(WORK, "tamp-cert.pem"), "w").write(
    "-----BEGIN CERTIFICATE-----\n" + tb64 + "-----END CERTIFICATE-----\n")
# Expired via openssl ca -selfsign.
ca_dir = os.path.join(WORK, "ca")
os.makedirs(os.path.join(ca_dir, "newcerts"), exist_ok=True)
open(os.path.join(ca_dir, "index.txt"), "w").close()
open(os.path.join(ca_dir, "serial"), "w").write("1000\n")
open(os.path.join(ca_dir, "ca.cnf"), "w").write(
    "[ca]\ndefault_ca = myca\n[myca]\ndir = " + ca_dir + "\n"
    "database = $dir/index.txt\nnew_certs_dir = $dir/newcerts\n"
    "serial = $dir/serial\nprivate_key = " + os.path.join(ca_dir, "srv.key") + "\n"
    "certificate = " + os.path.join(ca_dir, "srv.crt") + "\n"
    "default_md = sha256\npolicy = pol\ncopy_extensions = copy\n"
    "[pol]\ncommonName = supplied\n[req_ext]\n"
    "subjectAltName = IP:10.0.2.2\nbasicConstraints = critical,CA:TRUE\n")
subprocess.run(["openssl", "req", "-newkey", "rsa:2048",
                "-keyout", os.path.join(ca_dir, "srv.key"),
                "-out", os.path.join(ca_dir, "srv.csr"),
                "-nodes", "-subj", "/CN=10.0.2.2"],
               check=True, capture_output=True)
subprocess.run(["openssl", "ca", "-selfsign", "-config", os.path.join(ca_dir, "ca.cnf"),
                "-in", os.path.join(ca_dir, "srv.csr"),
                "-out", os.path.join(ca_dir, "srv.crt"),
                "-startdate", "20200101000000Z", "-enddate", "20210101000000Z",
                "-batch", "-notext", "-extensions", "req_ext"],
               check=True, capture_output=True)

def tls_server(port, cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("AES128-GCM-SHA256")
    ctx.load_cert_chain(cert, key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(5); srv.settimeout(150)
    def serve():
        try:
            conn, _ = srv.accept()
            t = ctx.wrap_socket(conn, server_side=True)
            t.recv(4096)
            t.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            t.close()
        except Exception: pass
    threading.Thread(target=serve, daemon=True).start()
    return srv

def http_server(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(5); srv.settimeout(150)
    def serve():
        try:
            conn, _ = srv.accept()
            conn.recv(4096)
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            conn.close()
        except Exception: pass
    threading.Thread(target=serve, daemon=True).start()
    return srv

tls_server(18441, os.path.join(WORK, "wrong-cert.pem"), os.path.join(WORK, "wrong-key.pem"))
http_server(18442)
tls_server(18443, os.path.join(WORK, "tamp-cert.pem"), os.path.join(WORK, "valid-key.pem"))
tls_server(18444, os.path.join(ca_dir, "srv.crt"), os.path.join(ca_dir, "srv.key"))

qb = boot_qemu(B_SERIAL, B_MON, ["-netdev", "user,id=n0", "-device", "e1000,netdev=n0"])
try:
    assert wait_prompt(B_SERIAL), "guest did not reach prompt"
    sb = mon_connect(B_MON)
    type_cmd(sb, "dhcp", 8)
    type_cmd(sb, "https 10.0.2.2 / 18441", 25)
    type_cmd(sb, "https 10.0.2.2 / 18442", 25)
    type_cmd(sb, "https 10.0.2.2 / 18443", 25)
    type_cmd(sb, "https 10.0.2.2 / 18444", 25)
    type_cmd(sb, "netinfo", 3)
    sb.close()
finally:
    qb.terminate(); qb.wait(timeout=10)
log_b = open(B_SERIAL, errors="replace").read()
check("B1 wrong-host cert refused", log_b.count("certificate refused") >= 1)
# B2 must be a plain handshake failure, and the refused count
# must be exactly 3 (B1, B3, B4) — B2 must not be counted as one.
check("B2 plain-HTTP on TLS port fails (not cert)", "https: failed" in log_b)
check("B1+B3+B4 refused count == 3", log_b.count("certificate refused") == 3)
check("B shell alive after all", log_b.count("nxts> ") >= 6)

print("--- results ---")
ok = all(results.values())
for k, v in results.items():
    print(f"{'PASS' if v else 'FAIL'}: {k}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
