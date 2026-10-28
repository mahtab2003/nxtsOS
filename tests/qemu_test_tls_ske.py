#!/usr/bin/env python3
"""Raw-server ServerKeyExchange signature test (HTTPS chunk 6).

Why a raw server: python ssl always signs ServerKeyExchange
correctly, so the guest's wrong-signature refusal branch (-2 in
net/tls.c, "certificate refused" in the shell) was stated as
NOT TESTED through every previous HTTPS chunk. This test
replaces the TLS proxy with a hand-built TLS 1.2 server flight:
ServerHello (ECDHE-RSA-AES128-GCM-SHA256 only), Certificate
(openssl self-signed, SAN DNS:ske.test, CA:TRUE), a
ServerKeyExchange carrying the P-256 generator point, and
ServerHelloDone. The signature is a real RSA-SHA256 signature
over client_random || server_random || params, made with
`openssl dgst -sign` on the certificate key -- except in the
BAD case, where its last byte is flipped before sending, so
the signature is well-formed (right length, right algorithm
bytes) but cryptographically wrong.

Cases, one boot each, guest runs `dhcp` then `https ske.test /`
(TOFU mode, peer DNS answers every name, so a refusal cannot
be a DNS failure):
  BAD:  guest must print "certificate refused" and must NOT
        send a ClientKeyExchange (it never gets past SKE).
  GOOD: guest must NOT print "certificate refused" and MUST
        send a ClientKeyExchange (handshake type 16) -- that
        send only happens after SKE verification and
        ServerHelloDone. The GOOD case is NOT claimed as a
        full handshake: this raw server sends no server
        ChangeCipherSpec/Finished, so the guest stalls or
        fails after CKX; the test asserts only the CKX
        proof, not an HTTP body (the ECDHE peer test already
        proves a full good ECDHE handshake end to end).

Peer TCP/DHCP/DNS rules are copied unchanged from
qemu_test_tls_peer.py; only the TLS layer is replaced.

Usage: qemu_test_tls_ske.py <iso> <workdir>
Exit 0 only if both cases pass. Always terminates QEMU.
"""
import os, socket, struct, subprocess, sys, threading, time

ISO, WORK = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)

LISTEN_PORT = 12349  # not 12345/12347/12348: avoids parallel-session collisions
PEER_MAC = bytes([0x52, 0x55, 0x0A, 0x00, 0x63, 0x01])
PEER_IP = bytes([192, 168, 99, 1])
GUEST_IP = bytes([192, 168, 99, 10])
NETMASK = bytes([255, 255, 255, 0])
SEG_MAX = 1400

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

def make_cert(name, san, cert_path, key_path):
    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", key_path, "-out", cert_path, "-days", "2",
           "-nodes", "-subj", f"/CN={name}"]
    if san:
        cmd += ["-addext", f"subjectAltName=DNS:{san}"]
    subprocess.run(cmd, check=True, capture_output=True)

class Peer:
    def __init__(self, cert_der, key_path, bad_sig, debug_path=None):
        self.dbg = open(debug_path, "w") if debug_path else None
        self.cert_der = cert_der
        self.key_path = key_path
        self.bad_sig = bad_sig
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        deadline = time.time() + 15
        while True:
            try:
                self.sock.connect(("127.0.0.1", LISTEN_PORT))
                break
            except OSError:
                if time.time() > deadline: raise
                time.sleep(0.2)
        self.sock.settimeout(0.5)
        self.rxbuf = b""
        self.guest_mac = None
        self.running = True
        self.ckx_seen = False   # guest sent ClientKeyExchange (type 16)
        self.flight_sent = False
        self.tcp_reset()

    def tcp_reset(self):
        self.tcp_state = "listen"
        self.tcp_guest_port = 0
        self.tcp_guest_seq = 0   # next guest seq we accept
        self.tcp_my_seq = 1000   # next peer seq to send
        self.tcp_una = 1000      # oldest unacked peer seq
        self.send_queue = bytearray()
        self.raw_buf = b""
        self.hello_len = 0
        self.responded = False
        self.peer_fin_sent = False
        self.fin_pending = False

    def log(self, msg):
        if self.dbg:
            self.dbg.write(msg + "\n"); self.dbg.flush()

    def send(self, frame):
        self.sock.sendall(struct.pack(">I", len(frame)) + frame)

    def recv_frame(self):
        while len(self.rxbuf) < 4:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not chunk: return None
            self.rxbuf += chunk
        n = struct.unpack(">I", self.rxbuf[:4])[0]
        if n > 2048: raise ValueError(f"bad frame length {n}")
        while len(self.rxbuf) < 4 + n:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not chunk: return None
            self.rxbuf += chunk
        frame = self.rxbuf[4:4 + n]
        self.rxbuf = self.rxbuf[4 + n:]
        return frame

    # ---- link/DHCP/DNS helpers (same as qemu_test_net_peer.py) ----
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
        # Answer EVERY A query with the peer IP: the guest's
        # https lookup resolves any tested name to us.
        data = req_udp[8:]
        qid = data[:2]
        pos = 12
        while pos < len(data) and data[pos] != 0:
            pos += 1 + data[pos]
        pos += 1 + 4
        question = data[12:pos]
        resp = struct.pack(">HHHHHH", struct.unpack(">H", qid)[0],
                           0x8180, 1, 1, 0, 0) + question
        resp += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + PEER_IP
        sport = struct.unpack(">H", req_udp[0:2])[0]
        udp = udp_pkt(req_ip, PEER_IP, sport, 53, resp)
        self.send(eth(guest_mac, PEER_MAC, 0x0800, udp))

    # ---- TCP + TLS proxy ----
    def tcp_send_seg(self, src_mac, flags, payload=b"", mss=False):
        self.log(f"PEER> flags=0x{flags:02x} seq={self.tcp_my_seq} "
                 f"ack={self.tcp_guest_seq} len={len(payload)}")
        pkt = tcp_pkt(self.tcp_peer_ip, PEER_IP, self.tcp_guest_port,
                      443, self.tcp_my_seq, self.tcp_guest_seq,
                      flags, payload, mss)
        self.send(eth(src_mac, PEER_MAC, 0x0800, pkt))
        if payload:
            self.tcp_my_seq += len(payload)

    def tcp_ack(self, src_mac):
        self.tcp_send_seg(src_mac, 0x10)

    def maybe_send(self, src_mac):
        # One segment at a time: send only when everything
        # previously sent is ACKed (guest ACKs each segment).
        if self.tcp_una == self.tcp_my_seq and self.send_queue:
            chunk = bytes(self.send_queue[:SEG_MAX])
            del self.send_queue[:len(chunk)]
            self.tcp_send_seg(src_mac, 0x18, chunk)
        # Deferred FIN: the guest FIN arrived while server
        # output was still queued; send it once drained.
        if (not self.send_queue and self.fin_pending
                and not self.peer_fin_sent
                and self.tcp_una == self.tcp_my_seq):
            self.tcp_send_seg(src_mac, 0x11)
            self.tcp_my_seq += 1
            self.peer_fin_sent = True
            self.tcp_state = "done"

    def hs_msg(self, mtype, body):
        return bytes([mtype]) + len(body).to_bytes(3, "big") + body

    def record(self, payload):
        return b"\x16\x03\x03" + len(payload).to_bytes(2, "big") + payload

    def build_flight(self):
        # Need the whole ClientHello record first.
        if len(self.raw_buf) < 5: return None
        reclen = int.from_bytes(self.raw_buf[3:5], "big")
        if len(self.raw_buf) < 5 + reclen: return None
        hello = self.raw_buf[5:5 + reclen]
        if len(hello) < 38 or hello[0] != 1: return None
        client_random = hello[6:38]
        self.hello_len = 5 + reclen
        server_random = os.urandom(32)
        sh_body = (b"\x03\x03" + server_random + b"\x00"
                   + struct.pack(">H", 0xC02F) + b"\x00"
                   + struct.pack(">H", 0))
        cert_body = ((len(self.cert_der) + 3).to_bytes(3, "big")
                     + len(self.cert_der).to_bytes(3, "big") + self.cert_der)
        # P-256 generator point (valid point, private key 1 --
        # irrelevant here: the GOOD case only needs CKX, and
        # the server never completes the handshake).
        gx = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        gy = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        params = b"\x03\x00\x17\x41\x04" + gx + gy
        assert len(params) == 69
        ske_msg = client_random + server_random + params
        with open(f"{WORK}/ske-msg.bin", "wb") as f: f.write(ske_msg)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.key_path,
                        "-out", f"{WORK}/ske-sig.bin", f"{WORK}/ske-msg.bin"],
                       check=True, capture_output=True)
        sig = bytearray(open(f"{WORK}/ske-sig.bin", "rb").read())
        if self.bad_sig:
            sig[-1] ^= 0x01  # well-formed length, cryptographically wrong
        ske_body = params + b"\x04\x01" + struct.pack(">H", len(sig)) + bytes(sig)
        flight = (self.record(self.hs_msg(2, sh_body))
                  + self.record(self.hs_msg(11, cert_body))
                  + self.record(self.hs_msg(12, ske_body))
                  + self.record(self.hs_msg(14, b"")))
        self.log(f"RAW> flight len={len(flight)} bad_sig={self.bad_sig} "
                 f"client_random={client_random.hex()[:16]}...")
        return flight

    def raw_handle(self, src_mac, data):
        self.raw_buf += data
        if not self.flight_sent:
            flight = self.build_flight()
            if flight is not None:
                self.flight_sent = True
                self.send_queue += flight
                self.maybe_send(src_mac)
            return
        # After the flight: scan guest records past ClientHello
        # for a ClientKeyExchange (handshake type 16).
        pos = self.hello_len
        while pos + 5 <= len(self.raw_buf):
            reclen = int.from_bytes(self.raw_buf[pos + 3:pos + 5], "big")
            if pos + 5 + reclen > len(self.raw_buf): break
            payload = self.raw_buf[pos + 5:pos + 5 + reclen]
            if payload and payload[0] == 16:
                if not self.ckx_seen:
                    self.ckx_seen = True
                    self.log("RAW> ClientKeyExchange seen (SKE passed)")
            pos += 5 + reclen

    def tcp_handle(self, src_mac, src_ip, tcp):
        sport, dport = struct.unpack(">HH", tcp[0:4])
        seq = struct.unpack(">I", tcp[4:8])[0]
        ack = struct.unpack(">I", tcp[8:12])[0]
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        data = tcp[doff:]
        self.tcp_peer_ip = src_ip
        if dport != 443: return
        if flags & 0x04:  # RST: guest aborted; fresh state
            self.tcp_reset()
            return
        if flags & 0x02:  # SYN (new or retransmitted)
            if (self.tcp_state in ("listen", "done")
                    or sport != self.tcp_guest_port):
                self.tcp_reset()
                self.tcp_guest_port = sport
                self.tcp_guest_seq = seq + 1
                # SYNACK seq is 1000; the SYN consumes one
                # sequence number, so data starts at 1001
                # (the guest sets rcv_nxt = SYNACK seq + 1).
                self.tcp_send_seg(src_mac, 0x12, mss=True)
                self.tcp_my_seq = 1001
                self.tcp_state = "synack"
            elif self.tcp_state == "synack":
                # Retransmitted SYN: resend the SAME SYNACK
                # seq (1000), not the advanced data seq.
                save = self.tcp_my_seq
                self.tcp_my_seq = 1000
                self.tcp_send_seg(src_mac, 0x12, mss=True)
                self.tcp_my_seq = save
            return
        if sport != self.tcp_guest_port: return
        if self.tcp_state == "synack" and flags & 0x10:
            self.tcp_state = "established"
            self.log(f"GUEST> established ack={ack}")
            return
        if self.tcp_state != "established": return
        self.log(f"GUEST> flags=0x{flags:02x} seq={seq} ack={ack} "
                 f"len={len(data)} expected={self.tcp_guest_seq} "
                 f"una={self.tcp_una} my_seq={self.tcp_my_seq}")
        # ACK progress for our sent data.
        if ack > self.tcp_una and ack <= self.tcp_my_seq:
            self.tcp_una = ack
            self.maybe_send(src_mac)
        if data:
            if seq == self.tcp_guest_seq:
                self.tcp_guest_seq += len(data)
                self.tcp_ack(src_mac)
                self.raw_handle(src_mac, data)
            else:
                # Retransmit (seq < expected) or gap: re-ACK,
                # NEVER re-feed bytes to the TLS stream.
                self.tcp_ack(src_mac)
        elif flags & 0x10 and not self.peer_fin_sent:
            # Pure ACK (e.g. ACK of our data already handled
            # above); nothing else to do.
            pass
        if flags & 0x01:  # FIN at the expected position
            if seq + len(data) == self.tcp_guest_seq:
                self.tcp_guest_seq += 1
                self.tcp_ack(src_mac)
                if not self.peer_fin_sent:
                    if self.tcp_una == self.tcp_my_seq and not self.send_queue:
                        self.tcp_send_seg(src_mac, 0x11)
                        self.tcp_my_seq += 1
                        self.peer_fin_sent = True
                        self.tcp_state = "done"
                    else:
                        # FIN deferred until the queue drains
                        # (maybe_send sends it then).
                        self.fin_pending = True

    def run(self):
        while self.running:
            try:
                frame = self.recv_frame()
            except (OSError, ValueError):
                return
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
            if proto == 6 and len(ip) >= 40:
                self.tcp_handle(src_mac, src_ip, ip[20:])
                continue

def run_boot(case_name, cert_der, key_path, bad_sig):
    """One boot: dhcp, then one `https ske.test /`.
    BAD expects a certificate refusal and no CKX; GOOD
    expects no refusal and a CKX. Returns ok."""
    serial = f"{WORK}/tlsske-{case_name}.log"
    mon = f"{WORK}/tlsske-{case_name}.mon"
    for p in (serial, mon):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "none", "-serial", f"file:{serial}",
        "-monitor", f"unix:{mon},server,nowait",
        "-netdev", f"socket,id=n0,listen=127.0.0.1:{LISTEN_PORT}",
        "-device", "e1000,netdev=n0",
    ])
    peer = Peer(cert_der, key_path, bad_sig, f"{WORK}/tlsske-{case_name}.dbg")
    threading.Thread(target=peer.run, daemon=True).start()
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
        KEYMAP = {".": "dot", "/": "slash", " ": "spc", "-": "minus"}
        def sk(k):
            s.sendall(f"sendkey {k}\n".encode()); time.sleep(0.12)
        def cmd(c, w):
            for ch in c:
                sk(KEYMAP.get(ch, ch))
            sk("ret"); time.sleep(w)
        cmd("dhcp", 8)
        # 30 s: the guest exchange can run slow under
        # emulation load, so a short wait misreads
        # slowness as failure (peer-test lesson).
        cmd("https ske.test /", 30)
        s.close()
    finally:
        peer.running = False
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    log = open(serial, errors="replace").read() if os.path.exists(serial) else ""
    ok = True
    refused = "certificate refused" in log
    if bad_sig:
        if not refused:
            print(f"  case {case_name}: MISSING certificate refused")
            ok = False
        if peer.ckx_seen:
            print(f"  case {case_name}: CKX sent despite bad SKE")
            ok = False
    else:
        if refused:
            print(f"  case {case_name}: UNEXPECTED certificate refused")
            ok = False
        if not peer.ckx_seen:
            print(f"  case {case_name}: NO ClientKeyExchange after good SKE")
            ok = False
    for bad in ("PANIC", "EXCEPTION", "page fault"):
        if bad in log:
            print(f"  case {case_name}: FORBIDDEN marker present: {bad}")
            ok = False
    print(f"  case {case_name}: {'PASS' if ok else 'FAIL'} "
          f"(refused={refused} ckx_seen={peer.ckx_seen} "
          f"flight_sent={peer.flight_sent})")
    return ok

def main():
    cert = f"{WORK}/tlsske.crt"
    key = f"{WORK}/tlsske.key"
    make_cert("ske.test", "ske.test", cert, key)
    der = f"{WORK}/tlsske.der"
    subprocess.run(["openssl", "x509", "-in", cert, "-outform", "DER",
                    "-out", der], check=True, capture_output=True)
    cert_der = open(der, "rb").read()
    all_ok = True
    # BAD first: a refusal must poison nothing for the GOOD
    # boot (fresh QEMU + fresh peer each time).
    for case_name, bad_sig in (("bad", True), ("good", False)):
        all_ok = run_boot(case_name, cert_der, key, bad_sig) and all_ok
        time.sleep(1)  # let the listen port release before reuse
    print("RESULT:", "PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
