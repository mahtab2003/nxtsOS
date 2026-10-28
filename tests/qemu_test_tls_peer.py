#!/usr/bin/env python3
"""Phase 12 chunk: end-to-end wildcard hostname verification
through a real TLS handshake, via a peer-harness TLS proxy.

Why a peer proxy: guest DNS over slirp UDP is sandbox-blocked
(proven 2026-10-27), so no slirp-based wildcard test can run
here. This test reuses the socket-netdev peer harness from
qemu_test_net_peer.py (raw Ethernet, own DHCP/DNS/ARP) and
replaces its HTTP TCP server with a TLS proxy: the peer's
TCP state machine relays guest bytes into a python ssl
wrap_bio server object, and relays the server's bytes back
as TCP segments. No slirp, no host DNS, no internet.

Cases (one boot per certificate; guest runs `dhcp` then
`https <host> /` per fetch, TOFU mode, so self-signed peer
certs are accepted exactly on hostname match):
  A) cert SAN *.wild.test: one.wild.test -> SUCCESS (12
     bytes NXTS-TLS-OK, server ALPN http/1.1);
     wild.test -> certificate refused;
     a.b.wild.test -> certificate refused.
  B) cert SAN other.test: one.wild.test -> refused
     (control: success in A is not a bypass).
  C) cert CN *.wild.test, NO SAN: one.wild.test -> SUCCESS
     (CN fallback through a real handshake).

Peer TCP rules, from net/tcp.c (not assumed): guest sends
PSH+ACK, <=1400 bytes per send, waits for ACK, retransmits
once at 100 ticks; guest ACKs every in-order data segment
at once and drops out-of-order data. So the peer ACKs every
in-order segment immediately, feeds ONLY seq == expected
bytes to the SSL object (a retransmit has seq < expected:
re-ACK, never re-feed), segments server output at <=1400
bytes sending the next segment only after the previous is
ACKed, resends SYNACK on a SYN retransmit, and on guest
FIN ACKs it and sends its own FIN. Sequential guest
connections (new local port each time) reset TCP + SSL
state; a SYN from a new guest port restarts the machine.

Usage: qemu_test_tls_peer.py <iso> <workdir>
Exit 0 only if every case passes. Always terminates QEMU.
"""
import os, socket, ssl, struct, subprocess, sys, threading, time

ISO, WORK = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)

LISTEN_PORT = 12347  # not 12345: avoids parallel-session collisions
PEER_MAC = bytes([0x52, 0x55, 0x0A, 0x00, 0x63, 0x01])
PEER_IP = bytes([192, 168, 99, 1])
GUEST_IP = bytes([192, 168, 99, 10])
NETMASK = bytes([255, 255, 255, 0])
RESPONSE = (b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\n"
            b"NXTS-TLS-OK\n")
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
    def __init__(self, cert_path, key_path, debug_path=None):
        self.dbg = open(debug_path, "w") if debug_path else None
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_path, key_path)
        self.ctx.set_alpn_protocols(["http/1.1"])
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
        self.alpns = []       # selected ALPN per completed handshake
        self.ssl_errors = []
        self.tcp_reset()

    def tcp_reset(self):
        self.tcp_state = "listen"
        self.tcp_guest_port = 0
        self.tcp_guest_seq = 0   # next guest seq we accept
        self.tcp_my_seq = 1000   # next peer seq to send
        self.tcp_una = 1000      # oldest unacked peer seq
        self.send_queue = bytearray()
        self.sslobj = None
        self.ssl_in = None
        self.ssl_out = None
        self.ssl_done = False
        self.app_buf = b""
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

    def ssl_pump(self, src_mac):
        # Drive the wrap_bio server: handshake, then app data.
        try:
            if not self.ssl_done:
                self.sslobj.do_handshake()
                self.ssl_done = True
                self.alpns.append(self.sslobj.selected_alpn_protocol())
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLError as e:
            self.ssl_errors.append(f"{type(e).__name__}: {e}")
            return
        if self.ssl_done:
            try:
                while True:
                    data = self.sslobj.read(4096)
                    if not data: break
                    self.app_buf += data
                    if b"\r\n\r\n" in self.app_buf and not self.responded:
                        self.sslobj.write(RESPONSE)
                        self.responded = True
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as e:
                self.ssl_errors.append(f"{type(e).__name__}: {e}")
                return
        out = self.ssl_out.read()
        if out:
            self.log(f"SSL> handshake_done={self.ssl_done} "
                     f"outgoing={len(out)} app_buf={len(self.app_buf)} "
                     f"responded={self.responded}")
            self.send_queue += out
            self.maybe_send(src_mac)

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
                self.ssl_in = ssl.MemoryBIO()
                self.ssl_out = ssl.MemoryBIO()
                self.sslobj = self.ctx.wrap_bio(self.ssl_in, self.ssl_out,
                                                server_side=True)
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
                self.ssl_in.write(data)
                self.ssl_pump(src_mac)
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

def run_boot(case_name, cert_path, key_path, fetches):
    """One boot: dhcp, then one `https <host> /` per fetch.
    fetches: list of (host, expect_success). Returns
    (ok, serial_log, alpns)."""
    serial = f"{WORK}/tlspeer-{case_name}.log"
    mon = f"{WORK}/tlspeer-{case_name}.mon"
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
    peer = Peer(cert_path, key_path, f"{WORK}/tlspeer-{case_name}.dbg")
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
        for host, _ in fetches:
            # 30 s, not 15: the CN case once produced no
            # output inside 15 s but completed fine with
            # a 30 s wait (diagnostic run) — the guest
            # exchange can run slow under emulation load,
            # so a short wait misreads slowness as failure.
            cmd(f"https {host} /", 30)
        s.close()
    finally:
        peer.running = False
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    log = open(serial, errors="replace").read() if os.path.exists(serial) else ""
    # Ordered marker check: each fetch must produce its
    # expected marker, in command order.
    ok = True
    pos = 0
    for host, expect in fetches:
        marker = "NXTS-TLS-OK" if expect else "certificate refused"
        idx = log.find(marker, pos)
        if idx < 0:
            print(f"  case {case_name}: MISSING after {host}: {marker}")
            ok = False
        else:
            pos = idx + len(marker)
    for bad in ("PANIC", "EXCEPTION", "page fault"):
        if bad in log:
            print(f"  case {case_name}: FORBIDDEN marker present: {bad}")
            ok = False
    n_success = sum(1 for _, e in fetches if e)
    alpns_ok = [a for a in peer.alpns if a == "http/1.1"]
    if len(alpns_ok) != n_success:
        print(f"  case {case_name}: ALPN http/1.1 seen {len(alpns_ok)}x, "
              f"expected {n_success}x (all alpns: {peer.alpns}, "
              f"ssl errors: {peer.ssl_errors})")
        ok = False
    print(f"  case {case_name}: {'PASS' if ok else 'FAIL'} "
          f"(alpns={peer.alpns} ssl_errors={peer.ssl_errors})")
    return ok, log

def main():
    certs = {}
    for name, san in (("wild", "*.wild.test"), ("other", "other.test"),
                      ("cn", None)):
        cert = f"{WORK}/tlspeer-{name}.crt"
        key = f"{WORK}/tlspeer-{name}.key"
        cn = "*.wild.test" if name in ("wild", "cn") else "other.test"
        make_cert(cn, san, cert, key)
        certs[name] = (cert, key)
    cases = [
        ("wild", certs["wild"],
         [("one.wild.test", True), ("wild.test", False),
          ("a.b.wild.test", False)]),
        ("other", certs["other"], [("one.wild.test", False)]),
        ("cn", certs["cn"], [("one.wild.test", True)]),
    ]
    all_ok = True
    for case_name, (cert, key), fetches in cases:
        ok, _ = run_boot(case_name, cert, key, fetches)
        all_ok = all_ok and ok
        time.sleep(1)  # let the listen port release before reuse
    print("RESULT:", "PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
