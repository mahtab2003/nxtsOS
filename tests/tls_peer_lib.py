#!/usr/bin/env python3
"""Shared socket-netdev TLS peer harness, extracted verbatim
from tests/qemu_test_tls_anchor_stop.py (whose peer code is
itself the tls_peer.py lineage) and parameterized: no
module-level argv binding, so test files import it cleanly.
NetPeer: DHCP/DNS/ARP + TCP relay. SslPeer: full TLS 1.2
server via python ssl, with per-connection certificate
chains (chain_files[i] serves connection i, capped at the
last entry) so one boot can present a different leaf on a
later fetch — the TOFU fingerprint-mismatch case.
"""
import os, socket, ssl, struct, subprocess, threading, time

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
class NetPeer:
    """Socket-netdev peer: DHCP/DNS/ARP + TCP relay (same rules
    as qemu_test_tls_peer.py). Subclasses drive the TLS layer:
    SslPeer via python ssl, RawPeer via a hand-built flight.
    tcp_port is the guest-facing TCP port (443 default; the
    Phase 4 plain-HTTP peer uses 80). listen_port is the QEMU
    socket-netdev port, a different thing."""

    def __init__(self, listen_port, debug_path=None, tcp_port=443):
        self.tcp_port = tcp_port
        self.dbg = open(debug_path, "w") if debug_path else None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        deadline = time.time() + 15
        while True:
            try:
                self.sock.connect(("127.0.0.1", listen_port))
                break
            except OSError:
                if time.time() > deadline: raise
                time.sleep(0.2)
        self.sock.settimeout(0.5)
        self.rxbuf = b""
        self.guest_mac = None
        self.running = True
        self.tcp_reset()

    def tcp_reset(self):
        self.tcp_state = "listen"
        self.tcp_guest_port = 0
        self.tcp_guest_seq = 0
        self.tcp_my_seq = 1000
        self.tcp_una = 1000
        self.send_queue = bytearray()
        self.peer_fin_sent = False
        self.fin_pending = False
        self.tls_reset()

    def tls_reset(self):
        pass

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
        # Answer EVERY A query with the peer IP.
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

    def tcp_send_seg(self, src_mac, flags, payload=b"", mss=False):
        self.log(f"PEER> flags=0x{flags:02x} seq={self.tcp_my_seq} "
                 f"ack={self.tcp_guest_seq} len={len(payload)}")
        pkt = tcp_pkt(self.tcp_peer_ip, PEER_IP, self.tcp_guest_port,
                      self.tcp_port, self.tcp_my_seq, self.tcp_guest_seq,
                      flags, payload, mss)
        self.send(eth(src_mac, PEER_MAC, 0x0800, pkt))
        if payload:
            self.tcp_my_seq += len(payload)

    def tcp_ack(self, src_mac):
        self.tcp_send_seg(src_mac, 0x10)

    def maybe_send(self, src_mac):
        if self.tcp_una == self.tcp_my_seq and self.send_queue:
            chunk = bytes(self.send_queue[:SEG_MAX])
            del self.send_queue[:len(chunk)]
            self.tcp_send_seg(src_mac, 0x18, chunk)
        if (not self.send_queue and self.fin_pending
                and not self.peer_fin_sent
                and self.tcp_una == self.tcp_my_seq):
            self.tcp_send_seg(src_mac, 0x11)
            self.tcp_my_seq += 1
            self.peer_fin_sent = True
            self.tcp_state = "done"

    # ---- TLS layer: overridden by subclasses ----
    def tls_new_connection(self):
        pass

    def tls_feed(self, src_mac, data):
        pass

    def tcp_handle(self, src_mac, src_ip, tcp):
        sport, dport = struct.unpack(">HH", tcp[0:4])
        seq = struct.unpack(">I", tcp[4:8])[0]
        ack = struct.unpack(">I", tcp[8:12])[0]
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        data = tcp[doff:]
        self.tcp_peer_ip = src_ip
        if dport != self.tcp_port: return
        if flags & 0x04:
            self.tcp_reset()
            return
        if flags & 0x02:
            if (self.tcp_state in ("listen", "done")
                    or sport != self.tcp_guest_port):
                self.tcp_reset()
                self.tcp_guest_port = sport
                self.tcp_guest_seq = seq + 1
                self.tls_new_connection()
                self.tcp_send_seg(src_mac, 0x12, mss=True)
                self.tcp_my_seq = 1001
                self.tcp_state = "synack"
            elif self.tcp_state == "synack":
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
        if ack > self.tcp_una and ack <= self.tcp_my_seq:
            self.tcp_una = ack
            self.maybe_send(src_mac)
        if data:
            if seq == self.tcp_guest_seq:
                self.tcp_guest_seq += len(data)
                self.tcp_ack(src_mac)
                self.tls_feed(src_mac, data)
            else:
                self.tcp_ack(src_mac)
        if flags & 0x01:
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

class SslPeer(NetPeer):
    """Full TLS server via python ssl, serving routes.
    chain_files: list of (cert, key). Connection i is served
    chain_files[min(i, len-1)], so one boot can present a
    different leaf on a later fetch (TOFU mismatch case).
    min_version/max_version/ciphers override the TLS 1.2 default
    (used by the TLS 1.3 suite); negotiated records (version,
    cipher) per connection for the test to assert on."""

    def __init__(self, chain_files, routes, listen_port, debug_path=None,
                 min_version=None, max_version=None, ciphers=None,
                 seclevel0=False, raw_routes=None):
        self.ctxs = []
        self.ctxs = []
        for cert_path, key_path in chain_files:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = min_version if min_version is not None else ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = max_version if max_version is not None else ssl.TLSVersion.TLSv1_2
            cipher_str = ciphers if ciphers is not None else "AES128-GCM-SHA256"
            if seclevel0:
                # Fixture-only escape hatch: OpenSSL at the
                # default security level refuses even to LOAD
                # a SHA-1-signed chain (CA_MD_TOO_WEAK). The
                # legacy suite's sha1-default boot needs a
                # real TLS 1.2 peer serving a SHA-1 leaf so
                # the guest's modern-mode refusal is proven
                # against a live handshake, not a canned
                # record. Default behaviour is unchanged.
                cipher_str += "@SECLEVEL=0"
            ctx.set_ciphers(cipher_str)
            ctx.load_cert_chain(cert_path, key_path)
            ctx.set_alpn_protocols(["http/1.1"])
            self.ctxs.append(ctx)
        self.routes = routes
        # Phase 4 additions (defaults preserve old behaviour):
        # raw_routes maps a path to the complete response bytes
        # (for redirects, Set-Cookie, chunked bodies); requests
        # records (path, raw request bytes) per connection, so a
        # test can assert Cookie/Host headers on later hops.
        self.raw_routes = raw_routes or {}
        self.requests = []
        # Phase 4: the set of servable paths, so a test can
        # filter its request log to known routes (see
        # qemu_test_http.py's reqs() note).
        self.table = set(routes) | set(self.raw_routes)
        self.ssl_errors = []
        self.conn_count = 0
        self.negotiated = []
        super().__init__(listen_port, debug_path)

    def tls_reset(self):
        self.sslobj = None
        self.ssl_in = None
        self.ssl_out = None
        self.ssl_done = False
        self.app_buf = b""
        self.responded = False
        self.neg_recorded = False

    def tls_new_connection(self):
        self.ssl_in = ssl.MemoryBIO()
        self.ssl_out = ssl.MemoryBIO()
        idx = min(self.conn_count, len(self.ctxs) - 1)
        self.conn_count += 1
        self.sslobj = self.ctxs[idx].wrap_bio(self.ssl_in, self.ssl_out,
                                              server_side=True)

    def tls_feed(self, src_mac, data):
        self.ssl_in.write(data)
        try:
            if not self.ssl_done:
                self.sslobj.do_handshake()
                self.ssl_done = True
                if not self.neg_recorded:
                    self.neg_recorded = True
                    try:
                        self.negotiated.append(
                            (self.sslobj.version(),
                             (self.sslobj.cipher() or [None])[0]))
                    except Exception:
                        pass
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLError as e:
            self.ssl_errors.append(f"{type(e).__name__}: {e}")
            return
        if self.ssl_done:
            try:
                while True:
                    chunk = self.sslobj.read(4096)
                    if not chunk: break
                    self.app_buf += chunk
                    if b"\r\n\r\n" in self.app_buf and not self.responded:
                        line = self.app_buf.split(b"\r\n", 1)[0].decode("latin1")
                        parts = line.split(" ")
                        path = parts[1] if len(parts) >= 2 else "/"
                        self.requests.append((path, bytes(self.app_buf)))
                        if path in self.raw_routes:
                            resp = self.raw_routes[path]
                        else:
                            body = self.routes.get(path)
                            if body is None:
                                resp = b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"
                            else:
                                resp = (b"HTTP/1.0 200 OK\r\nContent-Length: "
                                        + str(len(body)).encode() + b"\r\n\r\n" + body)
                        self.log(f"SSL> serving {path} -> {len(resp)} bytes")
                        self.sslobj.write(resp)
                        self.responded = True
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as e:
                self.ssl_errors.append(f"{type(e).__name__}: {e}")
                return
        out = self.ssl_out.read()
        if out:
            self.send_queue += out
            self.maybe_send(src_mac)

KEYMAP_REPO = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
               ":": "shift-semicolon", "/": "slash"}
KEYMAP_RAW = {".": "dot", "/": "slash", " ": "spc", "-": "minus"}

def start_qemu(iso, serial, mon, disk=None, listen_port=12352):
    args = ["qemu-system-x86_64", "-cdrom", iso, "-boot", "d", "-m", "128",
            "-display", "none", "-serial", f"file:{serial}",
            "-monitor", f"unix:{mon},server,nowait"]
    if disk:
        args += ["-drive", f"file={disk},format=raw,if=ide,index=0"]
    args += ["-netdev", f"socket,id=n0,listen=127.0.0.1:{listen_port}",
             "-device", "e1000,netdev=n0"]
    return subprocess.Popen(args)

def wait_mon(mon, timeout=10):
    for _ in range(int(timeout * 10)):
        if os.path.exists(mon): return True
        time.sleep(0.1)
    return False

def wait_prompt(serial, prompt, timeout=60):
    for _ in range(int(timeout * 10)):
        try:
            if prompt in open(serial, errors="replace").read(): return True
        except FileNotFoundError: pass
        time.sleep(0.1)
    return False

def connect_mon(mon):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(mon); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    return s

def log_text(serial):
    try: return open(serial, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(serial, pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text(serial)): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

