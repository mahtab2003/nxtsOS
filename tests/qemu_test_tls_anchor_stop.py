#!/usr/bin/env python3
"""Stop-at-anchor / oversize-tail test (v1.1.2 real-device bug).

The live host nxtsos-repo.vercel.app serves a THREE-cert TLS
1.2 chain: leaf *.vercel.app + WR1 intermediate (the pinned
anchor) + GTS Root R1 (RSA-4096). On v1.1.1 BOTH client paths
refused it:
  - anchored (`httpsa`, `pkg repo httpsa://`): the verifier
    walked to the terminal R1, which is not the pinned anchor
    and 4096-bit (the kernel cannot verify it);
  - TOFU (`https`, `pkg repo https://` — the user's actual
    command): the 4096-bit R1 failed to PARSE (bn_from_be
    rejects >2048-bit keys) before verify_chain ever ran.
The fix: parse tolerates an oversize key (flagged, modulus
zeroed, never silently truncated), and verify_chain validates
only up to the trust anchor (anchored mode: first pinned
anchor cert) or up to the first oversize cert (TOFU mode:
equivalent to the server having withheld that tail, which
TOFU already accepts). Links that must actually be verified
still verify; anything past the anchor / truncation point is
not part of the validated path.

Cases (peer relay: guest DNS answers every name, so a
refusal cannot be a DNS failure):
  repo-good:      synthetic [leaf, int, root4096] chain, int
                  pinned in tlsanchors.txt -> `pkg repo
                  httpsa://repo.test` + `pkg update` + install
                  + run ALL succeed (full end-to-end proof
                  through the repo path).
  repo-badanchor: same chain, WRONG anchor file -> refused.
  repo-badsig:    leaf signed by a different key under the
                  same intermediate subject -> refused (the
                  leaf signature must verify with the anchor).
  repo-wronghost: good chain, guest asks other.test ->
                  refused (host match still enforced).
  repo-expired:   expired leaf (cryptography lib only) ->
                  refused (dates still enforced to anchor).
  live-anchored:  RAW server presents the EXACT live DERs
                  (saved probe, ../vercel-chain-2026-10-28/);
                  guest `httpsa nxtsos-repo.vercel.app /`
                  must NOT print "certificate refused" and
                  MUST send ClientKeyExchange (type 16) --
                  that send only happens after certificate
                  verification passes. NOT a full handshake:
                  no leaf private key exists for the live
                  chain, so the raw server never completes
                  it; CKX is the verification proof.
  live-tofu:      same raw server, guest `https
                  nxtsos-repo.vercel.app /` -> NOT refused
                  + CKX (the user's actual https:// path).
  live-wronghost: same raw server, guest `httpsa
                  notvercel.example /` -> refused + NO CKX
                  (control: CKX above is not a bypass).

Usage: qemu_test_tls_anchor_stop.py <iso> <workdir>
<workdir> is created by tests/qemu_test_tls_anchor_stop_setup.py.
Exit 0 only if every non-skipped case passes. Always
terminates QEMU.
"""
import os, shutil, socket, ssl, struct, subprocess, sys, threading, time

ISO, WORK = sys.argv[1:3]
REPO_DIR = os.path.join(WORK, "repo_anchor_stop_v1")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHAIN_DIR = os.path.join(os.path.dirname(ROOT), "vercel-chain-2026-10-28")
LISTEN_PORT = 12351  # not 12345/12347/12348/12349/12350
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
    SslPeer via python ssl, RawPeer via a hand-built flight."""

    def __init__(self, debug_path=None):
        self.dbg = open(debug_path, "w") if debug_path else None
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
                      443, self.tcp_my_seq, self.tcp_guest_seq,
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
        if dport != 443: return
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
    """Full TLS server via python ssl, serving repo routes."""

    def __init__(self, cert_path, key_path, routes, debug_path=None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.set_ciphers("AES128-GCM-SHA256")
        self.ctx.load_cert_chain(cert_path, key_path)
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.routes = routes
        self.ssl_errors = []
        super().__init__(debug_path)

    def tls_reset(self):
        self.sslobj = None
        self.ssl_in = None
        self.ssl_out = None
        self.ssl_done = False
        self.app_buf = b""
        self.responded = False

    def tls_new_connection(self):
        self.ssl_in = ssl.MemoryBIO()
        self.ssl_out = ssl.MemoryBIO()
        self.sslobj = self.ctx.wrap_bio(self.ssl_in, self.ssl_out,
                                        server_side=True)

    def tls_feed(self, src_mac, data):
        self.ssl_in.write(data)
        try:
            if not self.ssl_done:
                self.sslobj.do_handshake()
                self.ssl_done = True
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

class RawPeer(NetPeer):
    """Hand-built TLS 1.2 flight: ServerHello (RSA suite) +
    Certificate (given DERs) + ServerHelloDone. No leaf key
    needed: the guest's ClientKeyExchange is the proof that
    certificate verification passed."""

    def __init__(self, cert_ders, debug_path=None):
        self.cert_ders = cert_ders
        self.ckx_seen = False
        super().__init__(debug_path)

    def tls_reset(self):
        self.raw_buf = b""
        self.hello_len = 0
        self.flight_sent = False
        # NOTE: ckx_seen is NOT reset here: one boot = one
        # connection for the live cases; a reset mid-boot
        # (guest RST) must not erase an already-seen CKX.
        # It is reset per boot by the caller (fresh Peer).

    def tls_new_connection(self):
        pass

    def hs_msg(self, mtype, body):
        return bytes([mtype]) + len(body).to_bytes(3, "big") + body

    def record(self, payload):
        return b"\x16\x03\x03" + len(payload).to_bytes(2, "big") + payload

    def build_flight(self):
        if len(self.raw_buf) < 5: return None
        reclen = int.from_bytes(self.raw_buf[3:5], "big")
        if len(self.raw_buf) < 5 + reclen: return None
        hello = self.raw_buf[5:5 + reclen]
        if len(hello) < 38 or hello[0] != 1: return None
        self.hello_len = 5 + reclen
        server_random = os.urandom(32)
        sh_body = (b"\x03\x03" + server_random + b"\x00"
                   + struct.pack(">H", 0x009C) + b"\x00"
                   + struct.pack(">H", 0))
        cert_list = b""
        for der in self.cert_ders:
            cert_list += len(der).to_bytes(3, "big") + der
        cert_body = len(cert_list).to_bytes(3, "big") + cert_list
        flight = (self.record(self.hs_msg(2, sh_body))
                  + self.record(self.hs_msg(11, cert_body))
                  + self.record(self.hs_msg(14, b"")))
        self.log(f"RAW> flight len={len(flight)} certs={len(self.cert_ders)}")
        return flight

    def tls_feed(self, src_mac, data):
        self.raw_buf += data
        if not self.flight_sent:
            flight = self.build_flight()
            if flight is not None:
                self.flight_sent = True
                self.send_queue += flight
                self.maybe_send(src_mac)
            return
        # After the flight: scan guest records for a
        # ClientKeyExchange (handshake type 16). Records may
        # hold several handshake messages; scan each one.
        pos = self.hello_len
        while pos + 5 <= len(self.raw_buf):
            rtype = self.raw_buf[pos]
            reclen = int.from_bytes(self.raw_buf[pos + 3:pos + 5], "big")
            if pos + 5 + reclen > len(self.raw_buf): break
            payload = self.raw_buf[pos + 5:pos + 5 + reclen]
            if rtype == 22:
                mpos = 0
                while mpos + 4 <= len(payload):
                    mtype = payload[mpos]
                    mlen = int.from_bytes(payload[mpos + 1:mpos + 4], "big")
                    if mtype == 16 and not self.ckx_seen:
                        self.ckx_seen = True
                        self.log("RAW> ClientKeyExchange seen (cert verified)")
                    if mpos + 4 + mlen > len(payload): break
                    mpos += 4 + mlen
            pos += 5 + reclen

# ---------- boot drivers ----------

KEYMAP_REPO = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
               ":": "shift-semicolon", "/": "slash"}
KEYMAP_RAW = {".": "dot", "/": "slash", " ": "spc", "-": "minus"}

def start_qemu(serial, mon, disk=None):
    args = ["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
            "-display", "none", "-serial", f"file:{serial}",
            "-monitor", f"unix:{mon},server,nowait"]
    if disk:
        args += ["-drive", f"file={disk},format=raw,if=ide,index=0"]
    args += ["-netdev", f"socket,id=n0,listen=127.0.0.1:{LISTEN_PORT}",
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

def repo_boot(tag, disk_src, cert, key, repo_url, good):
    """One repo boot. good=True expects update+install+run;
    good=False expects a certificate refusal and no update."""
    serial = os.path.join(WORK, f"anchorstop-{tag}-serial.log")
    mon = os.path.join(WORK, f"anchorstop-{tag}-mon.sock")
    disk = os.path.join(WORK, f"disk-{tag}.img")
    shutil.copy(disk_src, disk)
    for p in (serial, mon):
        try: os.unlink(p)
        except FileNotFoundError: pass
    routes = {}
    for name in ("index.txt", "index.txt.sig", "calc.nxpkg", "sysinfo.nxpkg"):
        with open(os.path.join(REPO_DIR, name), "rb") as f:
            routes["/" + name] = f.read()
    qemu = start_qemu(serial, mon, disk)
    peer = SslPeer(cert, key, routes, f"{WORK}/anchorstop-{tag}.dbg")
    threading.Thread(target=peer.run, daemon=True).start()
    ok = True
    try:
        wait_mon(mon)
        prompt = "root@nxts> "
        ok &= wait_prompt(serial, prompt, 60)
        s = connect_mon(mon)
        def send_text(txt):
            def type_cmd(t):
                for ch in t:
                    s.sendall(f"sendkey {KEYMAP_REPO.get(ch, ch)}\n".encode())
                    time.sleep(0.15)
                s.sendall(b"sendkey ret\n"); time.sleep(1)
            before = len(log_text(serial))
            type_cmd(txt)
            for _ in range(150):
                fresh = log_text(serial)[before:]
                if f"{prompt}{txt}" in fresh: return
                if fresh.count(prompt) >= 1: break
                time.sleep(0.1)
            if f"{prompt}{txt}" not in log_text(serial)[before:]:
                before2 = len(log_text(serial))
                type_cmd(txt)
                for _ in range(150):
                    if f"{prompt}{txt}" in log_text(serial)[before2:]: break
                    time.sleep(0.1)
        send_text("dhcp")
        send_text(f"pkg repo {repo_url}")
        ok &= wait_for(serial,
                       lambda t: f"Repository set to {repo_url}" in t,
                       30, f"{tag} repo set")
        send_text("pkg update")
        if good:
            ok &= wait_for(serial,
                           lambda t: "Repository index updated: 2 package(s), version 1" in t,
                           120, f"{tag} index update")
            send_text("pkg install sysinfo")
            ok &= wait_for(serial, lambda t: "Installed sysinfo 1.0" in t,
                           120, f"{tag} package install")
            send_text("run sysinfo.elf")
            ok &= wait_for(serial, lambda t: "sysinfo: pid " in t,
                           60, f"{tag} sysinfo run")
        else:
            ok &= wait_for(serial,
                           lambda t: "pkg update: repository certificate refused" in t,
                           90, f"{tag} anchored certificate refusal")
        time.sleep(1); s.close()
    finally:
        peer.running = False
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    log = log_text(serial)
    for m in ("EXCEPTION", "PANIC", "page fault"):
        if m in log:
            print(f"  {tag}: FORBIDDEN marker present: {m}"); ok = False
    if peer.ssl_errors:
        print(f"  {tag}: peer ssl errors: {peer.ssl_errors}"); ok = False
    if good and "certificate refused" in log:
        print(f"  {tag}: UNEXPECTED certificate refused"); ok = False
    if not good and "Repository index updated" in log:
        print(f"  {tag}: index updated despite refusal case"); ok = False
    print(f"  {tag}: {'PASS' if ok else 'FAIL'}")
    return ok

def raw_boot(tag, cert_ders, command, expect_ckx):
    """One raw-server boot. expect_ckx=True: no refusal + CKX;
    expect_ckx=False: refusal + no CKX."""
    serial = os.path.join(WORK, f"anchorstop-{tag}-serial.log")
    mon = os.path.join(WORK, f"anchorstop-{tag}-mon.sock")
    for p in (serial, mon):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = start_qemu(serial, mon, None)
    peer = RawPeer(cert_ders, f"{WORK}/anchorstop-{tag}.dbg")
    threading.Thread(target=peer.run, daemon=True).start()
    try:
        wait_mon(mon)
        wait_prompt(serial, "nxts> ", 60)
        s = connect_mon(mon)
        def sk(k):
            s.sendall(f"sendkey {k}\n".encode()); time.sleep(0.12)
        def cmd(c, w):
            for ch in c:
                sk(KEYMAP_RAW.get(ch, ch))
            sk("ret"); time.sleep(w)
        cmd("dhcp", 8)
        # 30 s: the guest exchange can run slow under
        # emulation load (peer-test lesson).
        cmd(command, 30)
        s.close()
    finally:
        peer.running = False
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    log = log_text(serial)
    ok = True
    refused = "certificate refused" in log
    if expect_ckx:
        if refused:
            print(f"  {tag}: UNEXPECTED certificate refused"); ok = False
        if not peer.ckx_seen:
            print(f"  {tag}: NO ClientKeyExchange after good chain"); ok = False
    else:
        if not refused:
            print(f"  {tag}: MISSING certificate refused"); ok = False
        if peer.ckx_seen:
            print(f"  {tag}: CKX sent despite refusal case"); ok = False
    for m in ("PANIC", "EXCEPTION", "page fault"):
        if m in log:
            print(f"  {tag}: FORBIDDEN marker present: {m}"); ok = False
    print(f"  {tag}: {'PASS' if ok else 'FAIL'} "
          f"(refused={refused} ckx_seen={peer.ckx_seen} "
          f"flight_sent={peer.flight_sent})")
    return ok

def main():
    for name in ("chain3.pem", "leaf-key.pem", "badsig-chain.pem",
                 "badsig-leaf-key.pem", "disk-good.img", "disk-wrong.img"):
        if not os.path.isfile(os.path.join(WORK, name)):
            print(f"missing fixture {name} — run "
                  "tests/qemu_test_tls_anchor_stop_setup.py first")
            return 1
    live_ders = []
    for i in range(3):
        p = os.path.join(CHAIN_DIR, f"chain{i}.der")
        if not os.path.isfile(p):
            print(f"missing live chain DER {p} — cannot run live cases")
            return 1
        live_ders.append(open(p, "rb").read())
    all_ok = True
    all_ok &= repo_boot("repo-good", f"{WORK}/disk-good.img",
                        f"{WORK}/chain3.pem", f"{WORK}/leaf-key.pem",
                        "httpsa://repo.test", good=True)
    time.sleep(1)
    all_ok &= repo_boot("repo-badanchor", f"{WORK}/disk-wrong.img",
                        f"{WORK}/chain3.pem", f"{WORK}/leaf-key.pem",
                        "httpsa://repo.test", good=False)
    time.sleep(1)
    all_ok &= repo_boot("repo-badsig", f"{WORK}/disk-good.img",
                        f"{WORK}/badsig-chain.pem",
                        f"{WORK}/badsig-leaf-key.pem",
                        "httpsa://repo.test", good=False)
    time.sleep(1)
    all_ok &= repo_boot("repo-wronghost", f"{WORK}/disk-good.img",
                        f"{WORK}/chain3.pem", f"{WORK}/leaf-key.pem",
                        "httpsa://other.test", good=False)
    time.sleep(1)
    if os.path.isfile(f"{WORK}/exp-chain.pem"):
        all_ok &= repo_boot("repo-expired", f"{WORK}/disk-good.img",
                            f"{WORK}/exp-chain.pem",
                            f"{WORK}/exp-leaf-key.pem",
                            "httpsa://repo.test", good=False)
        time.sleep(1)
    else:
        print("  repo-expired: SKIPPED (no cryptography lib at setup)")
    all_ok &= raw_boot("live-anchored", live_ders,
                       "httpsa nxtsos-repo.vercel.app /", expect_ckx=True)
    time.sleep(1)
    all_ok &= raw_boot("live-tofu", live_ders,
                       "https nxtsos-repo.vercel.app /", expect_ckx=True)
    time.sleep(1)
    all_ok &= raw_boot("live-wronghost", live_ders,
                       "httpsa notvercel.example /", expect_ckx=False)
    print("RESULT:", "PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
