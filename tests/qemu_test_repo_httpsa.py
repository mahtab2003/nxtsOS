#!/usr/bin/env python3
"""Anchored repo chunk test: `pkg repo httpsa://...` must select
the ANCHORED TLS client for index + signature + package
fetches, not the TOFU client and not plain HTTP.

Why a peer proxy: guest DNS over slirp UDP is sandbox-blocked
(proven 2026-10-27), so no slirp-based HTTPS test can run here.
This test reuses the socket-netdev peer harness from
qemu_test_tls_peer.py (raw Ethernet, own DHCP/DNS/ARP, TLS
proxy via python ssl wrap_bio) and replaces its fixed
NXTS-TLS-OK response with path-based serving of a real signed
repo directory: /index.txt, /index.txt.sig, /calc.nxpkg,
/sysinfo.nxpkg. Two boots, one guest disk (which carries
tlsanchors.txt with the intermediate anchor's modulus):
  BAD: the peer presents a self-signed cert for repo.test
    (TOFU would accept it) -> `pkg update` must print
    "repository certificate refused" and install nothing.
  GOOD: the peer presents [leaf, intermediate] for repo.test,
    the intermediate being the pinned anchor -> update,
    install by name, and run must all succeed.
The refusal in the BAD boot must not poison the GOOD boot
(fresh disk copy per boot, same anchor file).

Peer TCP rules, from net/tcp.c (same as qemu_test_tls_peer.py):
ACKs every in-order segment at once; feeds ONLY seq ==
expected bytes to the SSL object (a retransmit is re-ACKed,
never re-fed); segments server output at <=1400 bytes, next
segment only after the previous is ACKed; SYN consumes one
sequence number (SYNACK seq 1000, data from 1001); SYN from a
new guest port restarts the machine; guest FIN is ACKed with
a peer FIN (deferred until queued output drains).

Usage: qemu_test_repo_https.py <iso> <workdir>
<workdir> is created by tests/qemu_test_repo_https_setup.py.
Exit 0 only if every check passes. Always terminates QEMU.
"""
import os, socket, ssl, struct, subprocess, sys, threading, time

ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
REPO_DIR = os.path.join(WORK, "repo_httpsa_v1")
SERIAL = os.path.join(WORK, "repohttpsa-serial.log")
MON = os.path.join(WORK, "repohttpsa-mon.sock")

LISTEN_PORT = 12350  # not 12345/12347/12348/12349: avoids parallel-session collisions
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
           "-nodes", "-subj", f"/CN={name}",
           "-addext", f"subjectAltName=DNS:{san}"]
    subprocess.run(cmd, check=True, capture_output=True)

class Peer:
    def __init__(self, cert_path, key_path, routes, debug_path=None):
        self.dbg = open(debug_path, "w") if debug_path else None
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_path, key_path)
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.routes = routes  # path (str) -> body bytes
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
        self.ssl_errors = []
        self.tcp_reset()

    def tcp_reset(self):
        self.tcp_state = "listen"
        self.tcp_guest_port = 0
        self.tcp_guest_seq = 0
        self.tcp_my_seq = 1000
        self.tcp_una = 1000
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
        # repo lookup resolves any tested name to us, so a
        # wrong-host refusal is a certificate refusal, not a
        # DNS failure.
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

    def ssl_pump(self, src_mac):
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
                    data = self.sslobj.read(4096)
                    if not data: break
                    self.app_buf += data
                    if b"\r\n\r\n" in self.app_buf and not self.responded:
                        # First line: GET <path> HTTP/1.0
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
        if flags & 0x04:
            self.tcp_reset()
            return
        if flags & 0x02:
            if (self.tcp_state in ("listen", "done")
                    or sport != self.tcp_guest_port):
                self.tcp_reset()
                self.tcp_guest_port = sport
                self.tcp_guest_seq = seq + 1
                self.ssl_in = ssl.MemoryBIO()
                self.ssl_out = ssl.MemoryBIO()
                self.sslobj = self.ctx.wrap_bio(self.ssl_in, self.ssl_out,
                                                server_side=True)
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
                self.ssl_in.write(data)
                self.ssl_pump(src_mac)
            else:
                self.tcp_ack(src_mac)
        elif flags & 0x10 and not self.peer_fin_sent:
            pass
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

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""

def wait_for(pred, timeout, label):
    for _ in range(int(timeout * 10)):
        if pred(log_text()): return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash"}

def boot(cert, key, tag, routes, good):
    # Sequential boots share the log_text/wait_for globals, so
    # rebind them per boot; each boot gets a fresh disk copy
    # (the BAD boot's repo.txt must not leak into GOOD).
    global SERIAL, MON
    import shutil
    SERIAL = os.path.join(WORK, f"repohttpsa-{tag}-serial.log")
    MON = os.path.join(WORK, f"repohttpsa-{tag}-mon.sock")
    disk = os.path.join(WORK, f"disk-{tag}.img")
    shutil.copy(DISK, disk)
    ok = True
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "none", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={disk},format=raw,if=ide,index=0",
        "-netdev", f"socket,id=n0,listen=127.0.0.1:{LISTEN_PORT}",
        "-device", "e1000,netdev=n0",
    ])
    peer = Peer(cert, key, routes, f"{WORK}/repohttpsa-{tag}.dbg")
    threading.Thread(target=peer.run, daemon=True).start()
    try:
        for _ in range(100):
            if os.path.exists(MON): break
            time.sleep(0.1)
        prompt = "root@nxts> "
        ok &= wait_for(lambda t: prompt in t, 60, f"{tag} shell prompt")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(MON); s.settimeout(2)
        try: s.recv(4096)
        except socket.timeout: pass
        def send_text(txt):
            def type_cmd(t):
                for ch in t:
                    s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode())
                    time.sleep(0.15)
                s.sendall(b"sendkey ret\n"); time.sleep(1)
            before = len(log_text())
            type_cmd(txt)
            for _ in range(150):
                fresh = log_text()[before:]
                if f"{prompt}{txt}" in fresh: return
                if fresh.count(prompt) >= 1: break
                time.sleep(0.1)
            if f"{prompt}{txt}" not in log_text()[before:]:
                before2 = len(log_text())
                type_cmd(txt)
                for _ in range(150):
                    if f"{prompt}{txt}" in log_text()[before2:]: break
                    time.sleep(0.1)
        send_text("dhcp")
        send_text("pkg repo httpsa://repo.test")
        ok &= wait_for(lambda t: "Repository set to httpsa://repo.test" in t,
                       30, f"{tag} repo set httpsa")
        send_text("pkg update")
        if good:
            ok &= wait_for(lambda t: "Repository index updated: 2 package(s), version 1" in t,
                           120, f"{tag} httpsa index update")
            send_text("pkg install sysinfo")
            ok &= wait_for(lambda t: "Installed sysinfo 1.0" in t,
                           120, f"{tag} httpsa package install")
            send_text("run sysinfo.elf")
            ok &= wait_for(lambda t: "sysinfo: pid " in t, 60, f"{tag} sysinfo run")
        else:
            ok &= wait_for(lambda t: "pkg update: repository certificate refused" in t,
                           90, f"{tag} anchored certificate refusal")
        time.sleep(1); s.close()
    finally:
        peer.running = False
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()
    log = log_text()
    print(f"--- {tag} boot log ---"); print(log)
    return log, peer.ssl_errors, ok

def main():
    routes = {}
    for name in ("index.txt", "index.txt.sig", "calc.nxpkg", "sysinfo.nxpkg"):
        with open(os.path.join(REPO_DIR, name), "rb") as f:
            routes["/" + name] = f.read()
    ok = True
    # BAD first: self-signed repo.test cert, anchor file present
    # for a different key -> anchored mode must refuse (TOFU
    # would accept this cert, so a refusal proves anchoring).
    bad_log, bad_err, bad_ok = boot(f"{WORK}/selfsigned.crt",
                                    f"{WORK}/selfsigned.key",
                                    "bad", routes, good=False)
    ok &= bad_ok
    # GOOD: [leaf, intermediate] chain, intermediate pinned.
    good_log, good_err, good_ok = boot(f"{WORK}/chain.pem",
                                       f"{WORK}/leaf-key.pem",
                                       "good", routes, good=True)
    ok &= good_ok
    def check(log, marker, should):
        nonlocal ok
        found = marker in log
        good = found if should else not found
        print(f"{'PASS' if good else 'FAIL'}: {'found' if should else 'absent'} {marker}")
        ok = ok and good
    check(bad_log, "pkg update: repository certificate refused", True)
    check(bad_log, "Repository index updated", False)
    check(good_log, "Repository set to httpsa://repo.test", True)
    check(good_log, "Repository index updated: 2 package(s), version 1", True)
    check(good_log, "Installed sysinfo 1.0", True)
    check(good_log, "sysinfo: pid ", True)
    for log in (bad_log, good_log):
        for m in ["EXCEPTION", "PANIC", "page fault"]:
            check(log, m, False)
    for err in (bad_err, good_err):
        if err:
            print(f"FAIL: peer ssl errors: {err}"); ok = False
    print("RESULT:", "PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
