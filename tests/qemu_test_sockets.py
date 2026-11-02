#!/usr/bin/env python3
"""Socket layer + TCP server (CORE_CLI.md section 15.2):
two concurrent client connections through the new socket
table (both complete with correct data), listen + accept
(a host peer connects to the guest server, exchanges a
payload, and a second connection is accepted while the
first is open), UDP socket send/recv, a user-program socket
test (sockprog.elf via syscalls 22/26/16/15/17), privileged-
port listen refused for non-root and allowed for root, a
firewall rule blocking a server port, and the old fetch-side
client still working end-to-end through the refactored
table (plain HTTP fetch).

Peer model (mirrors tests/qemu_test_net_peer.py): QEMU with
a socket netdev backend, plus a Python peer speaking raw
Ethernet (DHCP server, ARP, per-connection TCP servers on
18080 HTTP / 18081+18082 echo-ACK, a UDP echo on 19090,
and a TCP client for the guest-server test).

Usage: python3 tests/qemu_test_sockets.py <iso> <workdir>
Exit 0 only if all checks pass.
"""
import os, socket, struct, subprocess, sys, threading, time

ISO, WORK = sys.argv[1:3]
DISK = os.path.join(WORK, "disk.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
os.makedirs(WORK, exist_ok=True)

PEER_MAC = bytes([0x52, 0x55, 0x0A, 0x00, 0x63, 0x01])
PEER_IP = bytes([192, 168, 99, 1])
GUEST_IP = bytes([192, 168, 99, 10])
NETMASK = bytes([255, 255, 255, 0])
HTTP_RESPONSE = (b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\n"
                 b"NXTS-NET-OK\n")

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

class ServerConn:
    """One guest->peer TCP connection (HTTP or echo-ACK)."""
    def __init__(self, sport, kind):
        self.sport = sport; self.kind = kind
        self.state = "synack"; self.my_seq = 1000; self.guest_seq = 0
        self.req = b""; self.done = False

class ClientConn:
    """One peer->guest TCP connection (guest is the server)."""
    def __init__(self, sport, payload):
        self.sport = sport; self.payload = payload
        self.state = "syn_sent"; self.my_seq = 5000; self.guest_seq = 0
        self.rxbuf = b""; self.reply_event = threading.Event()
        self.synack_seen = False

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
        self.servers = {}  # sport -> ServerConn
        self.clients = {}  # sport -> ClientConn
        self.running = True
        self.lock = threading.Lock()

    def send(self, frame):
        try: self.sock.sendall(struct.pack(">I", len(frame)) + frame)
        except OSError: pass

    def recv_frame(self):
        while len(self.rxbuf) < 4:
            try: chunk = self.sock.recv(4096)
            except socket.timeout: return None
            if not chunk: return None
            self.rxbuf += chunk
        n = struct.unpack(">I", self.rxbuf[:4])[0]
        if n > 2048: raise ValueError(f"bad frame length {n}")
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

    def tcp_send(self, dst_ip, src_mac, dport, sport, seq, ack, flags, payload=b"", mss=False):
        pkt = tcp_pkt(dst_ip, PEER_IP, dport, sport, seq, ack, flags, payload, mss)
        self.send(eth(src_mac, PEER_MAC, 0x0800, pkt))

    def handle_server_tcp(self, src_mac, src_ip, sport, dport, seq, ack, flags, data):
        with self.lock:
            c = self.servers.get(sport)
            if c is None:
                if dport not in (18080, 18081, 18082): return
                if not (flags & 0x02): return
                kind = "http" if dport == 18080 else "echo"
                c = ServerConn(sport, kind)
                c.guest_seq = seq + 1
                self.servers[sport] = c
                self.tcp_send(src_ip, src_mac, sport, dport, c.my_seq,
                              c.guest_seq, 0x12, mss=True)
                return
            if flags & 0x04:
                self.servers.pop(sport, None); return
            if c.state == "synack" and (flags & 0x10) and not data:
                c.state = "established"; c.guest_seq = seq; return
            if c.state != "established": return
            if flags & 0x01:  # guest FIN: ACK it, then FIN back
                c.guest_seq = seq + 1 + len(data)
                self.tcp_send(src_ip, src_mac, sport, dport, c.my_seq,
                              c.guest_seq, 0x10)
                self.tcp_send(src_ip, src_mac, sport, dport, c.my_seq,
                              c.guest_seq, 0x11)
                c.state = "closing"; return
            if not data: return
            if seq != c.guest_seq:
                self.tcp_send(src_ip, src_mac, sport, dport, c.my_seq,
                              c.guest_seq, 0x10)
                return
            c.guest_seq = seq + len(data)
            if c.kind == "http":
                c.req += data
                if b"\r\n\r\n" in c.req and not c.done:
                    c.done = True
                    self.tcp_send(src_ip, src_mac, sport, dport, c.my_seq + 1,
                                  c.guest_seq, 0x18, HTTP_RESPONSE)
                    self.tcp_send(src_ip, src_mac, sport, dport,
                                  c.my_seq + 1 + len(HTTP_RESPONSE),
                                  c.guest_seq, 0x11)
                    c.my_seq += 1 + len(HTTP_RESPONSE)
            else:
                reply = b"ACK-" + data
                self.tcp_send(src_ip, src_mac, sport, dport, c.my_seq + 1,
                              c.guest_seq, 0x18, reply)
                c.my_seq += 1 + len(reply)

    def handle_client_tcp(self, src_mac, src_ip, sport, dport, seq, ack, flags, data):
        # Lookup is by dport (the peer client sport): incoming
        # frames carry sport = the guest's server port.
        with self.lock:
            c = self.clients.get(dport)
            if c is None: return
            if flags & 0x04:
                c.state = "reset"; return
            if c.state == "syn_sent" and (flags & 0x12):
                c.synack_seen = True
                c.guest_seq = seq + 1
                c.state = "established"
                # ACK the SYN-ACK, then send the payload.
                self.tcp_send(src_ip, src_mac, sport, dport, c.my_seq + 1,
                              c.guest_seq, 0x10)
                self.tcp_send(src_ip, src_mac, sport, dport, c.my_seq + 1,
                              c.guest_seq, 0x18, c.payload)
                return
            if c.state not in ("established", "replied"): return
            if flags & 0x01:
                c.guest_seq = seq + 1 + len(data)
                self.tcp_send(src_ip, src_mac, sport, dport,
                              c.my_seq + 1 + len(c.payload),
                              c.guest_seq, 0x10)
                return
            if not data: return
            if seq != c.guest_seq:
                self.tcp_send(src_ip, src_mac, sport, dport,
                              c.my_seq + 1 + len(c.payload),
                              c.guest_seq, 0x10)
                return
            c.guest_seq = seq + len(data)
            c.rxbuf += data
            self.tcp_send(src_ip, src_mac, sport, dport,
                          c.my_seq + 1 + len(c.payload),
                          c.guest_seq, 0x10)
            if b"SRV-ACK:" + c.payload in c.rxbuf:
                c.state = "replied"
                c.reply_event.set()

    def client_connect(self, sport, payload, wait_reply=True):
        """Drive one peer->guest connection from this thread;
        returns the ClientConn (reply_event set iff replied)."""
        c = ClientConn(sport, payload)
        with self.lock: self.clients[sport] = c
        deadline = time.time() + 8
        while time.time() < deadline and c.state == "syn_sent":
            with self.lock:
                if self.guest_mac is not None:
                    self.tcp_send(GUEST_IP, self.guest_mac, 18080, sport,
                                  c.my_seq, 0, 0x02, mss=True)
            time.sleep(0.5)
        if wait_reply and c.state != "syn_sent":
            c.reply_event.wait(timeout=20)
        return c

    def client_close(self, c):
        if self.guest_mac is None: return
        with self.lock:
            self.tcp_send(GUEST_IP, self.guest_mac, 18080, c.sport,
                          c.my_seq + 1 + len(c.payload), c.guest_seq, 0x11)
        time.sleep(0.3)

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
                elif dport == 19090 and payload == b"UDP-HELLO":
                    udp = udp_pkt(src_ip, PEER_IP, sport, 19090, b"UDP-ACK")
                    self.send(eth(src_mac, PEER_MAC, 0x0800, udp))
                continue
            if proto == 6 and len(ip) >= 40:
                tcp = ip[20:]
                sport, dport = struct.unpack(">HH", tcp[0:4])
                seq = struct.unpack(">I", tcp[4:8])[0]
                ack = struct.unpack(">I", tcp[8:12])[0]
                doff = (tcp[12] >> 4) * 4
                flags = tcp[13]
                data = tcp[doff:]
                # Dispatch by DESTINATION port for peer-as-client
                # connections: a guest->peer frame for a client
                # connection has sport = the guest's server
                # port (18080) and dport = the peer client
                # sport (4000x). Keying on sport (the old
                # code) sent every guest SYN-ACK to the
                # server handler, which dropped it — the
                # guest server handshake could never
                # complete. Server connections are keyed by
                # the guest's ephemeral sport instead, and
                # the ranges are disjoint, so dport-first
                # dispatch is unambiguous.
                with self.lock:
                    is_client = dport in self.clients
                if is_client:
                    self.handle_client_tcp(src_mac, src_ip, sport, dport,
                                           seq, ack, flags, data)
                else:
                    self.handle_server_tcp(src_mac, src_ip, sport, dport,
                                           seq, ack, flags, data)
                continue

# ---------------- harness (block-suite pattern) ----------------
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "_": "shift-minus",
          ":": "shift-semicolon", "/": "slash", "%": "shift-5",
          "&": "shift-7", "|": "shift-backslash"}
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    KEYMAP[_c] = "shift-" + _c.lower()

def log_text():
    try: return open(SERIAL, errors="replace").read()
    except FileNotFoundError: return ""
POS = [0]

def wait_from(needle, timeout, label):
    for _ in range(int(timeout * 10)):
        t = log_text()
        i = t.find(needle, POS[0])
        if i >= 0:
            POS[0] = i + len(needle)
            return True
        time.sleep(0.1)
    print(f"TIMEOUT: {label}"); return False

def stop(qemu, s):
    try: s.close()
    except Exception: pass
    if qemu.poll() is None:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()

def _current_line(t):
    idx = t.rfind("@nxts> ")
    raw = t[idx + len("@nxts> "):] if idx >= 0 else ""
    out = []
    for ch in raw:
        if ch == "\b":
            if out: out.pop()
        elif ch == "\n" or ch == "\r":
            out = []
        else:
            out.append(ch)
    return "".join(out)

def send_verified(s, txt):
    for _attempt in range(3):
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        time.sleep(0.5)
        if _current_line(log_text()) == txt:
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            return True
        for _ in range(len(txt) + 2):
            s.sendall(b"sendkey backspace\n"); time.sleep(0.1)
        time.sleep(0.5)
    s.sendall(b"sendkey ret\n"); time.sleep(1)
    return False

def send_text(s, txt):
    for ch in txt:
        s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
    s.sendall(b"sendkey ret\n"); time.sleep(1)

def sh(s, txt, user):
    before = POS[0]
    send_verified(s, txt)
    seg = None
    for _ in range(4):
        if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt}"):
            try: s.sendall(b"sendkey ret\n")
            except Exception: pass
            time.sleep(1)
            continue
        seg = log_text()[before:POS[0]]
        if f"{txt}\n" in seg:
            break
        try: s.sendall(b"sendkey ret\n")
        except Exception: pass
        time.sleep(1)
    return seg

def login(s, user, pw):
    for attempt in range(3):
        if not wait_from("login: ", 60, f"login prompt {user}"):
            return False
        send_text(s, user)
        if not wait_from("Password: ", 30, f"password prompt {user}"):
            return False
        send_text(s, pw)
        got = None
        for _ in range(300):
            t = log_text()
            if f"Welcome, {user}." in t[POS[0]:]:
                got = "ok"; break
            if "Login incorrect" in t[POS[0]:]:
                got = "bad"; break
            time.sleep(0.1)
        if got == "ok":
            return wait_from(f"{user}@nxts> ", 30, f"shell prompt {user}")
        if got != "bad":
            return False
    return False

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "none", "-serial", f"file:{SERIAL}",
    "-monitor", f"unix:{MON},server,nowait",
    "-netdev", "socket,id=n0,listen=127.0.0.1:12345",
    "-device", "e1000,netdev=n0",
    "-drive", f"file={DISK},format=raw,if=ide"])
peer = Peer()
threading.Thread(target=peer.run, daemon=True).start()
s = None
try:
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass

    check(login(s, "admin", "pwadmin"), "login as admin")
    seg = sh(s, "dhcp", "admin")
    check(seg is not None and "dhcp: configured" in seg, "dhcp configures the guest IP")
    seg = sh(s, "socktest clients 192.168.99.1 18081", "admin")
    check(seg is not None and "socktest: two connections established" in seg,
          "FIRST GATE: two client connections established at once")
    check(seg is not None and "socktest: client A got ACK-HELLO-A" in seg,
          "FIRST GATE: client A completes with correct data")
    check(seg is not None and "socktest: client B got ACK-HELLO-B" in seg,
          "FIRST GATE: client B completes with correct data")
    check(seg is not None and "socktest: two clients OK" in seg,
          "FIRST GATE: two clients OK")
    seg = sh(s, "socktest udp 192.168.99.1 19090", "admin")
    check(seg is not None and "socktest: udp got UDP-ACK" in seg, "UDP socket send/recv round-trip")
    check(seg is not None and "socktest: udp OK" in seg, "UDP socket OK")
    seg = sh(s, "run sockprog.elf", "admin")
    check(seg is not None and "sockprog: OK" in seg,
          "user-program socket via syscalls 22/26/16/15/17")
    seg = sh(s, "http 192.168.99.1 /test.txt 18080", "admin")
    check(seg is not None and "NXTS-NET-OK" in seg,
          "old fetch-side client works through the refactored table")
    seg = sh(s, "srv listen 80", "admin")
    check(seg is not None and "srv: listening on 80" in seg,
          "privileged-port listen allowed for root")
    # --- listen + accept: guest server, host peer connects twice ---
    before = POS[0]
    check(send_verified(s, "srv serve 18080"), "srv serve typed")
    time.sleep(1.5)
    c1 = peer.client_connect(40001, b"HELLO-SRV-A", wait_reply=False)
    check(c1.state != "syn_sent", "server test: peer conn 1 handshake completes")
    c2 = peer.client_connect(40002, b"HELLO-SRV-B", wait_reply=False)
    check(c2.state != "syn_sent", "server test: peer conn 2 handshake completes while conn 1 open")
    r1 = c1.reply_event.wait(timeout=20)
    r2 = c2.reply_event.wait(timeout=20)
    check(r1 and b"SRV-ACK:HELLO-SRV-A" in c1.rxbuf, "server test: conn 1 gets SRV-ACK for its payload")
    check(r2 and b"SRV-ACK:HELLO-SRV-B" in c2.rxbuf, "server test: conn 2 gets SRV-ACK for its payload")
    peer.client_close(c1); peer.client_close(c2)
    check(wait_from("admin@nxts> ", 30, "prompt after srv serve"), "srv serve returns to prompt")
    seg = log_text()[before:POS[0]]
    check(seg is not None and "srv: accepted connection 1" in seg, "serve accepted connection 1")
    check(seg is not None and "srv: accepted connection 2" in seg, "serve accepted connection 2")
    check(seg is not None and "srv: conn 1 payload HELLO-SRV-A" in seg, "serve read conn 1 payload")
    check(seg is not None and "srv: conn 2 payload HELLO-SRV-B" in seg, "serve read conn 2 payload")
    check(seg is not None and "srv: served 2 connections" in seg, "serve served 2 connections")
    seg = sh(s, "help srv serve", "admin")
    check(seg is not None and "srv serve (net)" in seg, "help srv serve gives a dedicated entry")
    seg = sh(s, "help socktest", "admin")
    check(seg is not None and "socktest (test)" in seg, "help socktest gives a dedicated entry")
    seg = sh(s, "net srv status", "admin")
    check(seg is not None and "sock: no sockets" in seg, "group dispatch net srv status; table empty after close")
    # --- firewall blocks a server port ---
    seg = sh(s, "fw enable", "admin")
    check(seg is not None and "fw: enabled" in seg, "firewall enabled for the block test")
    seg = sh(s, "fw add in deny tcp any any any 18080", "admin")
    check(seg is not None and "fw: rule added" in seg, "firewall deny rule for port 18080 added")
    before = POS[0]
    check(send_verified(s, "srv serve 18080 1 300"), "fw-block srv serve typed")
    time.sleep(1.5)
    c3 = peer.client_connect(40003, b"HELLO-BLOCKED", wait_reply=False)
    time.sleep(1.0)
    check(not c3.synack_seen, "firewall: no SYN-ACK reaches the peer on the blocked server port")
    check(wait_from("admin@nxts> ", 30, "prompt after fw-block srv serve"), "fw-block srv serve returns on timeout")
    seg = log_text()[before:POS[0]]
    check(seg is not None and "srv: timeout waiting for connections" in seg,
          "firewall: server times out with no connection (SYN dropped)")
    seg = sh(s, "fw clear", "admin")
    seg = sh(s, "fw disable", "admin")
    check(seg is not None and "fw: disabled" in seg, "firewall disabled again after the block test")
    # --- privileged port for non-root ---
    # su changes the prompt user, so sh()'s prompt wait would
    # look for the wrong user: type it and wait for alice's
    # prompt directly (root switches without a password).
    check(send_verified(s, "su alice"), "su alice typed")
    check(wait_from("alice@nxts> ", 30, "alice prompt after su"), "su to alice switches the session")
    seg = sh(s, "srv listen 80", "alice")
    check(seg is not None and "refused (root only for ports below 1024)" in seg,
          "privileged-port listen refused for non-root")
    seg = sh(s, "srv listen 18082", "alice")
    check(seg is not None and "srv: listening on 18082" in seg,
          "non-privileged listen allowed for non-root")
finally:
    peer.running = False
    try:
        if s is not None:
            stop(qemu, s)
        elif qemu.poll() is None:
            qemu.terminate()
            try: qemu.wait(timeout=10)
            except subprocess.TimeoutExpired: qemu.kill()
    except Exception:
        pass

print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
