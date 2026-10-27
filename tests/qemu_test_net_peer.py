#!/usr/bin/env python3
"""Deterministic Phase 9 test: QEMU with a socket netdev backend,
plus a Python peer that speaks raw Ethernet on the other end
(DHCP server, DNS server, ARP, ICMP echo, and a minimal TCP
server for HTTP). No slirp, no host DNS, no internet needed.
Usage: python3 tests/qemu_test_net_peer.py <iso> <workdir>
Exit 0 only if all markers are found."""
import os, socket, struct, subprocess, sys, threading, time

ISO, WORK = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)
SERIAL_LOG = os.path.join(WORK, "serial.log")
MON_SOCK = os.path.join(WORK, "mon.sock")

PEER_MAC = bytes([0x52, 0x55, 0x0A, 0x00, 0x63, 0x01])
PEER_IP = bytes([192, 168, 99, 1])
GUEST_IP = bytes([192, 168, 99, 10])
NETMASK = bytes([255, 255, 255, 0])
DNS_ANSWER = bytes([93, 184, 216, 34])  # example.com's real IP

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

class Peer:
    def __init__(self):
        # TCP stream mode: QEMU listens on 127.0.0.1:12345; frames
        # are length-prefixed (4-byte big-endian length + frame).
        # (UDP socket mode was tried first and delivered nothing
        # in this sandbox, even though QEMU reported the netdev
        # as up — stream mode is the documented QEMU-to-QEMU
        # link, so it is the reliable choice here.)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        deadline = time.time() + 15
        while True:
            try:
                self.sock.connect(("127.0.0.1", 12345))
                break
            except OSError:
                if time.time() > deadline: raise
                time.sleep(0.2)
        self.sock.settimeout(0.5)
        self.rxbuf = b""
        self.guest_mac = None
        self.tcp_state = "listen"  # listen, synack, established, done
        self.tcp_guest_port = 0
        self.tcp_guest_seq = 0
        self.tcp_my_seq = 1000
        self.http_response = (b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\n"
                              b"NXTS-NET-OK\n")
        self.running = True

    def send(self, frame):
        self.sock.sendall(struct.pack(">I", len(frame)) + frame)

    def recv_frame(self):
        # Returns one frame, or None on timeout.
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
        # req is the UDP payload (BOOTP). Echo xid + chaddr.
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
        # Find end of question: skip QNAME then 4 bytes.
        pos = 12
        while pos < len(data) and data[pos] != 0:
            pos += 1 + data[pos]
        pos += 1 + 4
        question = data[12:pos]
        resp = struct.pack(">HHHHHH", struct.unpack(">H", qid)[0],
                           0x8180, 1, 1, 0, 0) + question
        resp += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + DNS_ANSWER
        sport = struct.unpack(">H", req_udp[0:2])[0]
        udp = udp_pkt(req_ip, PEER_IP, sport, 53, resp)
        self.send(eth(guest_mac, PEER_MAC, 0x0800, udp))

    def run(self):
        while self.running:
            try:
                frame = self.recv_frame()
            except (OSError, ValueError):
                return
            if frame is None: continue
            if len(frame) < 14: continue
            etype = struct.unpack(">H", frame[12:14])[0]
            print(f"peer got frame len={len(frame)} type=0x{etype:04x} "
                  f"dst={frame[:6].hex()} src={frame[6:12].hex()}", flush=True)
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
                if icmp[0] == 8:  # echo request
                    reply_icmp = bytes([0, 0, 0, 0]) + icmp[4:]
                    reply_icmp = reply_icmp[:2] + struct.pack(
                        ">H", csum(reply_icmp)) + reply_icmp[4:]
                    pkt = ip_pkt(src_ip, PEER_IP, 1, reply_icmp)
                    self.send(eth(src_mac, PEER_MAC, 0x0800, pkt))
                continue
            if proto == 17 and len(ip) >= 28:
                udp = ip[20:]
                sport, dport = struct.unpack(">HH", udp[0:4])
                payload = udp[8:]
                if dport == 67 and len(payload) >= 240:
                    # DHCP: find message type option.
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
                    print(f"peer DNS query id={udp[8:10].hex()} from {src_ip.hex()}", flush=True)
                    self.dns_reply(src_ip, udp, src_mac)
                    print("peer DNS reply sent", flush=True)
                continue
            if proto == 6 and len(ip) >= 40:
                tcp = ip[20:]
                sport, dport = struct.unpack(">HH", tcp[0:4])
                seq = struct.unpack(">I", tcp[4:8])[0]
                ack = struct.unpack(">I", tcp[8:12])[0]
                doff = (tcp[12] >> 4) * 4
                flags = tcp[13]
                data = tcp[doff:]
                if dport != 18080: continue
                if self.tcp_state == "listen" and flags & 0x02:
                    self.tcp_guest_port = sport
                    self.tcp_guest_seq = seq + 1
                    pkt = tcp_pkt(src_ip, PEER_IP, sport, 18080,
                                  self.tcp_my_seq, self.tcp_guest_seq,
                                  0x12, mss=True)
                    self.send(eth(src_mac, PEER_MAC, 0x0800, pkt))
                    self.tcp_state = "synack"
                elif self.tcp_state == "synack" and flags & 0x10:
                    self.tcp_state = "established"
                elif self.tcp_state == "established" and data:
                    # HTTP request: send response + FIN.
                    self.tcp_guest_seq = seq + len(data)
                    pkt = tcp_pkt(src_ip, PEER_IP, sport, 18080,
                                  self.tcp_my_seq + 1, self.tcp_guest_seq,
                                  0x18, self.http_response)
                    self.send(eth(src_mac, PEER_MAC, 0x0800, pkt))
                    fin = tcp_pkt(src_ip, PEER_IP, sport, 18080,
                                  self.tcp_my_seq + 1 + len(self.http_response),
                                  self.tcp_guest_seq, 0x11)
                    self.send(eth(src_mac, PEER_MAC, 0x0800, fin))
                    self.tcp_state = "done"
                elif self.tcp_state == "done" and flags & 0x01:
                    ack_pkt = tcp_pkt(src_ip, PEER_IP, sport, 18080,
                                      self.tcp_my_seq + 1 + len(self.http_response),
                                      seq + 1, 0x10)
                    self.send(eth(src_mac, PEER_MAC, 0x0800, ack_pkt))

peer = None  # created after QEMU starts listening (below)

MARKERS = [
    "net: DHCP ok ip=192.168.99.10",
    "ping: reply received",
    "dns: example.com = 93.184.216.34",
    "NXTS-NET-OK",
    "nettest PASS",
]

for p in (SERIAL_LOG, MON_SOCK):
    try: os.unlink(p)
    except FileNotFoundError: pass

qemu = subprocess.Popen([
    "qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
    "-display", "none", "-serial", f"file:{SERIAL_LOG}",
    "-monitor", f"unix:{MON_SOCK},server,nowait",
    "-netdev", "socket,id=n0,listen=127.0.0.1:12345",
    "-device", "e1000,netdev=n0",
])
# QEMU listens on 12345; connect the peer, then run it.
peer = Peer()
threading.Thread(target=peer.run, daemon=True).start()
try:
    for _ in range(100):
        if os.path.exists(MON_SOCK): break
        time.sleep(0.1)
    for _ in range(600):
        try:
            if "nxts> " in open(SERIAL_LOG, errors="replace").read(): break
        except FileNotFoundError: pass
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(MON_SOCK)
    s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    KEYMAP = {".": "dot", "/": "slash", " ": "spc", "-": "minus"}
    def sendkey(k):
        s.sendall(f"sendkey {k}\n".encode())
        time.sleep(0.12)
    def type_cmd(cmd, wait):
        for ch in cmd:
            sendkey(KEYMAP.get(ch, ch))
        sendkey("ret")
        time.sleep(wait)
    type_cmd("dhcp", 8)
    type_cmd("ping 192.168.99.1", 6)
    type_cmd("dns example.com", 8)
    type_cmd("http 192.168.99.1 /test.txt 18080", 8)
    type_cmd("nettest", 3)
    s.close()
finally:
    peer.running = False
    qemu.terminate()
    try: qemu.wait(timeout=10)
    except subprocess.TimeoutExpired: qemu.kill()

log = open(SERIAL_LOG, errors="replace").read() if os.path.exists(SERIAL_LOG) else ""
print("--- serial log (tail) ---")
print("\n".join(log.splitlines()[-30:]))
print("--- marker check ---")
ok = True
for m in MARKERS:
    found = m in log
    print(f"{'FOUND' if found else 'MISSING'}: {m}")
    ok = ok and found
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
