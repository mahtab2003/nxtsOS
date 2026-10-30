#!/usr/bin/env python3
"""Core firewall test: rule management + proof that denied
traffic is actually dropped.

The guest network is POLLED: the shell idle loop never calls
net_poll, so an inbound frame sent while the guest idles at
the prompt sits in the NIC ring until a polling command runs.
Every inbound proof therefore pumps the stack with a guest
`ping` to the peer (allowed traffic, distinguishable from the
injected frames by direction and by ICMP id), then reads
`fw stat`. Outbound proofs need no pump: the denied send
fails inside net_ip_send before ARP.

Peer: QEMU socket netdev (stream, length-prefixed frames) on
127.0.0.1:12357, serving DHCP (guest 192.168.99.10, peer
192.168.99.1), ARP, and ICMP echo replies. It records every
frame it receives, so "no reply" and "packet never sent" are
proven from the peer side, not just from guest messages.

Boots (all on the same ISO):
  1 (fresh blank disk, setup root): status/list defaults;
     inbound ICMP deny (no guest reply + drops up) then
     allow (reply arrives); inbound UDP deny on port 9999
     (drops up) then allow (drops unchanged); outbound ICMP
     deny (ping no reply + peer sees no echo request +
     drops up) then allow (ping reply); validation (bad
     direction/port/range/del-number/bare-fw all refused,
     list unchanged); default deny then allow; port-range +
     dst-IP rule matching (8005 denied, 8101 untouched);
     clear + disable; then persistence: add 2 rules +
     enable, shell `reboot`, dhcp again, list + status show
     the same rules and enabled state.
  2 (malformed disk, setup root): fw.txt with headers +
     one good rule + three malformed lines loads exactly
     the good rule with the header values.
  3 (admin disk): alice is refused on every mutation with
     "fw: root only" while list/status stay readable; admin
     (uid 0) then proves no rules were added and the
     firewall is still disabled.
Exit 0 only if all checks pass.
Usage: python3 tests/qemu_test_core_fw.py <iso> <workdir>
<workdir> is created by tests/qemu_test_core_fw_setup.py.
"""
import os, re, shutil, socket, struct, subprocess, sys, threading, time
ISO, WORK = sys.argv[1:3]
BLANK = os.path.join(WORK, "blank.img")
MALFORMED = os.path.join(WORK, "malformed.img")
ADMIN = os.path.join(WORK, "admin.img")
SERIAL = os.path.join(WORK, "serial.log")
MON = os.path.join(WORK, "mon.sock")
PORT = 12357
PEER_MAC = bytes([0x52, 0x55, 0x0A, 0x00, 0x63, 0x01])
PEER_IP = bytes([192, 168, 99, 1])
GUEST_IP = bytes([192, 168, 99, 10])
NETMASK = bytes([255, 255, 255, 0])
KEYMAP = {" ": "spc", ".": "dot", "-": "minus", "/": "slash"}

def csum(data):
    if len(data) % 2: data += b"\x00"
    s = 0
    for i in range(0, len(data), 2): s += (data[i] << 8) | data[i + 1]
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def ip_pkt(dst_ip, src_ip, proto, payload):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, 0, 64, proto, 0, src_ip, dst_ip)
    hdr = hdr[:10] + struct.pack(">H", csum(hdr)) + hdr[12:]
    return hdr + payload

def udp_pkt(dst_ip, src_ip, dport, sport, payload):
    seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ip_pkt(dst_ip, src_ip, 17, seg)

def eth(dst_mac, src_mac, etype, payload):
    return dst_mac + src_mac + struct.pack(">H", etype) + payload

def icmp_echo(dst_ip, src_ip, id_, seq, payload=b"FWTEST"):
    icmp = struct.pack(">BBHHH", 8, 0, 0, id_, seq) + payload
    icmp = icmp[:2] + struct.pack(">H", csum(icmp)) + icmp[4:]
    return ip_pkt(dst_ip, src_ip, 1, icmp)

class Peer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        deadline = time.time() + 15
        while True:
            try:
                self.sock.connect(("127.0.0.1", PORT)); break
            except OSError:
                if time.time() > deadline: raise
                time.sleep(0.2)
        self.sock.settimeout(0.5)
        self.rxbuf = b""
        self.frames = []
        self.lock = threading.Lock()
        self.guest_mac = None
        self.running = True

    def send(self, frame):
        with self.lock:
            self.sock.sendall(struct.pack(">I", len(frame)) + frame)

    def recv_frame(self):
        while len(self.rxbuf) < 4:
            try: chunk = self.sock.recv(4096)
            except socket.timeout: return None
            if not chunk: return None
            self.rxbuf += chunk
        n = struct.unpack(">I", self.rxbuf[:4])[0]
        if n > 2048: raise ValueError("bad frame length")
        while len(self.rxbuf) < 4 + n:
            try: chunk = self.sock.recv(4096)
            except socket.timeout: return None
            if not chunk: return None
            self.rxbuf += chunk
        frame = self.rxbuf[4:4 + n]
        self.rxbuf = self.rxbuf[4 + n:]
        return frame

    def dhcp_reply(self, req, mtype, chaddr):
        pkt = bytearray(300)
        pkt[0] = 2; pkt[1] = 1; pkt[2] = 6
        pkt[4:8] = req[4:8]
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

    def run(self):
        while self.running:
            try: frame = self.recv_frame()
            except (OSError, ValueError): return
            if frame is None: continue
            with self.lock: self.frames.append(frame)
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
                if icmp[0] == 8:  # echo request from guest: answer it
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
                    if mtype == 1: self.dhcp_reply(payload, 2, src_mac)
                    elif mtype == 3: self.dhcp_reply(payload, 5, src_mac)
                continue

    # ---- test-side injection / inspection ----
    def guest_echo_reply_seen(self, id_, seq):
        with self.lock: frames = list(self.frames)
        for f in frames:
            if len(f) < 34: continue
            if struct.unpack(">H", f[12:14])[0] != 0x0800: continue
            ip = f[14:]
            if ip[9] != 1 or len(ip) < 28: continue
            icmp = ip[20:]
            if icmp[0] == 0 and struct.unpack(">HH", icmp[4:8]) == (id_, seq):
                return True
        return False

    def guest_echo_request_seen(self):
        with self.lock: frames = list(self.frames)
        for f in frames:
            if len(f) < 34: continue
            if struct.unpack(">H", f[12:14])[0] != 0x0800: continue
            ip = f[14:]
            if ip[9] != 1 or len(ip) < 28: continue
            if ip[20] == 8 and ip[12:16] == GUEST_IP:
                return True
        return False

    def clear(self):
        with self.lock: self.frames = []

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

def boot(disk):
    for p in (SERIAL, MON):
        try: os.unlink(p)
        except FileNotFoundError: pass
    POS[0] = 0
    qemu = subprocess.Popen(["qemu-system-x86_64", "-cdrom", ISO, "-boot", "d", "-m", "128",
        "-display", "none", "-serial", f"file:{SERIAL}",
        "-monitor", f"unix:{MON},server,nowait",
        "-drive", f"file={disk},format=raw,if=ide,index=0",
        "-netdev", f"socket,id=n0,listen=127.0.0.1:{PORT}",
        "-device", "e1000,netdev=n0"])
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(MON); s.settimeout(2)
    try: s.recv(4096)
    except socket.timeout: pass
    return qemu, s

def stop(qemu, s):
    try: s.close()
    except Exception: pass
    if qemu.poll() is None:
        qemu.terminate()
        try: qemu.wait(timeout=10)
        except subprocess.TimeoutExpired: qemu.kill()

def send_text(s, txt):
    for _attempt in range(2):
        before = len(log_text())
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        s.sendall(b"sendkey ret\n"); time.sleep(1)
        if "Unknown command" not in log_text()[before:]:
            break

def _current_line(t):
    """Text of the current shell input line, as the terminal
    would show it: the raw log after the last prompt, with
    backspace bytes (0x08, one per shell backspace echo)
    applied as deletions. Lets the verified sender check a
    retyped line even after backspaces polluted the log."""
    idx = t.rfind("@nxts> ")
    raw = t[idx + len("@nxts> "):] if idx >= 0 else ""
    out = []
    for ch in raw:
        if ch == "\b":
            if out: out.pop()
        elif ch == "\n" or ch == "\r":
            break
        else:
            out.append(ch)
    return "".join(out)

def send_text_verified(s, txt):
    """Type a shell command WITHOUT Enter, verify the echo line
    matches exactly, and only then send Enter. QEMU sendkey
    occasionally doubles a key ("fw liist", "ffw enable"): the
    old send-then-check pattern let the garbled command
    EXECUTE (usage/Unknown/wrong rule) and desynced every
    later segment. Verifying before Enter means a garble is
    cleared with backspaces and retyped, never executed.
    Returns True if the echo verified (else Enter was still
    sent on the last attempt and the caller checks output)."""
    for _attempt in range(3):
        for ch in txt:
            s.sendall(f"sendkey {KEYMAP.get(ch, ch)}\n".encode()); time.sleep(0.15)
        time.sleep(0.5)
        if _current_line(log_text()) == txt:
            s.sendall(b"sendkey ret\n"); time.sleep(1)
            return True
        # Garbled: clear the line (len+2 backspaces covers one
        # doubled key; backspace on an empty line is harmless)
        for _ in range(len(txt) + 2):
            s.sendall(b"sendkey backspace\n"); time.sleep(0.1)
        time.sleep(0.5)
    s.sendall(b"sendkey ret\n"); time.sleep(1)
    return False

def sh(s, txt, user):
    """Shell command; returns the output segment, or None.
    Uses the verified sender, then loops prompts until the
    segment holds the command's echo line (echo + Enter
    newline). The prompt prefix is NOT part of the check:
    the segment starts after the previous prompt, so the
    echo line is split across that boundary (prompt before,
    text after) — requiring the prefix can never match.
    The first prompt after sending may be the stale
    pre-command prompt, whose segment holds no echo."""
    before = POS[0]
    send_text_verified(s, txt)
    seg = None
    for _ in range(3):
        if not wait_from(f"{user}@nxts> ", 30, f"prompt after {txt}"):
            return None
        seg = log_text()[before:POS[0]]
        if f"{txt}\n" in seg:
            break
    return seg

def fw_drops(s, user):
    seg = sh(s, "fw stat", user)
    if seg is None: return None
    m = re.search(r"fw: (\d+) drops", seg)
    return int(m.group(1)) if m else None

def login(s, user, pw):
    fails = 0
    for _attempt in range(3):
        if not wait_from("login: ", 60, f"login prompt {user}"): return False
        send_text(s, user)
        if not wait_from("Password: ", 30, f"password prompt {user}"): return False
        send_text(s, pw)
        got = None
        for _ in range(300):
            t = log_text()
            if f"Welcome, {user}." in t[POS[0]:]: got = "ok"; break
            if "Login incorrect" in t[POS[0]:]: got = "bad"; break
            time.sleep(0.1)
        if got == "ok":
            return wait_from(f"{user}@nxts> ", 30, f"shell prompt {user}")
        if got != "bad": return False
        fails += 1
        if fails >= 2: return False
    return False

ok = True
def check(cond, label):
    global ok
    if cond: print(f"ok: {label}")
    else: print(f"FAIL: {label}"); ok = False

def fresh_blank(name):
    dst = os.path.join(WORK, name)
    shutil.copyfile(BLANK, dst)
    return dst

def pump(s, user, expect_reply=True):
    """Poll the guest network stack via a ping. The ping's own
    result depends on the active rules: when an inbound ICMP
    deny (or default deny) is active, its reply is denied too,
    so it reports no reply — but net_ping still polls for 300
    ticks first, which is what processes queued inbound
    frames. expect_reply=False covers exactly that case: the
    pump's job is the poll, not its own reply."""
    seg = sh(s, "ping 192.168.99.1", user)
    if seg is None: return False
    return ("ping: reply received" in seg) if expect_reply else ("ping: no reply" in seg)

PEER_IP_TXT = "192.168.99.1"
peer = None

# ---- Boot 1: proofs + persistence ----
qemu, s = boot(fresh_blank("fw1.img"))
try:
    peer = Peer()
    t = threading.Thread(target=peer.run, daemon=True); t.start()
    check(wait_from("root@nxts> ", 60, "boot 1 prompt"), "boot 1 prompt")
    seg = sh(s, "dhcp", "root")
    check(seg is not None and "dhcp: configured" in seg, "dhcp configured")
    seg = sh(s, "fw status", "root")
    check(seg is not None and "fw: disabled, default allow, 0 rules, 0 drops" in seg, "status defaults")
    seg = sh(s, "fw list", "root")
    check(seg is not None and "fw: no rules" in seg, "list empty")
    # inbound ICMP deny
    seg = sh(s, "fw add in deny icmp any any any any", "root")
    check(seg is not None and "fw: rule added" in seg, "add inbound icmp deny")
    seg = sh(s, "fw list", "root")
    check(seg is not None and "1: in deny icmp any any any any" in seg, "list shows icmp deny")
    seg = sh(s, "fw enable", "root")
    check(seg is not None and "fw: enabled" in seg, "enable")
    d0 = fw_drops(s, "root")
    peer.clear()
    peer.send(eth(peer.guest_mac, PEER_MAC, 0x0800, icmp_echo(GUEST_IP, PEER_IP, 0xF001, 1)))
    time.sleep(1.0)
    # The pump ping's own reply is denied by the same inbound
    # ICMP rule, so it reports no reply — but its 300-tick
    # poll still processes the injected frame.
    check(pump(s, "root", expect_reply=False), "pump poll runs (icmp deny)")
    time.sleep(0.5)
    check(not peer.guest_echo_reply_seen(0xF001, 1), "inbound icmp denied: no guest reply")
    d1 = fw_drops(s, "root")
    check(d0 is not None and d1 is not None and d1 > d0, "inbound icmp denied: drops up")
    # inbound ICMP allow
    seg = sh(s, "fw del 1", "root")
    check(seg is not None and "fw: rule deleted" in seg, "del icmp deny")
    peer.clear()
    peer.send(eth(peer.guest_mac, PEER_MAC, 0x0800, icmp_echo(GUEST_IP, PEER_IP, 0xF001, 2)))
    time.sleep(1.0)
    check(pump(s, "root"), "pump ping replies (allow)")
    time.sleep(0.5)
    check(peer.guest_echo_reply_seen(0xF001, 2), "inbound icmp allowed: guest reply arrives")
    # inbound UDP deny on 9999, then allow
    seg = sh(s, "fw add in deny udp any any any 9999", "root")
    check(seg is not None and "fw: rule added" in seg, "add inbound udp 9999 deny")
    d0 = fw_drops(s, "root")
    peer.send(eth(peer.guest_mac, PEER_MAC, 0x0800, udp_pkt(GUEST_IP, PEER_IP, 9999, 1234, b"FWTEST")))
    time.sleep(1.0)
    check(pump(s, "root"), "pump ping replies (udp deny)")
    d1 = fw_drops(s, "root")
    check(d0 is not None and d1 is not None and d1 > d0, "inbound udp 9999 denied: drops up")
    seg = sh(s, "fw del 1", "root")
    check(seg is not None and "fw: rule deleted" in seg, "del udp deny")
    d0 = fw_drops(s, "root")
    peer.send(eth(peer.guest_mac, PEER_MAC, 0x0800, udp_pkt(GUEST_IP, PEER_IP, 9999, 1234, b"FWTEST")))
    time.sleep(1.0)
    check(pump(s, "root"), "pump ping replies (udp allow)")
    d1 = fw_drops(s, "root")
    check(d0 is not None and d1 is not None and d1 == d0, "inbound udp 9999 allowed: drops unchanged")
    # outbound ICMP deny, then allow
    seg = sh(s, "fw add out deny icmp any any any any", "root")
    check(seg is not None and "fw: rule added" in seg, "add outbound icmp deny")
    d0 = fw_drops(s, "root")
    peer.clear()
    seg = sh(s, "ping 192.168.99.1", "root")
    check(seg is not None and "ping: no reply" in seg, "outbound icmp denied: ping no reply")
    time.sleep(0.5)
    check(not peer.guest_echo_request_seen(), "outbound icmp denied: peer sees no request")
    d1 = fw_drops(s, "root")
    check(d0 is not None and d1 is not None and d1 > d0, "outbound icmp denied: drops up")
    seg = sh(s, "fw del 1", "root")
    check(seg is not None and "fw: rule deleted" in seg, "del outbound deny")
    seg = sh(s, "ping 192.168.99.1", "root")
    check(seg is not None and "ping: reply received" in seg, "outbound icmp allowed: ping reply")
    # validation: bad fields refused, list unchanged
    seg = sh(s, "fw add sideways deny icmp any any any any", "root")
    check(seg is not None and "fw: bad rule" in seg, "bad direction refused")
    seg = sh(s, "fw add in deny tcp any any any 99999", "root")
    check(seg is not None and "fw: bad rule" in seg, "bad port refused")
    seg = sh(s, "fw add in deny tcp any any any 9000-8000", "root")
    check(seg is not None and "fw: bad rule" in seg, "inverted range refused")
    seg = sh(s, "fw add in deny tcp any any any", "root")
    check(seg is not None and "fw: bad rule" in seg, "short rule refused")
    seg = sh(s, "fw del 99", "root")
    check(seg is not None and "fw: no such rule 99" in seg, "del out of range refused")
    seg = sh(s, "fw", "root")
    check(seg is not None and "Usage: fw " in seg, "bare fw prints usage")
    seg = sh(s, "fw list", "root")
    check(seg is not None and "fw: no rules" in seg, "validation left no rules")
    # default deny, then allow. The pump ping needs an outbound
    # ICMP allow rule to reach its poll loop (default deny
    # would fail the send immediately, before any polling);
    # its own reply is still denied inbound, so it reports no
    # reply — the injected frame's fate is the proof.
    seg = sh(s, "fw default deny", "root")
    check(seg is not None and "fw: default deny" in seg, "default deny set")
    seg = sh(s, "fw add out allow icmp any any any any", "root")
    check(seg is not None and "fw: rule added" in seg, "default deny: pump enabler added")
    d0 = fw_drops(s, "root")
    peer.clear()
    peer.send(eth(peer.guest_mac, PEER_MAC, 0x0800, icmp_echo(GUEST_IP, PEER_IP, 0xF001, 3)))
    time.sleep(1.0)
    check(pump(s, "root", expect_reply=False), "pump poll runs (default deny)")
    time.sleep(0.5)
    check(not peer.guest_echo_reply_seen(0xF001, 3), "default deny: no guest reply")
    d1 = fw_drops(s, "root")
    check(d0 is not None and d1 is not None and d1 > d0, "default deny: drops up")
    seg = sh(s, "fw del 1", "root")
    check(seg is not None and "fw: rule deleted" in seg, "default deny: pump enabler removed")
    seg = sh(s, "fw default allow", "root")
    check(seg is not None and "fw: default allow" in seg, "default allow set")
    peer.clear()
    peer.send(eth(peer.guest_mac, PEER_MAC, 0x0800, icmp_echo(GUEST_IP, PEER_IP, 0xF001, 4)))
    time.sleep(1.0)
    check(pump(s, "root"), "pump ping replies (default allow)")
    time.sleep(0.5)
    check(peer.guest_echo_reply_seen(0xF001, 4), "default allow: guest reply arrives")
    # range + dst-IP matching
    seg = sh(s, "fw add in deny udp any any 192.168.99.10 8000-8100", "root")
    check(seg is not None and "fw: rule added" in seg, "add range+dst rule")
    d0 = fw_drops(s, "root")
    peer.send(eth(peer.guest_mac, PEER_MAC, 0x0800, udp_pkt(GUEST_IP, PEER_IP, 8005, 1234, b"FWTEST")))
    time.sleep(1.0)
    check(pump(s, "root"), "pump ping replies (range deny)")
    d1 = fw_drops(s, "root")
    check(d0 is not None and d1 is not None and d1 > d0, "range rule: 8005 denied")
    d0 = fw_drops(s, "root")
    peer.send(eth(peer.guest_mac, PEER_MAC, 0x0800, udp_pkt(GUEST_IP, PEER_IP, 8101, 1234, b"FWTEST")))
    time.sleep(1.0)
    check(pump(s, "root"), "pump ping replies (range allow)")
    d1 = fw_drops(s, "root")
    check(d0 is not None and d1 is not None and d1 == d0, "range rule: 8101 untouched")
    seg = sh(s, "fw clear", "root")
    check(seg is not None and "fw: rules cleared" in seg, "clear rules")
    seg = sh(s, "fw list", "root")
    check(seg is not None and "fw: no rules" in seg, "list empty after clear")
    seg = sh(s, "fw disable", "root")
    check(seg is not None and "fw: disabled" in seg, "disable")
    # persistence: 2 rules + enable, reboot, list + status
    seg = sh(s, "fw add in deny tcp any any any 80", "root")
    check(seg is not None and "fw: rule added" in seg, "persist: add tcp 80 deny")
    seg = sh(s, "fw add out deny udp any any any 53", "root")
    check(seg is not None and "fw: rule added" in seg, "persist: add udp 53 deny")
    seg = sh(s, "fw enable", "root")
    check(seg is not None and "fw: enabled" in seg, "persist: enable")
    send_text_verified(s, "reboot")
    check(wait_from("root@nxts> ", 60, "prompt after reboot"), "prompt after reboot")
    seg = sh(s, "dhcp", "root")
    check(seg is not None and "dhcp: configured" in seg, "dhcp after reboot")
    seg = sh(s, "fw list", "root")
    check(seg is not None and "1: in deny tcp any any any 80" in seg and "2: out deny udp any any any 53" in seg, "rules persist across reboot")
    seg = sh(s, "fw status", "root")
    check(seg is not None and "fw: enabled, default allow, 2 rules" in seg, "enabled state persists across reboot")
finally:
    if peer: peer.running = False
    stop(qemu, s)

# ---- Boot 2: malformed fw.txt ----
qemu, s = boot(MALFORMED)
try:
    peer = Peer()
    t = threading.Thread(target=peer.run, daemon=True); t.start()
    check(wait_from("root@nxts> ", 60, "boot 2 prompt"), "boot 2 prompt")
    seg = sh(s, "fw list", "root")
    check(seg is not None and "1: in deny tcp any any any 80" in seg and "2:" not in seg, "malformed lines skipped, good rule kept")
    seg = sh(s, "fw status", "root")
    check(seg is not None and "fw: enabled, default deny, 1 rules" in seg, "headers parsed from malformed file")
finally:
    if peer: peer.running = False
    stop(qemu, s)

# ---- Boot 3: non-root refusals + admin verification ----
qemu, s = boot(ADMIN)
try:
    peer = Peer()
    t = threading.Thread(target=peer.run, daemon=True); t.start()
    check(login(s, "alice", "pwalice"), "boot 3 login alice")
    seg = sh(s, "fw add in deny icmp any any any any", "alice")
    check(seg is not None and "fw: root only" in seg, "alice fw add refused")
    seg = sh(s, "fw enable", "alice")
    check(seg is not None and "fw: root only" in seg, "alice fw enable refused")
    seg = sh(s, "fw del 1", "alice")
    check(seg is not None and "fw: root only" in seg, "alice fw del refused")
    seg = sh(s, "fw clear", "alice")
    check(seg is not None and "fw: root only" in seg, "alice fw clear refused")
    seg = sh(s, "fw default deny", "alice")
    check(seg is not None and "fw: root only" in seg, "alice fw default refused")
    seg = sh(s, "fw list", "alice")
    check(seg is not None and "fw: no rules" in seg, "alice fw list readable")
    seg = sh(s, "fw status", "alice")
    check(seg is not None and "fw: disabled" in seg, "alice fw status readable")
    send_text(s, "logout")
    check(wait_from("Logged out.", 30, "alice logout"), "alice logout")
    check(login(s, "admin", "pwadmin"), "boot 3 login admin")
    seg = sh(s, "fw list", "admin")
    check(seg is not None and "fw: no rules" in seg, "admin proves no rules added")
    seg = sh(s, "fw status", "admin")
    check(seg is not None and "fw: disabled" in seg, "admin proves still disabled")
finally:
    if peer: peer.running = False
    stop(qemu, s)

print("CORE_FW TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
