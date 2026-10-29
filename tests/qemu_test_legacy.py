#!/usr/bin/env python3
"""web/SSL Phase 3 test: TLS 1.1 + SSLv3 clients + SSLv2-Hello probe.

Boots (guest runs `dhcp` first; peer is LegacyPeer below unless
noted). Port 12354 so this suite can run alongside the castore
(12352) and tls13 (12353) suites.

LegacyPeer is a hand-rolled TLS 1.1 / SSLv3 server built from
RFC 5246 / RFC 6101 text on hashlib/hmac/cryptography — it is
NOT the kernel's code, and it does NOT share the kernel's MD5 /
SHA-1 / AES implementations, so a kernel crypto bug fails the
handshake instead of being agreed with. (Residual shared risk:
record/hello framing, which is identical to the proven TLS 1.2
path except the version byte + suite list — see WEB_SSL.md.)
OpenSSL cannot serve TLS 1.1 in this sandbox (s_server -tls1_1
fails even with @SECLEVEL=1: tls_choose_sigalg finds no
suitable signature algorithm), so no real legacy server exists
here; the hand-rolled peer is the only option, and this is
stated honestly in the test report, not hidden.

Boots:
  legacy-tls11:         TLS 1.1, RSA chain, TOFU -> body fetched,
                        peer negotiated TLSv1.1 / 0x002F, premaster
                        version 0x0302.
  legacy-ssl3:          SSLv3, RSA chain, TOFU -> body fetched,
                        peer negotiated SSLv3 / 0x002F, premaster
                        version 0x0300.
  legacy-sha1:          TLS 1.1, SHA-1-signed leaf, TOFU -> body
                        fetched (the SHA-1 gate opens in legacy).
  legacy-sha1-default:  same SHA-1 chain, DEFAULT mode (SslPeer
                        TLS 1.2) -> certificate refused (the gate
                        stays shut in modern mode).
  legacy-default-refuses: legacy-only peer, DEFAULT mode ->
                        https: failed, no body, peer saw a modern
                        hello (no silent downgrade).
  legacy-modern-refused: modern ServerHello, LEGACY mode ->
                        "legacy: refused ServerHello version 3.3"
                        + https: failed (no silent upgrade).
  legacy-expired / legacy-wronghost / legacy-badsig: TLS 1.1
                        with expired / wrong-host / bad-signature
                        chains -> certificate refused.
  legacy-tampered:      TLS 1.1 peer with a flipped server
                        Finished -> https: failed, no body.
  legacy-store:         TLS 1.1, store mode (castore.txt holds
                        the Legacy CA modulus) -> fetched.
  legacy-anchored:      TLS 1.1, anchored mode (tlsanchors.txt
                        holds the Legacy CA modulus) -> fetched.
  legacy-tofu-mismatch: disk-backed TOFU: first fetch accepts
                        and pins, second fetch with a different
                        leaf for the same host -> refused.
  legacy-flag-consumed: legacy fetch OK, then a DEFAULT fetch
                        to the same legacy peer -> https: failed
                        (the single-use flag did not leak).
  sslprobe-ssl2:        SSLv2 SERVER_HELLO reply ->
                        "sslprobe: SSLv2 SERVER_HELLO".
  sslprobe-tls:         TLS ServerHello reply ->
                        "sslprobe: TLS ServerHello version 3.3".
  sslprobe-alert:       TLS alert reply -> "sslprobe: TLS alert".
  sslprobe-silent:      silent peer -> "sslprobe: no reply".
  sslprobe-group:       `net sslprobe` (group dispatch) -> same
                        TLS ServerHello classification.

Usage: python3 tests/qemu_test_legacy.py <iso> <workdir>
<workdir> is created by tests/qemu_test_legacy_setup.py.
"""
import hashlib
import hmac
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tls_peer_lib as lib
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ISO = sys.argv[1]
WORK = sys.argv[2]
PORT = 12354


def _pem_ders(path):
    text = open(path, "rb").read()
    ders = []
    while b"-----BEGIN CERTIFICATE-----" in text:
        start = text.index(b"-----BEGIN CERTIFICATE-----")
        end = text.index(b"-----END CERTIFICATE-----", start)
        end += len(b"-----END CERTIFICATE-----")
        cert = cx509.load_pem_x509_certificate(text[start:end])
        ders.append(cert.public_bytes(serialization.Encoding.DER))
        text = text[end:]
    return ders


def _p_hash(hashfn, secret, label_seed, n):
    out = b""
    a = hmac.new(secret, label_seed, hashfn).digest()
    while len(out) < n:
        out += hmac.new(secret, a + label_seed, hashfn).digest()
        a = hmac.new(secret, a, hashfn).digest()
    return out[:n]


def _tls11_prf(secret, label, seed, n):
    half = (len(secret) + 1) // 2
    s1, s2 = secret[:half], secret[len(secret) - half:]
    ls = label + seed
    p1 = _p_hash(hashlib.md5, s1, ls, n)
    p2 = _p_hash(hashlib.sha1, s2, ls, n)
    return bytes(x ^ y for x, y in zip(p1, p2))


def _ssl3_master(premaster, cr, sr):
    out = b""
    for label in (b"A", b"BB", b"CCC"):
        out += hashlib.md5(
            premaster + hashlib.sha1(label + premaster + cr + sr).digest()
        ).digest()
    return out


def _ssl3_keyblock(master, sr, cr, n):
    out = b""
    i = 0
    while len(out) < n:
        label = bytes([ord("A") + i]) * (i + 1)
        out += hashlib.md5(
            master + hashlib.sha1(label + master + sr + cr).digest()
        ).digest()
        i += 1
    return out[:n]


def _ssl3_finished(master, transcript, sender):
    pad1 = b"\x36" * 48
    inner_md5 = hashlib.md5(transcript + sender + master + pad1).digest()
    inner_sha1 = hashlib.sha1(transcript + sender + master + pad1).digest()
    return (hashlib.md5(master + pad1 + inner_md5).digest()
            + hashlib.sha1(master + pad1 + inner_sha1).digest())


def _cbc_encrypt(key, iv, data):
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _cbc_decrypt(key, iv, data):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


class LegacyPeer(lib.NetPeer):
    """Hand-rolled TLS 1.1 (0x0302) / SSLv3 (0x0300) server."""

    def __init__(self, chain_files, routes, listen_port, version=0x0302,
                 tamper_finished=False, debug_path=None):
        self.chain_files = chain_files
        self.routes = routes
        self.version = version
        self.tamper_finished = tamper_finished
        self.conn_count = 0
        self.negotiated = []
        self.errors = []
        self.saw_modern_hello = False
        self.premaster_versions = []
        self.offered = []
        super().__init__(listen_port, debug_path)

    def tls_reset(self):
        self.in_buf = b""
        self.hs_stream = b""
        self.transcript = b""
        self.state = "hello"
        self.app_buf = b""
        self.responded = False
        self.send_seq = 0
        self.recv_seq = 0
        self.guest_enc = False
        self.peer_enc = False
        self.client_random = None
        self.server_random = None
        self.master = None
        self.c_key = self.s_key = None
        self.c_mac = self.s_mac = None
        self.send_iv = self.recv_iv = None
        self.chain = None
        self.leaf_key = None

    def tls_new_connection(self):
        idx = min(self.conn_count, len(self.chain_files) - 1)
        self.conn_count += 1
        cert_pem, key_pem = self.chain_files[idx]
        self.chain = _pem_ders(cert_pem)
        self.leaf_key = serialization.load_pem_private_key(
            open(key_pem, "rb").read(), password=None)

    def _send_record(self, src_mac, rtype, payload, encrypt):
        ver = self.version
        if encrypt:
            if ver == 0x0302:
                mac = hmac.new(
                    self.s_mac,
                    self.send_seq.to_bytes(8, "big") + bytes([rtype])
                    + ver.to_bytes(2, "big") + len(payload).to_bytes(2, "big")
                    + payload, hashlib.sha1).digest()
            else:
                inner = hashlib.sha1(
                    self.s_mac + b"\x36" * 48
                    + self.send_seq.to_bytes(8, "big") + bytes([rtype])
                    + len(payload).to_bytes(2, "big") + payload).digest()
                mac = hashlib.sha1(self.s_mac + b"\x5c" * 48 + inner).digest()
            total = len(payload) + 20
            pad_len = (15 - (total % 16)) % 16
            plain = payload + mac + bytes([pad_len]) * (pad_len + 1)
            if ver == 0x0302:
                iv = os.urandom(16)
                body = iv + _cbc_encrypt(self.s_key, iv, plain)
            else:
                body = _cbc_encrypt(self.s_key, self.send_iv, plain)
                self.send_iv = body[-16:]
            self.send_seq += 1
        else:
            body = payload
        rec = (bytes([rtype]) + ver.to_bytes(2, "big")
               + len(body).to_bytes(2, "big") + body)
        self.send_queue += rec
        self.maybe_send(src_mac)

    def _send_hs(self, src_mac, mtype, body, encrypt=False):
        msg = bytes([mtype]) + len(body).to_bytes(3, "big") + body
        self.transcript += msg
        self._send_record(src_mac, 22, msg, encrypt)

    def tls_feed(self, src_mac, data):
        self.in_buf += data
        self._pump(src_mac)

    def _pump(self, src_mac):
        while len(self.in_buf) >= 5:
            rtype = self.in_buf[0]
            ln = int.from_bytes(self.in_buf[3:5], "big")
            if len(self.in_buf) < 5 + ln:
                return
            payload = self.in_buf[5:5 + ln]
            self.in_buf = self.in_buf[5 + ln:]
            if self.guest_enc:
                if rtype not in (22, 23):
                    self.errors.append(f"encrypted record type {rtype}")
                    return
                if self.version == 0x0302:
                    if ln < 32:
                        self.errors.append("short tls11 record")
                        return
                    iv, ct = payload[:16], payload[16:]
                else:
                    iv, ct = self.recv_iv, payload
                if not ct or len(ct) % 16:
                    self.errors.append("bad ciphertext length")
                    return
                plain = _cbc_decrypt(self.c_key, iv, ct)
                if self.version == 0x0300:
                    self.recv_iv = payload[-16:]
                pad_len = plain[-1]
                if pad_len + 1 + 20 > len(plain):
                    self.errors.append("bad padding")
                    return
                frag = plain[:len(plain) - pad_len - 1 - 20]
                mac = plain[len(frag):len(frag) + 20]
                if self.version == 0x0302:
                    for i in range(pad_len + 1):
                        if plain[len(plain) - 1 - i] != pad_len:
                            self.errors.append("bad tls padding bytes")
                            return
                    expect = hmac.new(
                        self.c_mac,
                        self.recv_seq.to_bytes(8, "big") + bytes([rtype])
                        + self.version.to_bytes(2, "big")
                        + len(frag).to_bytes(2, "big") + frag,
                        hashlib.sha1).digest()
                else:
                    inner = hashlib.sha1(
                        self.c_mac + b"\x36" * 48
                        + self.recv_seq.to_bytes(8, "big") + bytes([rtype])
                        + len(frag).to_bytes(2, "big") + frag).digest()
                    expect = hashlib.sha1(
                        self.c_mac + b"\x5c" * 48 + inner).digest()
                if mac != expect:
                    self.errors.append("mac failure")
                    return
                self.recv_seq += 1
                payload = frag
            self._handle_record(src_mac, rtype, payload)

    def _handle_record(self, src_mac, rtype, payload):
        if rtype == 20:
            if payload != b"\x01":
                self.errors.append("bad ccs")
                return
            if self.state == "cke":
                self.guest_enc = True
            return
        if rtype == 21:
            self.errors.append("guest alert")
            return
        if rtype == 22:
            self.hs_stream += payload
            self._pump_hs(src_mac)
            return
        if rtype == 23:
            if self.state != "app":
                self.errors.append("app data before handshake done")
                return
            self.app_buf += payload
            if b"\r\n\r\n" in self.app_buf and not self.responded:
                self._respond(src_mac)
            return
        self.errors.append(f"record type {rtype}")

    def _pump_hs(self, src_mac):
        while len(self.hs_stream) >= 4:
            mtype = self.hs_stream[0]
            blen = int.from_bytes(self.hs_stream[1:4], "big")
            if len(self.hs_stream) < 4 + blen:
                return
            msg = self.hs_stream[:4 + blen]
            self.hs_stream = self.hs_stream[4 + blen:]
            self._handle_hs(src_mac, mtype, msg)

    def _handle_hs(self, src_mac, mtype, msg):
        body = msg[4:]
        if self.state == "hello":
            if mtype != 1:
                self.errors.append(f"expected ClientHello, got {mtype}")
                return
            ver = int.from_bytes(body[0:2], "big")
            if ver != 0x0302:
                self.saw_modern_hello = True
                rec = bytes([21, 0x03, 0x03, 0, 2, 0x02, 0x28])
                self.send_queue += rec
                self.maybe_send(src_mac)
                self.state = "dead"
                return
            self.client_random = body[2:34]
            pos = 34
            sid_len = body[pos]
            pos += 1 + sid_len
            cs_len = int.from_bytes(body[pos:pos + 2], "big")
            pos += 2
            suites = [int.from_bytes(body[pos + i:pos + i + 2], "big")
                      for i in range(0, cs_len, 2)]
            pos += cs_len
            comp_len = body[pos]
            pos += 1 + comp_len
            has_ext = pos != len(body)
            self.offered.append((ver, suites, has_ext))
            self.transcript += msg
            self.server_random = os.urandom(32)
            sh = (self.version.to_bytes(2, "big") + self.server_random
                  + bytes([0, 0x00, 0x2F, 0]))
            self._send_hs(src_mac, 2, sh)
            cert_body = b""
            for der in self.chain:
                cert_body += len(der).to_bytes(3, "big") + der
            cert_body = len(cert_body).to_bytes(3, "big") + cert_body
            self._send_hs(src_mac, 11, cert_body)
            self._send_hs(src_mac, 14, b"")
            self.negotiated.append(
                ("TLSv1.1" if self.version == 0x0302 else "SSLv3", "0x002f"))
            self.state = "cke"
            return
        if self.state == "cke":
            if mtype == 16:
                clen = int.from_bytes(body[0:2], "big")
                ct = body[2:2 + clen]
                try:
                    from cryptography.hazmat.primitives.asymmetric import padding as _pad
                    premaster = self.leaf_key.decrypt(ct, _pad.PKCS1v15())
                except Exception as e:
                    self.errors.append(f"premaster decrypt failed: {e}")
                    return
                if len(premaster) != 48:
                    self.errors.append("bad premaster length")
                    return
                self.premaster_versions.append(premaster[:2])
                self.transcript += msg
                cr, sr = self.client_random, self.server_random
                if self.version == 0x0302:
                    self.master = _tls11_prf(
                        premaster, b"master secret", cr + sr, 48)
                    kb = _tls11_prf(self.master, b"key expansion", sr + cr, 72)
                    self.c_mac, self.s_mac = kb[0:20], kb[20:40]
                    self.c_key, self.s_key = kb[40:56], kb[56:72]
                else:
                    self.master = _ssl3_master(premaster, cr, sr)
                    kb = _ssl3_keyblock(self.master, sr, cr, 104)
                    self.c_mac, self.s_mac = kb[0:20], kb[20:40]
                    self.c_key, self.s_key = kb[40:56], kb[56:72]
                    # Key-block layout after the keys is client
                    # IV then server IV. This peer is the SERVER:
                    # it SENDS with the server IV and RECEIVES
                    # (decrypts) with the client IV.
                    self.send_iv, self.recv_iv = kb[88:104], kb[72:88]
                return
            if mtype == 20:
                if self.version == 0x0302:
                    expect = _tls11_prf(
                        self.master, b"client finished",
                        hashlib.md5(self.transcript).digest()
                        + hashlib.sha1(self.transcript).digest(), 12)
                else:
                    expect = _ssl3_finished(self.master, self.transcript, b"CLNT")
                if body != expect:
                    self.errors.append("client Finished mismatch")
                    return
                self.transcript += msg
                if self.version == 0x0302:
                    srv_fin = _tls11_prf(
                        self.master, b"server finished",
                        hashlib.md5(self.transcript).digest()
                        + hashlib.sha1(self.transcript).digest(), 12)
                else:
                    srv_fin = _ssl3_finished(self.master, self.transcript, b"SRVR")
                if self.tamper_finished:
                    srv_fin = bytes([srv_fin[0] ^ 0xFF]) + srv_fin[1:]
                self._send_record(src_mac, 20, b"\x01", False)
                self.peer_enc = True
                self._send_hs(src_mac, 20, srv_fin, encrypt=True)
                self.state = "app"
                return
            self.errors.append(f"unexpected hs {mtype} in cke state")
            return
        if self.state == "app":
            self.errors.append(f"unexpected hs {mtype} in app state")
            return
        # state "dead": ignore everything.

    def _respond(self, src_mac):
        self.responded = True
        try:
            line = self.app_buf.split(b"\r\n", 1)[0].decode("latin1")
            path = line.split(" ")[1]
        except Exception:
            path = "/"
        body = self.routes.get(path, b"NXTS-LEGACY-404")
        resp = (b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n"
                % len(body)) + body
        self._send_record(src_mac, 23, resp, True)


class RawPeer(lib.NetPeer):
    """Canned-reply peer: on first app bytes, sends one canned
    reply, then stays silent. Modes: modern-sh, probe-ssl2,
    probe-tls, probe-alert, probe-silent."""

    def __init__(self, mode, listen_port, cert_der=None, debug_path=None):
        self.mode = mode
        self.sent = False
        self.cert_der = cert_der
        super().__init__(listen_port, debug_path)

    def tls_reset(self):
        self.sent = False

    def tls_feed(self, src_mac, data):
        if self.sent:
            return
        self.sent = True
        if self.mode == "modern-sh" or self.mode == "probe-tls":
            body = bytes([0x03, 0x03]) + os.urandom(32) + bytes([0, 0x00, 0x9C, 0])
            msg = bytes([2]) + len(body).to_bytes(3, "big") + body
            rec = bytes([22, 0x03, 0x03]) + len(msg).to_bytes(2, "big") + msg
        elif self.mode == "probe-ssl2":
            cert = self.cert_der or b"\x00" * 64
            cs = bytes([0x07, 0x00, 0xC0])
            conn = os.urandom(16)
            rest = (bytes([0, 1]) + bytes([0x02, 0x00])
                    + len(cert).to_bytes(2, "big") + len(cs).to_bytes(2, "big")
                    + len(conn).to_bytes(2, "big") + cert + cs + conn)
            payload = bytes([0x04]) + rest
            rec = bytes([0x80 | (len(payload) >> 8), len(payload) & 0xFF]) + payload
        elif self.mode == "probe-alert":
            rec = bytes([21, 0x03, 0x03, 0, 2, 0x02, 0x28])
        elif self.mode == "probe-silent":
            return
        else:
            return
        self.send_queue += rec
        self.maybe_send(src_mac)


def run_boot(tag, make_peer, disk_src, script):
    serial = os.path.join(WORK, f"legacy-{tag}-serial.log")
    mon = os.path.join(WORK, f"legacy-{tag}-mon.sock")
    disk = None
    if disk_src:
        disk = os.path.join(WORK, f"legacy-{tag}.img")
        shutil.copy(disk_src, disk)
    for p in (serial, mon):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    qemu = lib.start_qemu(ISO, serial, mon, disk, listen_port=PORT)
    peer = None
    ok = True
    try:
        peer = make_peer()
        threading.Thread(target=peer.run, daemon=True).start()
        ok &= lib.wait_mon(mon)
        ok &= lib.wait_prompt(serial, "root@nxts> ", 60)
        s = lib.connect_mon(mon)

        def send_text(txt):
            def type_cmd(t):
                for ch in t:
                    s.sendall(f"sendkey {lib.KEYMAP_REPO.get(ch, ch)}\n".encode())
                    time.sleep(0.15)
                s.sendall(b"sendkey ret\n")
                time.sleep(1)

            before = len(lib.log_text(serial))
            type_cmd(txt)
            for _ in range(150):
                fresh = lib.log_text(serial)[before:]
                if f"root@nxts> {txt}" in fresh:
                    return
                if fresh.count("root@nxts> ") >= 1:
                    break
                time.sleep(0.1)
            if f"root@nxts> {txt}" not in lib.log_text(serial)[before:]:
                before2 = len(lib.log_text(serial))
                type_cmd(txt)
                for _ in range(150):
                    if f"root@nxts> {txt}" in lib.log_text(serial)[before2:]:
                        break
                    time.sleep(0.1)

        send_text("dhcp")
        for cmd, marker, timeout in script:
            send_text(cmd)
            if marker:
                ok &= lib.wait_for(serial, lambda t, m=marker: m in t,
                                   timeout, f"{tag} {marker}")
        time.sleep(1)
        s.close()
    finally:
        if peer is not None:
            peer.running = False
        qemu.terminate()
        try:
            qemu.wait(timeout=10)
        except subprocess.TimeoutExpired:
            qemu.kill()
    log = lib.log_text(serial)
    for m in ("EXCEPTION", "PANIC", "page fault"):
        if m in log:
            print(f"  {tag}: FORBIDDEN marker present: {m}")
            ok = False
    for e in getattr(peer, "ssl_errors", []) + getattr(peer, "errors", []):
        print(f"  {tag}: peer error: {e}")
        ok = False
    return ok, log, peer


def legacy_peer(chains, marker, version=0x0302, tamper=False):
    return LegacyPeer(chains, {"/": marker}, PORT,
                      version=version, tamper_finished=tamper)


def ssl_peer(chains, marker, seclevel0=False):
    return lib.SslPeer(chains, {"/": marker}, PORT,
                       min_version=ssl.TLSVersion.TLSv1_2,
                       max_version=ssl.TLSVersion.TLSv1_2,
                       seclevel0=seclevel0)


def check(tag, ok, log, peer, want_body=None, want_absent=(),
          want_version=None, want_premaster=None, want_modern_hello=False,
          want_present=(), want_count=None):
    if want_version is not None:
        got = getattr(peer, "negotiated", [])
        if not got or got[0] != want_version:
            print(f"  {tag}: negotiated {got}, want {want_version}")
            ok = False
        else:
            print(f"  {tag}: negotiated {got[0][0]} {got[0][1]}")
    if want_premaster is not None:
        got = getattr(peer, "premaster_versions", [])
        if not got or got[0] != want_premaster:
            print(f"  {tag}: premaster version {got}, want {want_premaster}")
            ok = False
        else:
            print(f"  {tag}: premaster version {got[0].hex()}")
    if want_modern_hello and not getattr(peer, "saw_modern_hello", False):
        print(f"  {tag}: peer did not see a modern hello")
        ok = False
    if want_body is not None and want_body not in log:
        print(f"  {tag}: body marker missing: {want_body}")
        ok = False
    for a in want_present:
        if a not in log:
            print(f"  {tag}: required marker missing: {a}")
            ok = False
    if want_count is not None:
        marker, count = want_count
        got_count = log.count(marker)
        if got_count != count:
            print(f"  {tag}: marker {marker!r} appears {got_count}x, want {count}x")
            ok = False
    for a in want_absent:
        if a in log:
            print(f"  {tag}: unexpected present: {a}")
            ok = False
    print(f"  {tag}: {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    need = ["chain-legacy.pem", "legacy-leaf-key.pem",
            "chain-legacy-b.pem", "leaf2-key.pem",
            "chain-legacy-wrong.pem", "wrong-leaf-key.pem",
            "chain-legacy-badsig.pem", "badsig-leaf-key.pem",
            "chain-legacy-expired.pem", "expired-leaf-key.pem",
            "chain-legacy-sha1.pem", "sha1-leaf-key.pem",
            "disk-legacy-store.img", "disk-legacy-anchor.img",
            "disk-legacy-tofu.img"]
    for name in need:
        if not os.path.isfile(os.path.join(WORK, name)):
            print(f"missing fixture {name} — run "
                  "tests/qemu_test_legacy_setup.py first")
            return 1
    results = []

    def W(p):
        return os.path.join(WORK, p)

    LEG = (W("chain-legacy.pem"), W("legacy-leaf-key.pem"))
    LEGB = (W("chain-legacy-b.pem"), W("leaf2-key.pem"))
    SHA1 = (W("chain-legacy-sha1.pem"), W("sha1-leaf-key.pem"))

    # 1. TLS 1.1, RSA chain, TOFU.
    ok, log, p = run_boot(
        "tls11", lambda: legacy_peer([LEG], b"NXTS-LEGACY-TLS11-OK"),
        None, [("https --legacy legacy.test /", "NXTS-LEGACY-TLS11-OK", 90)])
    results.append(check("tls11", ok, log, p, want_version=("TLSv1.1", "0x002f"),
                         want_premaster=bytes([0x03, 0x02]),
                         want_body="NXTS-LEGACY-TLS11-OK",
                         want_absent=("certificate refused", "https: failed")))

    # 2. SSLv3, RSA chain, TOFU.
    ok, log, p = run_boot(
        "ssl3", lambda: legacy_peer([LEG], b"NXTS-LEGACY-SSL3-OK", version=0x0300),
        None, [("https --legacy legacy.test /", "NXTS-LEGACY-SSL3-OK", 90)])
    results.append(check("ssl3", ok, log, p, want_version=("SSLv3", "0x002f"),
                         want_premaster=bytes([0x03, 0x00]),
                         want_body="NXTS-LEGACY-SSL3-OK",
                         want_absent=("certificate refused", "https: failed")))

    # 3. TLS 1.1, SHA-1-signed leaf (gate opens in legacy mode).
    ok, log, p = run_boot(
        "sha1", lambda: legacy_peer([SHA1], b"NXTS-LEGACY-SHA1-OK"),
        None, [("https --legacy legacy.test /", "NXTS-LEGACY-SHA1-OK", 90)])
    results.append(check("sha1", ok, log, p, want_version=("TLSv1.1", "0x002f"),
                         want_body="NXTS-LEGACY-SHA1-OK",
                         want_absent=("certificate refused", "https: failed")))

    # 4. Same SHA-1 chain, DEFAULT mode -> certificate refused.
    # seclevel0: the peer must be allowed to LOAD the SHA-1
    # chain at all (OpenSSL refuses at default level).
    ok, log, p = run_boot(
        "sha1-default", lambda: ssl_peer([SHA1], b"NXTS-LEGACY-XXX", seclevel0=True),
        None, [("https legacy.test /", "https: certificate refused", 90)])
    results.append(check("sha1-default", ok, log, p,
                         want_absent=("NXTS-LEGACY-XXX",)))

    # 5. Legacy-only peer, DEFAULT mode -> failed, no downgrade.
    ok, log, p = run_boot(
        "default-refuses", lambda: legacy_peer([LEG], b"NXTS-LEGACY-XXX"),
        None, [("https legacy.test /", "https: failed", 90)])
    results.append(check("default-refuses", ok, log, p,
                         want_modern_hello=True,
                         want_absent=("NXTS-LEGACY-XXX", "certificate refused")))

    # 6. Modern ServerHello, LEGACY mode -> refused, no upgrade.
    ok, log, p = run_boot(
        "modern-refused", lambda: RawPeer("modern-sh", PORT),
        None, [("https --legacy legacy.test /",
                "legacy: refused ServerHello version 3.3", 90)])
    results.append(check("modern-refused", ok, log, p,
                         want_present=("https: failed",),
                         want_absent=("NXTS-LEGACY-XXX",)))

    # 7-9. Legacy negatives: expired / wrong-host / bad-sig.
    for tag, chain, key in (
            ("expired", "chain-legacy-expired.pem", "expired-leaf-key.pem"),
            ("wronghost", "chain-legacy-wrong.pem", "wrong-leaf-key.pem"),
            ("badsig", "chain-legacy-badsig.pem", "badsig-leaf-key.pem")):
        ok, log, p = run_boot(
            tag, lambda: legacy_peer([(W(chain), W(key))], b"NXTS-LEGACY-XXX"),
            None, [("https --legacy legacy.test /",
                    "https: certificate refused", 90)])
        results.append(check(tag, ok, log, p,
                             want_absent=("NXTS-LEGACY-XXX",)))

    # 10. Tampered server Finished (TLS 1.1).
    ok, log, p = run_boot(
        "tampered", lambda: legacy_peer([LEG], b"NXTS-LEGACY-XXX", tamper=True),
        None, [("https --legacy legacy.test /", "https: failed", 90)])
    results.append(check("tampered", ok, log, p,
                         want_absent=("NXTS-LEGACY-XXX", "certificate refused")))

    # 11. TLS 1.1, store mode.
    ok, log, p = run_boot(
        "store", lambda: legacy_peer([LEG], b"NXTS-LEGACY-STORE-OK"),
        W("disk-legacy-store.img"),
        [("httpss --legacy legacy.test /", "NXTS-LEGACY-STORE-OK", 90)])
    results.append(check("store", ok, log, p, want_version=("TLSv1.1", "0x002f"),
                         want_body="NXTS-LEGACY-STORE-OK",
                         want_absent=("httpss: failed",)))

    # 12. TLS 1.1, anchored mode.
    ok, log, p = run_boot(
        "anchored", lambda: legacy_peer([LEG], b"NXTS-LEGACY-ANCHOR-OK"),
        W("disk-legacy-anchor.img"),
        [("httpsa --legacy legacy.test /", "NXTS-LEGACY-ANCHOR-OK", 90)])
    results.append(check("anchored", ok, log, p, want_version=("TLSv1.1", "0x002f"),
                         want_body="NXTS-LEGACY-ANCHOR-OK",
                         want_absent=("httpsa: failed",)))

    # 13. TOFU fingerprint mismatch (disk-backed).
    ok, log, p = run_boot(
        "tofu-mismatch", lambda: legacy_peer([LEG, LEGB], b"NXTS-LEGACY-TLS11-OK"),
        W("disk-legacy-tofu.img"),
        [("https --legacy legacy.test /", "NXTS-LEGACY-TLS11-OK", 90),
         ("https --legacy legacy.test /", "https: certificate refused", 90)])
    results.append(check("tofu-mismatch", ok, log, p,
                         want_version=("TLSv1.1", "0x002f"),
                         want_body="NXTS-LEGACY-TLS11-OK"))

    # 14. Flag consumption: legacy OK, then default to the same
    # legacy peer must fail (a leaked flag would fetch the body).
    # NOTE: this harness family double-types every command (the
    # echo check breaks on the echo's own prompt, then retypes),
    # so a global body COUNT is meaningless here. The proof is
    # positional instead: after the LAST prompt of the default
    # fetch, the body must be absent and "https: failed" present.
    ok, log, p = run_boot(
        "flag-consumed", lambda: legacy_peer([LEG], b"NXTS-LEGACY-TLS11-OK"),
        None, [("https --legacy legacy.test /", "NXTS-LEGACY-TLS11-OK", 90),
               ("https legacy.test /", "https: failed", 90)])
    tail = log.split("root@nxts> https legacy.test /")[-1]
    if "NXTS-LEGACY-TLS11-OK" in tail:
        print("  flag-consumed: body leaked into the default fetch")
        ok = False
    if "https: failed" not in tail:
        print("  flag-consumed: default fetch did not fail")
        ok = False
    results.append(check("flag-consumed", ok, log, p,
                         want_body="NXTS-LEGACY-TLS11-OK"))

    # 15-19. sslprobe classifications.
    leaf_der = _pem_ders(W("chain-legacy.pem"))[0]
    for tag, mode, cmd, marker in (
            ("probe-ssl2", "probe-ssl2", "sslprobe legacy.test",
             "sslprobe: SSLv2 SERVER_HELLO (server speaks SSLv2)"),
            ("probe-tls", "probe-tls", "sslprobe legacy.test",
             "sslprobe: TLS ServerHello version 3.3"),
            ("probe-alert", "probe-alert", "sslprobe legacy.test",
             "sslprobe: TLS alert"),
            ("probe-silent", "probe-silent", "sslprobe legacy.test",
             "sslprobe: no reply (timeout or closed)"),
            ("probe-group", "probe-tls", "net sslprobe legacy.test",
             "sslprobe: TLS ServerHello version 3.3")):
        ok, log, p = run_boot(
            tag, lambda: RawPeer(mode, PORT, cert_der=leaf_der),
            None, [(cmd, marker, 60)])
        results.append(check(tag, ok, log, p))

    print(f"LEGACY: {sum(results)}/{len(results)} PASS")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
