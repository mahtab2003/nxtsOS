#!/usr/bin/env python3
"""Wrapped-certificate-length negative test (raw TLS 1.3 peer).
Regression pin for the v1.1.3 der_tlv u32-wraparound fix: the server
sends a Certificate whose leaf DER is byte-identical to the valid
tls13 RSA leaf EXCEPT the subject Name length field is replaced by
the wrapped long-form value 0xFFFFFFF0 (with the outer and
tbsCertificate lengths recomputed to the true buffer size, so the
guest reaches the subject parse). The guest MUST refuse during
Certificate parsing ("tls13: handshake failed at stage 2") and must
NOT panic: pre-fix, der_tlv accepted the wrapped length and handed
verify_chain / parse_name_cn a ~4 GiB Name length (out-of-bounds
read -> kernel panic from a malicious server certificate).
Run: python3 tests/qemu_test_tls13_wrappedcert.py <iso> <workdir>
(needs the tls13 fixtures in <workdir>: run
tests/qemu_test_tls13_setup.py <workdir> first).
Exit 0 on PASS (guest refused at stage 2, no panic, no body), 1
otherwise.
"""
import hashlib
import hmac
import os
import struct
import sys

sys.argv = ["x", sys.argv[1], sys.argv[2]]
os.chdir(os.path.expanduser("~/workspace/nxtsOS"))
sys.path.insert(0, "tests")
import tls_peer_lib as lib

ISO, WORK = sys.argv[1], sys.argv[2]
PORT = 12354

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509 as cx509


def read_tlv(buf, pos):
    """Return (tag, hdr_len, val_len, val_pos, end). Raises on truncation."""
    tag = buf[pos]
    lb = buf[pos + 1]
    if lb < 0x80:
        hl, vl = 2, lb
    else:
        n = lb & 0x7F
        if n == 0 or n > 4:
            raise ValueError("bad long form")
        vl = int.from_bytes(buf[pos + 2:pos + 2 + n], "big")
        hl = 2 + n
    if pos + hl + vl > len(buf):
        raise ValueError("truncated tlv")
    return tag, hl, vl, pos + hl, pos + hl + vl


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def wrap_subject(der):
    """Return der with the subject Name length replaced by the wrapped
    value 0xFFFFFFF0. The tbsCertificate and outer SEQUENCE lengths
    are recomputed to the true buffer size, so the guest's outer/tbs
    checks pass and it reaches the subject parse (where the fixed
    der_tlv must refuse). The signature becomes invalid (tbs
    changed) but the guest refuses before signature verification,
    so that is irrelevant."""
    _, _, _, o_vp, o_end = read_tlv(der, 0)
    assert o_end == len(der), "outer SEQ"
    # tbsCertificate TLV starts at o_vp (its value holds the fields).
    _, _, _, t_vp, t_end = read_tlv(der, o_vp)
    assert t_end <= o_end, "tbs bounds"
    tbs_value = der[t_vp:t_end]
    rest = der[t_end:o_end]  # signatureAlgorithm + signatureValue
    fields = []
    pos = 0
    while pos < len(tbs_value):
        fields.append(read_tlv(tbs_value, pos))
        pos = fields[-1][4]
    assert pos == len(tbs_value), "tbs walk"
    i = 0
    if fields[0][0] == 0xA0:  # explicit [0] version
        i = 1
    assert fields[i][0] == 0x02, "serial"
    i += 1
    assert fields[i][0] == 0x30, "sig alg"
    i += 1
    assert fields[i][0] == 0x30, "issuer"
    i += 1
    assert fields[i][0] == 0x30, "validity"
    i += 1
    subj_tag, subj_hl, subj_vl, subj_vp, subj_end = fields[i]
    assert subj_tag == 0x30, "subject"
    subj_content = tbs_value[subj_vp:subj_end]
    wrapped_subject = b"\x30\x84\xff\xff\xff\xf0" + subj_content
    new_tbs_value = (tbs_value[:subj_vp - subj_hl] + wrapped_subject
                     + tbs_value[subj_end:])
    new_tbs_tlv = b"\x30" + der_len(len(new_tbs_value)) + new_tbs_value
    return (b"\x30" + der_len(len(new_tbs_tlv) + len(rest))
            + new_tbs_tlv + rest)


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, ln):
    out = b""
    t = b""
    ctr = 1
    while len(out) < ln:
        t = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256).digest()
        out += t
        ctr += 1
    return out[:ln]


def expand_label(secret, label, ctx, ln):
    full = b"tls13 " + label
    return hkdf_expand(secret, struct.pack(">H", ln) + bytes([len(full)])
                       + full + bytes([len(ctx)]) + ctx, ln)


def derive_secret(secret, label, thash):
    return expand_label(secret, label, thash, 32)


def hs_msg(mtype, body):
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body


def record(rtype, payload):
    return bytes([rtype]) + b"\x03\x03" + len(payload).to_bytes(2, "big") + payload


class Raw13Peer(lib.NetPeer):
    """Minimal TLS 1.3 server: valid flight except the leaf certificate
    carries a wrapped subject length. Copied from the tampered-Finished
    peer; only the leaf DER differs."""

    def __init__(self, listen_port, debug_path=None):
        super().__init__(listen_port, debug_path=debug_path)
        self.buf = b""
        self.sent = False
        leaf_pem = open(os.path.join(WORK, "rsa-leaf-cert.pem"), "rb").read()
        ca_pem = open(os.path.join(WORK, "rsa-ca-cert.pem"), "rb").read()
        leaf_der = cx509.load_pem_x509_certificate(leaf_pem).public_bytes(
            serialization.Encoding.DER)
        self.leaf_der = wrap_subject(leaf_der)
        self.ca_der = cx509.load_pem_x509_certificate(ca_pem).public_bytes(
            serialization.Encoding.DER)
        self.leaf_key = serialization.load_pem_private_key(
            open(os.path.join(WORK, "rsa-leaf-key.pem"), "rb").read(), None)

    def tls_new_connection(self):
        self.buf = b""
        self.sent = False

    def _enc_record(self, key, iv, seq, hs_payload):
        nonce = bytes(iv[:8]) + bytes(a ^ b for a, b in
                                       zip(iv[8:12], seq.to_bytes(4, "big")))
        pt = hs_payload + b"\x16"
        hdr = b"\x17\x03\x03" + (len(pt) + 16).to_bytes(2, "big")
        ct = AESGCM(key).encrypt(nonce, pt, hdr)
        return hdr + ct

    def tls_feed(self, src_mac, data):
        self.buf += data
        if self.sent:
            return
        # Parse records until we have a full ClientHello.
        pos = 0
        ch_msg = None
        while pos + 5 <= len(self.buf):
            typ = self.buf[pos]
            ln = int.from_bytes(self.buf[pos + 3:pos + 5], "big")
            if pos + 5 + ln > len(self.buf):
                break
            if typ == 22:
                ch_msg = self.buf[pos + 5:pos + 5 + ln]
                break
            pos += 5 + ln
        if ch_msg is None or ch_msg[0] != 1:
            return
        self.sent = True
        try:
            self._respond(src_mac, ch_msg)
        except Exception as e:
            self.log(f"WRAP13 error: {type(e).__name__}: {e}")

    def _respond(self, src_mac, ch_msg):
        body = ch_msg[4:]
        pos = 0
        pos += 2  # legacy_version
        client_random = body[pos:pos + 32]
        pos += 32
        sid_len = body[pos]
        pos += 1
        sid = body[pos:pos + sid_len]
        pos += sid_len
        suites_len = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2 + suites_len
        comp_len = body[pos]
        pos += 1 + comp_len
        ext_len = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        eend = pos + ext_len
        client_pub = None
        while pos + 4 <= eend:
            et = int.from_bytes(body[pos:pos + 2], "big")
            el = int.from_bytes(body[pos + 2:pos + 4], "big")
            ed = body[pos + 4:pos + 4 + el]
            if et == 51:
                # key_share: shares_len(2) + group(2) + klen(2) + point
                pt = ed[6:6 + int.from_bytes(ed[4:6], "big")]
                client_pub = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(pt[1:33], "big"),
                    int.from_bytes(pt[33:65], "big"),
                    ec.SECP256R1()).public_key()
            pos += 4 + el
        assert client_pub is not None, "no client key_share"
        # Server ECDHE + shared secret.
        srv_priv = ec.generate_private_key(ec.SECP256R1())
        srv_pub = srv_priv.public_key().public_numbers()
        srv_point = b"\x04" + srv_pub.x.to_bytes(32, "big") + srv_pub.y.to_bytes(32, "big")
        shared = srv_priv.exchange(ec.ECDH(), client_pub)
        # ServerHello.
        import os as _os
        srv_random = _os.urandom(32)
        sh_body = (b"\x03\x03" + srv_random + bytes([len(sid)]) + sid
                   + b"\x13\x01\x00")
        exts = b""
        exts += b"\x00\x2b\x00\x02\x03\x04"  # supported_versions
        # Server key_share: a SINGLE KeyShareEntry (69 bytes).
        ks_data = b"\x00\x17" + (65).to_bytes(2, "big") + srv_point
        exts += b"\x00\x33" + len(ks_data).to_bytes(2, "big") + ks_data
        sh_body += len(exts).to_bytes(2, "big") + exts
        sh_msg = hs_msg(2, sh_body)
        # Key schedule.
        th_sh = hashlib.sha256(ch_msg + sh_msg).digest()
        early = hkdf_extract(b"\x00" * 32, b"\x00" * 32)
        derived = derive_secret(early, b"derived", hashlib.sha256(b"").digest())
        hs_secret = hkdf_extract(derived, shared)
        s_hs = derive_secret(hs_secret, b"s hs traffic", th_sh)
        s_key = expand_label(s_hs, b"key", b"", 16)
        s_iv = expand_label(s_hs, b"iv", b"", 12)
        out = record(22, sh_msg)
        # EncryptedExtensions (empty).
        ee_msg = hs_msg(8, b"\x00\x00")
        out += self._enc_record(s_key, s_iv, 0, ee_msg)
        # Certificate (WRAPPED leaf + CA, empty per-cert extensions).
        # The guest must refuse while parsing this message (stage 2);
        # the CV + Finished below are never reached, but keeping the
        # flight complete costs nothing.
        cert_list = b""
        for der in (self.leaf_der, self.ca_der):
            cert_list += len(der).to_bytes(3, "big") + der + b"\x00\x00"
        cert_msg = hs_msg(11, b"\x00" + len(cert_list).to_bytes(3, "big") + cert_list)
        out += self._enc_record(s_key, s_iv, 1, cert_msg)
        # CertificateVerify (over CH..Cert incl. the wrapped cert).
        th_cert = hashlib.sha256(ch_msg + sh_msg + ee_msg + cert_msg).digest()
        blob = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + th_cert
        sig = self.leaf_key.sign(blob, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        cv_msg = hs_msg(15, b"\x08\x04" + len(sig).to_bytes(2, "big") + sig)
        out += self._enc_record(s_key, s_iv, 2, cv_msg)
        # Finished (valid; never reached).
        fin_key = expand_label(s_hs, b"finished", b"", 32)
        th_cv = hashlib.sha256(ch_msg + sh_msg + ee_msg + cert_msg + cv_msg).digest()
        verify = hmac.new(fin_key, th_cv, hashlib.sha256).digest()
        fin_msg = hs_msg(20, verify)
        out += self._enc_record(s_key, s_iv, 3, fin_msg)
        self.send_queue += out
        self.maybe_send(src_mac)
        self.log("WRAP13> sent SH + EE + Cert(wrapped leaf) + CV + Finished")


def make_peer():
    return Raw13Peer(PORT, debug_path=os.path.join(WORK, "wrappedcert-peer.log"))


def main():
    import qemu_test_tls13 as t13
    # run_boot starts QEMU on t13.PORT, so point it at our port
    # (the tampered test shares 12353 with tls13.py; we use our
    # own to avoid colliding with a concurrent tls13 run).
    t13.PORT = PORT
    for name in ("rsa-leaf-cert.pem", "rsa-ca-cert.pem", "rsa-leaf-key.pem"):
        if not os.path.isfile(os.path.join(WORK, name)):
            print(f"missing fixture {name} — run "
                  "tests/qemu_test_tls13_setup.py <workdir> first")
            return 1
    ok, log, peer = t13.run_boot(
        "wrapped-cert", make_peer, None,
        # Wait for the stage-2 print itself: if the guest refuses at
        # Certificate parsing this appears within seconds; if the guest
        # wrongly accepts the wrapped length it never appears (60 s
        # timeout, then the verdict below correctly FAILs).
        [("https tls13.test /", "tls13: handshake failed at stage 2", 60)])
    # Decisive marker: the guest must fail EXACTLY at Certificate
    # parsing (stage 2 = Certificate block, parse_cert refused).
    # A panic here would be the pre-fix vulnerability, so any
    # EXCEPTION/PANIC/page fault fails the test outright.
    stage2 = "tls13: handshake failed at stage 2" in log
    import re as _re
    got_bytes = _re.search(r"https: \d+ bytes", log) is not None
    panics = any(m in log for m in ("EXCEPTION", "PANIC", "page fault"))
    print(f"wrapped-cert: stage2={stage2} got_bytes_line={got_bytes} panic={panics}")
    if stage2 and not got_bytes and not panics:
        print("RESULT: PASS (guest refused wrapped-length certificate, no panic)")
        return 0
    print("RESULT: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
