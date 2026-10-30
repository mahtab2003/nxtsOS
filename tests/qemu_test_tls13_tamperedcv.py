#!/usr/bin/env python3
"""Tampered-CertificateVerify negative test (raw TLS 1.3 peer, NOT
part of the main suite): a hand-rolled TLS 1.3 server sends a fully
valid flight except the server CertificateVerify signature is
tampered. The guest MUST refuse at CertificateVerify (stage 3:
stage 3 is set BEFORE CV verification, stage 4 only after it
passes) and must NOT fetch the body. If the guest fetches the
body for any variant, this test FAILS — that would be a forged
peer identity, a critical authentication bypass (STOP rule:
report, do not patch silently).

Variants (one boot each, port 12356), all TLS 1.3:
  pss-flip:             RSA leaf, PSS sig with one flipped byte.
  pss-wrong-transcript: RSA leaf, valid PSS sig over a blob whose
                        transcript hash has a flipped byte.
  pss-wrong-key:        RSA leaf presented, CV signed with
                        leaf2-key (a different RSA key for the
                        same host).
  pss-wrong-alg:        RSA leaf, PSS signature bytes declared
                        as alg 0x0401 (PKCS#1 v1.5).
  ecdsa-flip:           EC leaf, ECDSA sig with a flipped byte
                        in s (DER length unchanged, value
                        changed).
  ecdsa-wrong-transcript: EC leaf, valid ECDSA sig over the
                        wrong transcript hash.
TLS 1.2 / legacy have no server-CV verification point in this
client profile (1.2 parses Certificate -> ServerKeyExchange ->
ServerHelloDone -> Finished; legacy parses SH -> Certificate ->
ServerHelloDone -> Finished; the guest offers no client cert,
so the server never sends CV there) — CV tampering is a
TLS 1.3-only test by construction. The 1.2 analogue (SKE
signature) is already covered by tls_ske.
Run: python3 tests/qemu_test_tls13_tamperedcv.py <iso> <workdir>
Exit 0 on PASS (guest refused every variant), 1 otherwise.
"""
import hashlib
import hmac
import os
import re
import struct
import sys

sys.argv = ["x", sys.argv[1], sys.argv[2]]
os.chdir(os.path.expanduser("~/workspace/nxtsOS"))
sys.path.insert(0, "tests")
import tls_peer_lib as lib

ISO, WORK = sys.argv[1], sys.argv[2]
PORT = 12356

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509 as cx509


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


class Raw13CVPeer(lib.NetPeer):
    """Minimal TLS 1.3 server: valid flight except tampered CV."""

    def __init__(self, variant, listen_port, debug_path=None):
        self.variant = variant
        super().__init__(listen_port, debug_path=debug_path)
        self.buf = b""
        self.sent = False
        if variant.startswith("ecdsa"):
            leaf_cert, ca_cert, leaf_key = ("ec-leaf-cert.pem",
                                            "ec-ca-cert.pem",
                                            "ec-leaf-key.pem")
        else:
            leaf_cert, ca_cert, leaf_key = ("rsa-leaf-cert.pem",
                                            "rsa-ca-cert.pem",
                                            "rsa-leaf-key.pem")
        leaf_pem = open(os.path.join(WORK, leaf_cert), "rb").read()
        ca_pem = open(os.path.join(WORK, ca_cert), "rb").read()
        self.leaf_der = cx509.load_pem_x509_certificate(leaf_pem).public_bytes(
            serialization.Encoding.DER)
        self.ca_der = cx509.load_pem_x509_certificate(ca_pem).public_bytes(
            serialization.Encoding.DER)
        self.leaf_key = serialization.load_pem_private_key(
            open(os.path.join(WORK, leaf_key), "rb").read(), None)
        if variant == "pss-wrong-key":
            self.sign_key = serialization.load_pem_private_key(
                open(os.path.join(WORK, "leaf2-key.pem"), "rb").read(), None)
        else:
            self.sign_key = self.leaf_key

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
            self.log(f"RAW13CV error: {type(e).__name__}: {e}")

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
                pt = ed[6:6 + int.from_bytes(ed[4:6], "big")]
                client_pub = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(pt[1:33], "big"),
                    int.from_bytes(pt[33:65], "big"),
                    ec.SECP256R1()).public_key()
            pos += 4 + el
        assert client_pub is not None, "no client key_share"
        srv_priv = ec.generate_private_key(ec.SECP256R1())
        srv_pub = srv_priv.public_key().public_numbers()
        srv_point = b"\x04" + srv_pub.x.to_bytes(32, "big") + srv_pub.y.to_bytes(32, "big")
        shared = srv_priv.exchange(ec.ECDH(), client_pub)
        srv_random = os.urandom(32)
        sh_body = (b"\x03\x03" + srv_random + bytes([len(sid)]) + sid
                   + b"\x13\x01\x00")
        exts = b""
        exts += b"\x00\x2b\x00\x02\x03\x04"  # supported_versions
        ks_data = b"\x00\x17" + (65).to_bytes(2, "big") + srv_point
        exts += b"\x00\x33" + len(ks_data).to_bytes(2, "big") + ks_data
        sh_body += len(exts).to_bytes(2, "big") + exts
        sh_msg = hs_msg(2, sh_body)
        th_sh = hashlib.sha256(ch_msg + sh_msg).digest()
        early = hkdf_extract(b"\x00" * 32, b"\x00" * 32)
        derived = derive_secret(early, b"derived", hashlib.sha256(b"").digest())
        hs_secret = hkdf_extract(derived, shared)
        s_hs = derive_secret(hs_secret, b"s hs traffic", th_sh)
        s_key = expand_label(s_hs, b"key", b"", 16)
        s_iv = expand_label(s_hs, b"iv", b"", 12)
        out = record(22, sh_msg)
        ee_msg = hs_msg(8, b"\x00\x00")
        out += self._enc_record(s_key, s_iv, 0, ee_msg)
        cert_list = b""
        for der in (self.leaf_der, self.ca_der):
            cert_list += len(der).to_bytes(3, "big") + der + b"\x00\x00"
        cert_msg = hs_msg(11, b"\x00" + len(cert_list).to_bytes(3, "big") + cert_list)
        out += self._enc_record(s_key, s_iv, 1, cert_msg)
        # CertificateVerify, tampered per variant.
        th_cert = hashlib.sha256(ch_msg + sh_msg + ee_msg + cert_msg).digest()
        blob = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + th_cert
        v = self.variant
        if v.startswith("pss"):
            if v == "pss-wrong-transcript":
                th_wrong = bytes([th_cert[0] ^ 0xFF]) + th_cert[1:]
                blob_wrong = (b"\x20" * 64 + b"TLS 1.3, server CertificateVerify"
                              + b"\x00" + th_wrong)
                sig = self.sign_key.sign(blob_wrong, padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                    hashes.SHA256())
            else:
                sig = self.sign_key.sign(blob, padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                    hashes.SHA256())
            if v == "pss-flip":
                sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
            alg = b"\x04\x01" if v == "pss-wrong-alg" else b"\x08\x04"
        else:  # ecdsa
            if v == "ecdsa-wrong-transcript":
                th_wrong = bytes([th_cert[0] ^ 0xFF]) + th_cert[1:]
                blob_wrong = (b"\x20" * 64 + b"TLS 1.3, server CertificateVerify"
                              + b"\x00" + th_wrong)
                sig = self.sign_key.sign(blob_wrong, ec.ECDSA(hashes.SHA256()))
            else:
                sig = self.sign_key.sign(blob, ec.ECDSA(hashes.SHA256()))
            if v == "ecdsa-flip":
                # Flip the last byte of the DER sig: s changes value,
                # DER lengths stay valid, so this is a verify failure
                # (not a parse failure).
                sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
            alg = b"\x04\x03"
        cv_msg = hs_msg(15, alg + len(sig).to_bytes(2, "big") + sig)
        out += self._enc_record(s_key, s_iv, 2, cv_msg)
        # Finished: VALID over CH..CV as sent (guest refuses at CV
        # first, so this is never reached — sent for flight hygiene).
        fin_key = expand_label(s_hs, b"finished", b"", 32)
        th_cv = hashlib.sha256(ch_msg + sh_msg + ee_msg + cert_msg + cv_msg).digest()
        verify = hmac.new(fin_key, th_cv, hashlib.sha256).digest()
        fin_msg = hs_msg(20, verify)
        out += self._enc_record(s_key, s_iv, 3, fin_msg)
        self.send_queue += out
        self.maybe_send(src_mac)
        self.log(f"RAW13CV> sent SH + EE + Cert + TAMPERED CV ({v}) + Finished")


VARIANTS = [
    ("pss-flip", "tls13.test"),
    ("pss-wrong-transcript", "tls13.test"),
    ("pss-wrong-key", "tls13.test"),
    ("pss-wrong-alg", "tls13.test"),
    ("ecdsa-flip", "tls13ec.test"),
    ("ecdsa-wrong-transcript", "tls13ec.test"),
]


def main():
    import qemu_test_tls13 as t13
    t13.PORT = PORT
    for name in ("rsa-leaf-cert.pem", "rsa-ca-cert.pem", "rsa-leaf-key.pem",
                 "ec-leaf-cert.pem", "ec-ca-cert.pem", "ec-leaf-key.pem",
                 "leaf2-key.pem"):
        if not os.path.isfile(os.path.join(WORK, name)):
            print(f"missing fixture {name} — run "
                  "tests/qemu_test_tls13_setup.py <workdir> first")
            return 1
    all_ok = True
    # Short tags for run_boot ONLY: the QEMU monitor UNIX socket path
    # is capped at 108 bytes, and the regression workdir plus the full
    # "tls13-tamperedcv-<variant>-mon.sock" name exceeds it for the
    # two *-wrong-transcript variants (109/111 bytes), so QEMU refused
    # to start and the peer connection failed — a harness path-length
    # limit, not a kernel failure. Case names in results, serial logs
    # (via the short tag), peer debug logs, and every assertion below
    # are unchanged; only the socket filename is shortened.
    SHORT = {"pss-flip": "tcv-pf", "pss-wrong-transcript": "tcv-pwt",
             "pss-wrong-key": "tcv-pwk", "pss-wrong-alg": "tcv-pwa",
             "ecdsa-flip": "tcv-ef", "ecdsa-wrong-transcript": "tcv-ewt"}
    for variant, host in VARIANTS:
        def make_peer(v=variant):
            return Raw13CVPeer(v, PORT,
                               debug_path=os.path.join(WORK, f"tamperedcv-{v}.log"))
        ok, log, peer = t13.run_boot(
            SHORT[variant], make_peer, None,
            [(f"https {host} /", "tls13: handshake failed at stage 3", 60)])
        # Decisive marker: the guest must fail EXACTLY at CV
        # verification (stage 3). A later hang or a completed
        # handshake never shows stage 3, so this cannot false-pass
        # if the guest ignored the tampering.
        stage3 = "tls13: handshake failed at stage 3" in log
        got_bytes = re.search(r"https: \d+ bytes", log) is not None
        panics = any(m in log for m in ("EXCEPTION", "PANIC", "page fault"))
        passed = stage3 and not got_bytes and not panics
        print(f"tampered-cv {variant}: stage3={stage3} "
              f"got_bytes_line={got_bytes} panic={panics} -> "
              f"{'PASS' if passed else 'FAIL'}")
        if not passed:
            all_ok = False
    if all_ok:
        print("RESULT: PASS (guest refused every tampered CertificateVerify)")
        return 0
    print("RESULT: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
