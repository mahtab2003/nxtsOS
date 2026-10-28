#!/usr/bin/env python3
"""TOFU chain fix test (v1.1.0 real-device bug): the guest's TOFU
HTTPS client used to require the TERMINAL certificate to be
self-signed, so every real site (leaf + intermediate, root never
sent) was refused with "certificate refused". After the fix,
TOFU accepts a chain whose links all verify and whose terminal
is a real CA, while still refusing broken chains.

Reuses the socket-netdev peer harness from
qemu_test_tls_peer.py (imported, not copied): the peer's TCP
state machine relays guest bytes into a python ssl server,
which presents a leaf + intermediate chain (root withheld,
exactly like a real server).

Cases (one boot each; guest runs `dhcp` then `https <host> /`,
TOFU mode):
  chain-ok:      leaf SAN chain.test, signed by intermediate
                 (CA:true), signed by root (NOT sent) -> SUCCESS
                 (NXTS-TLS-OK, ALPN http/1.1).
  chain-badca:   same, but the intermediate carries CA:FALSE
                 -> certificate refused.
  chain-badsig:  leaf signed by key K1, but the presented
                 intermediate has the same subject with a
                 DIFFERENT key K2 (issuer name matches, the
                 signature cannot verify) -> refused.
  chain-wronghost: valid chain-ok chain, guest asks for
                 other.test instead of chain.test -> refused.
  chain-expired: leaf already expired at guest RTC time
                 (cryptography lib; skipped if unavailable)
                 -> refused.

Usage: qemu_test_tls_chain.py <iso> <workdir>
Exit 0 only if every case passes. Always terminates QEMU.
"""
import importlib.util
import os
import subprocess
import sys

ISO, WORK = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)

sys.argv = ["qemu_test_tls_peer.py", ISO, WORK]
spec = importlib.util.spec_from_file_location(
    "tls_peer", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "qemu_test_tls_peer.py"))
tls_peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls_peer)
tls_peer.ISO = ISO
tls_peer.WORK = WORK
tls_peer.LISTEN_PORT = 12349  # not the peer test's 12347

EXT_CA_TRUE = os.path.join(WORK, "ca_true.cnf")
EXT_CA_FALSE = os.path.join(WORK, "ca_false.cnf")
open(EXT_CA_TRUE, "w").write("basicConstraints=critical,CA:TRUE\n")
open(EXT_CA_FALSE, "w").write("basicConstraints=critical,CA:FALSE\n")


def run(cmd):
    subprocess.run(cmd, check=True, capture_output=True)


def req_newkey(subj, key, csr, san=None):
    cmd = ["openssl", "req", "-newkey", "rsa:2048", "-keyout", key,
           "-out", csr, "-nodes", "-subj", subj]
    if san:
        cmd += ["-addext", f"subjectAltName=DNS:{san}"]
    run(cmd)


def sign(csr, ca_crt, ca_key, out, ext=None):
    cmd = ["openssl", "x509", "-req", "-in", csr, "-CA", ca_crt,
           "-CAkey", ca_key, "-CAcreateserial", "-out", out, "-days", "2"]
    if ext:
        cmd += ["-extfile", ext]
    run(cmd)


def self_signed(subj, key, crt, san=None, ext=None):
    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", key, "-out", crt, "-days", "2",
           "-nodes", "-subj", subj]
    if san:
        cmd += ["-addext", f"subjectAltName=DNS:{san}"]
    if ext:
        # req -x509 takes -addext, not -extfile (openssl 3.0.13).
        cmd += ["-addext", open(ext).read().strip()]
    run(cmd)


def build_chain(tag, int_ext, leaf_signer_crt=None, leaf_signer_key=None):
    """Build root (withheld) -> intermediate -> leaf. Returns
    (chain_file, leaf_key). leaf_signer_* override which key
    signs the leaf (for the badsig case: same intermediate
    subject, different key)."""
    root_key, root_crt = f"{WORK}/{tag}-root.key", f"{WORK}/{tag}-root.crt"
    self_signed("/CN=ChainRoot", root_key, root_crt, ext=EXT_CA_TRUE)
    int_key, int_csr = f"{WORK}/{tag}-int.key", f"{WORK}/{tag}-int.csr"
    req_newkey("/CN=ChainInt", int_key, int_csr)
    int_crt = f"{WORK}/{tag}-int.crt"
    sign(int_csr, root_crt, root_key, int_crt, ext=int_ext)
    leaf_key, leaf_csr = f"{WORK}/{tag}-leaf.key", f"{WORK}/{tag}-leaf.csr"
    req_newkey("/CN=chain.test", leaf_key, leaf_csr, san="chain.test")
    leaf_crt = f"{WORK}/{tag}-leaf.crt"
    sign(leaf_csr, leaf_signer_crt or int_crt,
         leaf_signer_key or int_key, leaf_crt)
    chain = f"{WORK}/{tag}-chain.crt"
    with open(chain, "wb") as f:
        f.write(open(leaf_crt, "rb").read())
        f.write(open(int_crt, "rb").read())
    return chain, leaf_key


def build_expired():
    """Leaf whose validity already ended, via the cryptography
    lib (openssl req cannot backdate). Returns (chain, key) or
    None when the lib is unavailable."""
    try:
        from cryptography import x509 as cx
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
    except ImportError:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = cx.Name([cx.NameAttribute(NameOID.COMMON_NAME, "ChainRoot")])
    root = (cx.CertificateBuilder().subject_name(root_name)
            .issuer_name(root_name).public_key(root_key.public_key())
            .serial_number(cx.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(cx.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(root_key, hashes.SHA256()))
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    int_name = cx.Name([cx.NameAttribute(NameOID.COMMON_NAME, "ChainInt")])
    inter = (cx.CertificateBuilder().subject_name(int_name)
             .issuer_name(root_name).public_key(int_key.public_key())
             .serial_number(cx.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=2))
             .not_valid_after(now + datetime.timedelta(days=2))
             .add_extension(cx.BasicConstraints(ca=True, path_length=None),
                            critical=True)
             .sign(root_key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (cx.CertificateBuilder()
            .subject_name(cx.Name([cx.NameAttribute(NameOID.COMMON_NAME,
                                                    "chain.test")]))
            .issuer_name(int_name).public_key(leaf_key.public_key())
            .serial_number(cx.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now - datetime.timedelta(days=1))
            .add_extension(cx.SubjectAlternativeName(
                [cx.DNSName("chain.test")]), critical=False)
            .sign(int_key, hashes.SHA256()))
    chain = f"{WORK}/exp-chain.crt"
    leaf_key_pem = f"{WORK}/exp-leaf.key"
    with open(chain, "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
        f.write(inter.public_bytes(serialization.Encoding.PEM))
    with open(leaf_key_pem, "wb") as f:
        f.write(leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    return chain, leaf_key_pem


def main():
    cases = []
    chain, key = build_chain("ok", EXT_CA_TRUE)
    cases.append(("chain-ok", chain, key, [("chain.test", True)]))
    chain, key = build_chain("badca", EXT_CA_FALSE)
    cases.append(("chain-badca", chain, key, [("chain.test", False)]))
    # badsig: leaf signed by intA's key, presented intermediate
    # intB has the same subject but a different key.
    build_chain("badsigA", EXT_CA_TRUE)
    inta_key = f"{WORK}/badsigA-int.key"
    # Sign a fresh leaf with intA's key, but present intB's cert.
    leaf_key, leaf_csr = f"{WORK}/badsig-leaf.key", f"{WORK}/badsig-leaf.csr"
    req_newkey("/CN=chain.test", leaf_key, leaf_csr, san="chain.test")
    inta_crt = f"{WORK}/badsigA-int.crt"
    leaf_crt = f"{WORK}/badsig-leaf.crt"
    sign(leaf_csr, inta_crt, inta_key, leaf_crt)
    build_chain("badsigB", EXT_CA_TRUE)
    intb_crt = f"{WORK}/badsigB-int.crt"
    chain = f"{WORK}/badsig-chain.crt"
    with open(chain, "wb") as f:
        f.write(open(leaf_crt, "rb").read())
        f.write(open(intb_crt, "rb").read())
    cases.append(("chain-badsig", chain, leaf_key, [("chain.test", False)]))
    # wronghost reuses the valid ok chain, different hostname.
    chain, key = build_chain("wronghost", EXT_CA_TRUE)
    cases.append(("chain-wronghost", chain, key, [("other.test", False)]))
    exp = build_expired()
    if exp is not None:
        cases.append(("chain-expired", exp[0], exp[1],
                      [("chain.test", False)]))
    else:
        print("  chain-expired: SKIPPED (no cryptography lib)")
    all_ok = True
    for case_name, cert, key, fetches in cases:
        ok, _ = tls_peer.run_boot(case_name, cert, key, fetches)
        all_ok = all_ok and ok
        import time
        time.sleep(1)
    print("RESULT:", "PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
