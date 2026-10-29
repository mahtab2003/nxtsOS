#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_legacy.py (web/SSL
Phase 3: TLS 1.1 + SSLv3 clients + SSLv2-Hello probe).

Usage: python3 tests/qemu_test_legacy_setup.py <workdir>

Chains (all RSA-2048, 2-day validity unless noted):
  Legacy CA (CN=Test Legacy CA, CA:TRUE, SHA-256) ->
  RSA leaf (CN=legacy.test, SAN legacy.test).
  chain-legacy.pem = leaf + CA.
  leaf2: a second, different-key RSA leaf for legacy.test
  signed by Legacy CA (TOFU fingerprint-mismatch case).
  wrong-host: RSA leaf with SAN wrong.test, signed by Legacy CA.
  badsig: RSA leaf for legacy.test signed by CA2 (a different
  RSA CA); the presented chain pairs it with CA1 -> refused.
  expired: RSA leaf for legacy.test, validity entirely in the
  past (built with the cryptography package: openssl x509
  -req cannot set a past end date).
  sha1: RSA leaf for legacy.test SIGNED WITH SHA-1 by Legacy
  CA (openssl with a SECLEVEL=0 config: cryptography 50 and
  openssl at the default level both refuse SHA-1 signing).
  The leaf's SHA-1 signature is what the legacy SHA-1 gate
  admits (legacy mode) and modern mode refuses at parsing.
Store/anchor files: store-legacy.txt (Legacy CA modulus),
anchors-legacy.txt (same, for tlsanchors.txt).
Disks (mkdisk.py): disk-legacy-store.img (castore.txt),
disk-legacy-anchor.img (tlsanchors.txt),
disk-legacy-tofu.img (blank, for the TOFU print file).
"""
import datetime
import os
import subprocess
import sys

WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(cmd, env=None):
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        raise SystemExit(1)


def modhex(cert):
    out = subprocess.run(["openssl", "x509", "-in", cert, "-modulus",
                          "-noout"], check=True, capture_output=True,
                         text=True).stdout
    return out.strip().split("=", 1)[1].strip().replace(":", "")


EXT_CA_TRUE = os.path.join(WORK, "ca_true.cnf")
open(EXT_CA_TRUE, "w").write("basicConstraints=critical,CA:TRUE\n")
EXT_SAN = os.path.join(WORK, "san.cnf")
open(EXT_SAN, "w").write("subjectAltName=DNS:legacy.test\n")
EXT_SAN_WRONG = os.path.join(WORK, "san_wrong.cnf")
open(EXT_SAN_WRONG, "w").write("subjectAltName=DNS:wrong.test\n")

# Legacy CA + leaf.
run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/legacy-ca-key.pem", "-out", f"{WORK}/legacy-ca-cert.pem",
     "-days", "2", "-nodes", "-subj", "/CN=Test Legacy CA",
     "-addext", "basicConstraints=critical,CA:TRUE"])
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/legacy-leaf-key.pem", "-out", f"{WORK}/legacy-leaf.csr",
     "-nodes", "-subj", "/CN=legacy.test",
     "-addext", "subjectAltName=DNS:legacy.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/legacy-leaf.csr",
     "-CA", f"{WORK}/legacy-ca-cert.pem", "-CAkey", f"{WORK}/legacy-ca-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/legacy-leaf-cert.pem", "-days", "2",
     "-extfile", EXT_SAN])
with open(f"{WORK}/chain-legacy.pem", "w") as f:
    f.write(open(f"{WORK}/legacy-leaf-cert.pem").read())
    f.write(open(f"{WORK}/legacy-ca-cert.pem").read())

# Second-key RSA leaf for legacy.test (TOFU mismatch case).
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/leaf2-key.pem", "-out", f"{WORK}/leaf2.csr",
     "-nodes", "-subj", "/CN=legacy.test",
     "-addext", "subjectAltName=DNS:legacy.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/leaf2.csr",
     "-CA", f"{WORK}/legacy-ca-cert.pem", "-CAkey", f"{WORK}/legacy-ca-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/leaf2-cert.pem", "-days", "2",
     "-extfile", EXT_SAN])
with open(f"{WORK}/chain-legacy-b.pem", "w") as f:
    f.write(open(f"{WORK}/leaf2-cert.pem").read())
    f.write(open(f"{WORK}/legacy-ca-cert.pem").read())

# Wrong-host RSA leaf (SAN wrong.test), signed by Legacy CA.
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/wrong-leaf-key.pem", "-out", f"{WORK}/wrong-leaf.csr",
     "-nodes", "-subj", "/CN=wrong.test",
     "-addext", "subjectAltName=DNS:wrong.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/wrong-leaf.csr",
     "-CA", f"{WORK}/legacy-ca-cert.pem", "-CAkey", f"{WORK}/legacy-ca-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/wrong-leaf-cert.pem", "-days", "2",
     "-extfile", EXT_SAN_WRONG])
with open(f"{WORK}/chain-legacy-wrong.pem", "w") as f:
    f.write(open(f"{WORK}/wrong-leaf-cert.pem").read())
    f.write(open(f"{WORK}/legacy-ca-cert.pem").read())

# Badsig: CA2 + leaf signed by CA2, presented with CA1.
run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/ca2-key.pem", "-out", f"{WORK}/ca2-cert.pem",
     "-days", "2", "-nodes", "-subj", "/CN=Test Legacy CA2",
     "-addext", "basicConstraints=critical,CA:TRUE"])
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/badsig-leaf-key.pem", "-out", f"{WORK}/badsig-leaf.csr",
     "-nodes", "-subj", "/CN=legacy.test",
     "-addext", "subjectAltName=DNS:legacy.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/badsig-leaf.csr",
     "-CA", f"{WORK}/ca2-cert.pem", "-CAkey", f"{WORK}/ca2-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/badsig-leaf-cert.pem", "-days", "2",
     "-extfile", EXT_SAN])
with open(f"{WORK}/chain-legacy-badsig.pem", "w") as f:
    f.write(open(f"{WORK}/badsig-leaf-cert.pem").read())
    f.write(open(f"{WORK}/legacy-ca-cert.pem").read())

# Expired + SHA-1 leaves via cryptography.
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ca_cert = cx509.load_pem_x509_certificate(
    open(f"{WORK}/legacy-ca-cert.pem", "rb").read())
ca_key = serialization.load_pem_private_key(
    open(f"{WORK}/legacy-ca-key.pem", "rb").read(), password=None)
now = datetime.datetime.now(datetime.timezone.utc)


def build_leaf(key, not_before, not_after, algo):
    return (cx509.CertificateBuilder()
            .subject_name(cx509.Name(
                [cx509.NameAttribute(NameOID.COMMON_NAME, "legacy.test")]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(cx509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(cx509.SubjectAlternativeName(
                [cx509.DNSName("legacy.test")]), critical=False)
            .sign(ca_key, algo))


expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expired = build_leaf(expired_key, now - datetime.timedelta(days=2),
                     now - datetime.timedelta(days=1), hashes.SHA256())
open(f"{WORK}/expired-leaf-cert.pem", "wb").write(
    expired.public_bytes(serialization.Encoding.PEM))
open(f"{WORK}/expired-leaf-key.pem", "wb").write(
    expired_key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))
with open(f"{WORK}/chain-legacy-expired.pem", "w") as f:
    f.write(open(f"{WORK}/expired-leaf-cert.pem").read())
    f.write(open(f"{WORK}/legacy-ca-cert.pem").read())

# SHA-1 leaf via openssl with a SECLEVEL=0 config: cryptography
# 50 refuses SHA-1 signatures entirely, and openssl at the
# default security level refuses SHA-1 signing too. The
# SECLEVEL=0 config re-enables it for fixture generation only.
with open(f"{WORK}/openssl0.cnf", "w") as f:
    f.write("openssl_conf = openssl_init\n[openssl_init]\n"
            "ssl_conf = ssl_sect\n[ssl_sect]\n"
            "system_default = system_default_sect\n"
            "[system_default_sect]\n"
            "CipherString = DEFAULT@SECLEVEL=0\n")
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/sha1-leaf-key.pem", "-out", f"{WORK}/sha1-leaf.csr",
     "-nodes", "-subj", "/CN=legacy.test",
     "-addext", "subjectAltName=DNS:legacy.test"])
env0 = dict(os.environ)
env0["OPENSSL_CONF"] = f"{WORK}/openssl0.cnf"
run(["openssl", "x509", "-req", "-in", f"{WORK}/sha1-leaf.csr",
     "-CA", f"{WORK}/legacy-ca-cert.pem", "-CAkey", f"{WORK}/legacy-ca-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/sha1-leaf-cert.pem", "-days", "2",
     "-sha1", "-extfile", EXT_SAN], env=env0)
with open(f"{WORK}/chain-legacy-sha1.pem", "w") as f:
    f.write(open(f"{WORK}/sha1-leaf-cert.pem").read())
    f.write(open(f"{WORK}/legacy-ca-cert.pem").read())

# Store / anchor files.
with open(f"{WORK}/store-legacy.txt", "w") as f:
    f.write(modhex(f"{WORK}/legacy-ca-cert.pem") + "\n")
with open(f"{WORK}/anchors-legacy.txt", "w") as f:
    f.write(modhex(f"{WORK}/legacy-ca-cert.pem") + "\n")

# Disks.
with open(f"{WORK}/readme.txt", "w") as f:
    f.write("nxtsOS legacy test disk\n")
for disk, adds in (
        ("disk-legacy-store.img", ["castore.txt:store-legacy.txt"]),
        ("disk-legacy-anchor.img", ["tlsanchors.txt:anchors-legacy.txt"]),
        ("disk-legacy-tofu.img", [])):
    args = ["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
            os.path.join(WORK, disk),
            "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"]
    for a in adds:
        name, src = a.split(":")
        args += ["--add", f"{name}:{os.path.join(WORK, src)}"]
    run(args)
print("Legacy test fixtures ready in", WORK)
