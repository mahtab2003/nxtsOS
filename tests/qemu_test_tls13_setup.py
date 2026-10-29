#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_tls13.py (web/SSL
Phase 2: TLS 1.3 client + ECDSA for TLS 1.2).

Usage: python3 tests/qemu_test_tls13_setup.py <workdir>

Chains (all SHA-256, 2-day validity unless noted):
  RSA CA (CN=Test TLS13 RSA CA, CA:TRUE, RSA-2048) ->
  RSA leaf (CN=tls13.test, SAN tls13.test).
  chain-rsa13.pem = leaf + CA.
  EC CA (CN=Test TLS13 EC CA, CA:TRUE, P-256) ->
  EC leaf (CN=tls13ec.test, SAN tls13ec.test).
  chain-ec13.pem = leaf + CA.
  wrong-host: RSA leaf with SAN wrong.test, signed by RSA CA.
  badsig: RSA leaf for tls13.test signed by CA2 (a different
  RSA CA); the presented chain pairs it with CA1 -> refused.
  leaf2: a second, different-key RSA leaf for tls13.test
  signed by RSA CA (TOFU fingerprint-mismatch case).
  expired: RSA leaf for tls13.test, validity entirely in the
  past (built with the cryptography package: openssl x509
  -req cannot set a past end date).
Store/anchor files: store-rsa.txt (RSA CA modulus),
store-ec.txt ("EC256:" + uncompressed EC CA point hex),
anchors-rsa.txt (RSA CA modulus, for tlsanchors.txt).
Disks (mkdisk.py): disk-store-rsa.img, disk-store-ec.img,
disk-anchor.img (tlsanchors.txt), disk-tofu.img (blank, for
the TOFU print file).
"""
import datetime
import os
import subprocess
import sys

WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
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
EXT_SAN_RSA = os.path.join(WORK, "san_rsa.cnf")
open(EXT_SAN_RSA, "w").write("subjectAltName=DNS:tls13.test\n")
EXT_SAN_EC = os.path.join(WORK, "san_ec.cnf")
open(EXT_SAN_EC, "w").write("subjectAltName=DNS:tls13ec.test\n")
EXT_SAN_WRONG = os.path.join(WORK, "san_wrong.cnf")
open(EXT_SAN_WRONG, "w").write("subjectAltName=DNS:wrong.test\n")

# RSA CA + leaf.
run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/rsa-ca-key.pem", "-out", f"{WORK}/rsa-ca-cert.pem",
     "-days", "2", "-nodes", "-subj", "/CN=Test TLS13 RSA CA",
     "-addext", "basicConstraints=critical,CA:TRUE"])
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/rsa-leaf-key.pem", "-out", f"{WORK}/rsa-leaf.csr",
     "-nodes", "-subj", "/CN=tls13.test",
     "-addext", "subjectAltName=DNS:tls13.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/rsa-leaf.csr",
     "-CA", f"{WORK}/rsa-ca-cert.pem", "-CAkey", f"{WORK}/rsa-ca-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/rsa-leaf-cert.pem", "-days", "2",
     "-extfile", EXT_SAN_RSA])
with open(f"{WORK}/chain-rsa13.pem", "w") as f:
    f.write(open(f"{WORK}/rsa-leaf-cert.pem").read())
    f.write(open(f"{WORK}/rsa-ca-cert.pem").read())

# EC CA + leaf (P-256).
run(["openssl", "req", "-x509", "-newkey", "ec",
     "-pkeyopt", "ec_paramgen_curve:P-256",
     "-keyout", f"{WORK}/ec-ca-key.pem", "-out", f"{WORK}/ec-ca-cert.pem",
     "-days", "2", "-nodes", "-subj", "/CN=Test TLS13 EC CA",
     "-addext", "basicConstraints=critical,CA:TRUE"])
run(["openssl", "req", "-newkey", "ec",
     "-pkeyopt", "ec_paramgen_curve:P-256",
     "-keyout", f"{WORK}/ec-leaf-key.pem", "-out", f"{WORK}/ec-leaf.csr",
     "-nodes", "-subj", "/CN=tls13ec.test",
     "-addext", "subjectAltName=DNS:tls13ec.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/ec-leaf.csr",
     "-CA", f"{WORK}/ec-ca-cert.pem", "-CAkey", f"{WORK}/ec-ca-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/ec-leaf-cert.pem", "-days", "2",
     "-extfile", EXT_SAN_EC])
with open(f"{WORK}/chain-ec13.pem", "w") as f:
    f.write(open(f"{WORK}/ec-leaf-cert.pem").read())
    f.write(open(f"{WORK}/ec-ca-cert.pem").read())

# Wrong-host RSA leaf (SAN wrong.test), signed by RSA CA.
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/wrong-leaf-key.pem", "-out", f"{WORK}/wrong-leaf.csr",
     "-nodes", "-subj", "/CN=wrong.test",
     "-addext", "subjectAltName=DNS:wrong.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/wrong-leaf.csr",
     "-CA", f"{WORK}/rsa-ca-cert.pem", "-CAkey", f"{WORK}/rsa-ca-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/wrong-leaf-cert.pem", "-days", "2",
     "-extfile", EXT_SAN_WRONG])
with open(f"{WORK}/chain-wrong.pem", "w") as f:
    f.write(open(f"{WORK}/wrong-leaf-cert.pem").read())
    f.write(open(f"{WORK}/rsa-ca-cert.pem").read())

# Badsig: CA2 + leaf signed by CA2, presented with CA1.
run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/ca2-key.pem", "-out", f"{WORK}/ca2-cert.pem",
     "-days", "2", "-nodes", "-subj", "/CN=Test TLS13 CA2",
     "-addext", "basicConstraints=critical,CA:TRUE"])
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/badsig-leaf-key.pem", "-out", f"{WORK}/badsig-leaf.csr",
     "-nodes", "-subj", "/CN=tls13.test",
     "-addext", "subjectAltName=DNS:tls13.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/badsig-leaf.csr",
     "-CA", f"{WORK}/ca2-cert.pem", "-CAkey", f"{WORK}/ca2-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/badsig-leaf-cert.pem", "-days", "2",
     "-extfile", EXT_SAN_RSA])
with open(f"{WORK}/chain-badsig13.pem", "w") as f:
    f.write(open(f"{WORK}/badsig-leaf-cert.pem").read())
    f.write(open(f"{WORK}/rsa-ca-cert.pem").read())

# Second-key RSA leaf for tls13.test (TOFU mismatch case).
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/leaf2-key.pem", "-out", f"{WORK}/leaf2.csr",
     "-nodes", "-subj", "/CN=tls13.test",
     "-addext", "subjectAltName=DNS:tls13.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/leaf2.csr",
     "-CA", f"{WORK}/rsa-ca-cert.pem", "-CAkey", f"{WORK}/rsa-ca-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/leaf2-cert.pem", "-days", "2",
     "-extfile", EXT_SAN_RSA])
with open(f"{WORK}/chain-rsa13-b.pem", "w") as f:
    f.write(open(f"{WORK}/leaf2-cert.pem").read())
    f.write(open(f"{WORK}/rsa-ca-cert.pem").read())

# Expired RSA leaf (validity entirely in the past) via cryptography.
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ca_cert = cx509.load_pem_x509_certificate(
    open(f"{WORK}/rsa-ca-cert.pem", "rb").read())
ca_key = serialization.load_pem_private_key(
    open(f"{WORK}/rsa-ca-key.pem", "rb").read(), password=None)
leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = datetime.datetime.now(datetime.timezone.utc)
builder = (cx509.CertificateBuilder()
           .subject_name(cx509.Name(
               [cx509.NameAttribute(NameOID.COMMON_NAME, "tls13.test")]))
           .issuer_name(ca_cert.subject)
           .public_key(leaf_key.public_key())
           .serial_number(cx509.random_serial_number())
           .not_valid_before(now - datetime.timedelta(days=2))
           .not_valid_after(now - datetime.timedelta(days=1))
           .add_extension(cx509.SubjectAlternativeName(
               [cx509.DNSName("tls13.test")]), critical=False))
expired = builder.sign(ca_key, hashes.SHA256())
open(f"{WORK}/expired-leaf-cert.pem", "wb").write(
    expired.public_bytes(serialization.Encoding.PEM))
open(f"{WORK}/expired-leaf-key.pem", "wb").write(
    leaf_key.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.TraditionalOpenSSL,
                           serialization.NoEncryption()))
with open(f"{WORK}/chain-expired.pem", "w") as f:
    f.write(open(f"{WORK}/expired-leaf-cert.pem").read())
    f.write(open(f"{WORK}/rsa-ca-cert.pem").read())

# Store / anchor files.
with open(f"{WORK}/store-rsa.txt", "w") as f:
    f.write(modhex(f"{WORK}/rsa-ca-cert.pem") + "\n")
with open(f"{WORK}/anchors-rsa.txt", "w") as f:
    f.write(modhex(f"{WORK}/rsa-ca-cert.pem") + "\n")
ec_ca = cx509.load_pem_x509_certificate(
    open(f"{WORK}/ec-ca-cert.pem", "rb").read())
nums = ec_ca.public_key().public_numbers()
with open(f"{WORK}/store-ec.txt", "w") as f:
    f.write("EC256:04%064x%064x\n" % (nums.x, nums.y))

# Disks.
with open(f"{WORK}/readme.txt", "w") as f:
    f.write("nxtsOS tls13 test disk\n")
for disk, adds in (
        ("disk-store-rsa.img", ["castore.txt:store-rsa.txt"]),
        ("disk-store-ec.img", ["castore.txt:store-ec.txt"]),
        ("disk-anchor.img", ["tlsanchors.txt:anchors-rsa.txt"]),
        ("disk-tofu.img", [])):
    args = ["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
            os.path.join(WORK, disk),
            "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}"]
    for a in adds:
        name, src = a.split(":")
        args += ["--add", f"{name}:{os.path.join(WORK, src)}"]
    run(args)
print("TLS13 test fixtures ready in", WORK)
