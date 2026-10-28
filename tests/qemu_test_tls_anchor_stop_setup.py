#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_tls_anchor_stop.py.
Usage: python3 tests/qemu_test_tls_anchor_stop_setup.py <workdir>
Requires build/calc.nxpkg, build/sysinfo.nxpkg and
build/signing.key (from scripts/build.sh).
Creates: repo_anchor_stop_v1 (index v1: calc 1.0, sysinfo 1.0),
a 4096-bit root CA -> 2048-bit intermediate anchor CA ->
leaf for repo.test chain (chain3.pem = leaf + intermediate +
root, exactly the shape of the live Vercel chain: the anchor
is the middle cert, a 4096-bit root trails it), a badsig
variant (leaf signed by a different key under the same
intermediate subject), an expired-leaf variant when the
cryptography lib is available, tlsanchors.txt holding the
intermediate's RSA modulus, wronganchors.txt holding an
unrelated modulus, and disk-good.img / disk-wrong.img
carrying the respective anchor file for the guest.
"""
import os, subprocess, sys
WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.path.join(ROOT, "build", "signing.key")

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr); raise SystemExit(1)

def modhex(cert):
    out = subprocess.run(["openssl", "x509", "-in", cert, "-modulus",
                          "-noout"], check=True, capture_output=True,
                         text=True).stdout
    return out.strip().split("=", 1)[1].strip()

pkgs = [os.path.join(ROOT, "build", n) for n in
        ("calc.nxpkg", "sysinfo.nxpkg")]
for p in pkgs:
    if not os.path.isfile(p):
        print(f"missing {p} — run scripts/build.sh first"); raise SystemExit(1)
run(["python3", os.path.join(ROOT, "tools", "mkrepo.py"),
     "--key", KEY, "--out", os.path.join(WORK, "repo_anchor_stop_v1"),
     "--version", "1"] + pkgs)
EXT_CA_TRUE = os.path.join(WORK, "ca_true.cnf")
open(EXT_CA_TRUE, "w").write("basicConstraints=critical,CA:TRUE\n")
# 4096-bit root (trailing cert, mimics GTS Root R1).
run(["openssl", "req", "-x509", "-newkey", "rsa:4096",
     "-keyout", f"{WORK}/root-key.pem", "-out", f"{WORK}/root-cert.pem",
     "-days", "2", "-nodes", "-subj", "/CN=Test Root 4096",
     "-addext", "basicConstraints=critical,CA:TRUE"])
# 2048-bit intermediate anchor, signed by the root.
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/int-key.pem", "-out", f"{WORK}/int.csr",
     "-nodes", "-subj", "/CN=Test Anchor CA"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/int.csr",
     "-CA", f"{WORK}/root-cert.pem", "-CAkey", f"{WORK}/root-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/int-cert.pem", "-days", "2",
     "-extfile", EXT_CA_TRUE])
# Leaf for repo.test, signed by the intermediate.
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/leaf-key.pem", "-out", f"{WORK}/leaf.csr",
     "-nodes", "-subj", "/CN=repo.test",
     "-addext", "subjectAltName=DNS:repo.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/leaf.csr",
     "-CA", f"{WORK}/int-cert.pem", "-CAkey", f"{WORK}/int-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/leaf-cert.pem", "-days", "2"])
with open(f"{WORK}/chain3.pem", "w") as f:
    f.write(open(f"{WORK}/leaf-cert.pem").read())
    f.write(open(f"{WORK}/int-cert.pem").read())
    f.write(open(f"{WORK}/root-cert.pem").read())
# Badsig: leaf signed by intB (same subject, different key),
# presented intermediate is the pinned int (signature fails).
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/intB-key.pem", "-out", f"{WORK}/intB.csr",
     "-nodes", "-subj", "/CN=Test Anchor CA"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/intB.csr",
     "-CA", f"{WORK}/root-cert.pem", "-CAkey", f"{WORK}/root-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/intB-cert.pem", "-days", "2",
     "-extfile", EXT_CA_TRUE])
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/badsig-leaf-key.pem",
     "-out", f"{WORK}/badsig-leaf.csr",
     "-nodes", "-subj", "/CN=repo.test",
     "-addext", "subjectAltName=DNS:repo.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/badsig-leaf.csr",
     "-CA", f"{WORK}/intB-cert.pem", "-CAkey", f"{WORK}/intB-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/badsig-leaf-cert.pem",
     "-days", "2"])
with open(f"{WORK}/badsig-chain.pem", "w") as f:
    f.write(open(f"{WORK}/badsig-leaf-cert.pem").read())
    f.write(open(f"{WORK}/int-cert.pem").read())
    f.write(open(f"{WORK}/root-cert.pem").read())
# Expired leaf (cryptography lib only; openssl cannot backdate).
try:
    from cryptography import x509 as cx
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    import datetime
    int_key = serialization.load_pem_private_key(
        open(f"{WORK}/int-key.pem", "rb").read(), password=None)
    int_crt = cx.load_pem_x509_certificate(
        open(f"{WORK}/int-cert.pem", "rb").read())
    now = datetime.datetime.now(datetime.timezone.utc)
    exp_key_pem = f"{WORK}/exp-leaf-key.pem"
    run(["openssl", "genrsa", "-out", exp_key_pem, "2048"])
    exp_key = serialization.load_pem_private_key(
        open(exp_key_pem, "rb").read(), password=None)
    leaf = (cx.CertificateBuilder()
            .subject_name(cx.Name([cx.NameAttribute(
                NameOID.COMMON_NAME, "repo.test")]))
            .issuer_name(int_crt.subject)
            .public_key(exp_key.public_key())
            .serial_number(cx.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now - datetime.timedelta(days=1))
            .add_extension(cx.SubjectAlternativeName(
                [cx.DNSName("repo.test")]), critical=False)
            .sign(int_key, hashes.SHA256()))
    with open(f"{WORK}/exp-chain.pem", "w") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM).decode())
        f.write(open(f"{WORK}/int-cert.pem").read())
        f.write(open(f"{WORK}/root-cert.pem").read())
    print("expired-leaf fixture built")
except ImportError:
    print("cryptography lib unavailable: expired-leaf case will skip")
with open(f"{WORK}/tlsanchors.txt", "w") as f:
    f.write(modhex(f"{WORK}/int-cert.pem") + "\n")
run(["openssl", "genrsa", "-out", f"{WORK}/wrong-key.pem", "2048"])
wrong_mod = subprocess.run(["openssl", "rsa", "-in",
                            f"{WORK}/wrong-key.pem", "-modulus", "-noout"],
                           check=True, capture_output=True,
                           text=True).stdout
with open(f"{WORK}/wronganchors.txt", "w") as f:
    f.write(wrong_mod.strip().split("=", 1)[1].strip() + "\n")
with open(f"{WORK}/readme.txt", "w") as f:
    f.write("nxtsOS anchor-stop test disk\n")
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk-good.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}",
     "--add", f"tlsanchors.txt:{os.path.join(WORK, 'tlsanchors.txt')}"])
run(["python3", os.path.join(ROOT, "tools", "mkdisk.py"),
     os.path.join(WORK, "disk-wrong.img"),
     "--add", f"readme.txt:{os.path.join(WORK, 'readme.txt')}",
     "--add", f"tlsanchors.txt:{os.path.join(WORK, 'wronganchors.txt')}"])
print("Anchor-stop test fixtures ready in", WORK)
