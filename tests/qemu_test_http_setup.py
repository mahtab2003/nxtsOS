#!/usr/bin/env python3
"""Build the fixtures for tests/qemu_test_http.py (web/SSL
Phase 4: redirects, cookies, chunked encoding, header polish).

Only TLS fixtures are needed: the plain-HTTP peer is a raw
socket-netdev server (no certificates), and every HTTPS boot
uses TOFU (no disk: diskless TOFU proceeds without recording).

Chain (RSA-2048, 2-day validity):
  HTTP CA (CN=Test HTTP CA, CA:TRUE) ->
  RSA leaf (CN=http.test, SAN http.test + other.test).
  chain-http.pem = leaf + CA.
  The leaf covers other.test too because the HTTPS
  cross-host boot redirects to https://other.test/... and
  the guest's hostname check must (correctly) pass there;
  a cert covering only http.test would make that boot fail
  with a legitimate hostname refusal, not a redirect bug.

Usage: python3 tests/qemu_test_http_setup.py <workdir>
"""
import os
import subprocess
import sys

WORK = sys.argv[1]
os.makedirs(WORK, exist_ok=True)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        raise SystemExit(1)


EXT_SAN = os.path.join(WORK, "san.cnf")
open(EXT_SAN, "w").write("subjectAltName=DNS:http.test,DNS:other.test\n")

run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/http-ca-key.pem", "-out", f"{WORK}/http-ca-cert.pem",
     "-days", "2", "-nodes", "-subj", "/CN=Test HTTP CA",
     "-addext", "basicConstraints=critical,CA:TRUE"])
run(["openssl", "req", "-newkey", "rsa:2048",
     "-keyout", f"{WORK}/http-leaf-key.pem", "-out", f"{WORK}/http-leaf.csr",
     "-nodes", "-subj", "/CN=http.test",
     "-addext", "subjectAltName=DNS:http.test"])
run(["openssl", "x509", "-req", "-in", f"{WORK}/http-leaf.csr",
     "-CA", f"{WORK}/http-ca-cert.pem", "-CAkey", f"{WORK}/http-ca-key.pem",
     "-CAcreateserial", "-out", f"{WORK}/http-leaf-cert.pem", "-days", "2",
     "-extfile", EXT_SAN])
with open(f"{WORK}/chain-http.pem", "w") as f:
    f.write(open(f"{WORK}/http-leaf-cert.pem").read())
    f.write(open(f"{WORK}/http-ca-cert.pem").read())
print("HTTP test fixtures ready in", WORK)
