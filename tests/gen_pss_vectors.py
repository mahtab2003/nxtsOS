#!/usr/bin/env python3
"""Generate RSA-PSS/SHA-256 test vectors for tests/host_pss.c.

The host test reads three files from /tmp (paths hardcoded in
host_pss.c): the RSA-2048 modulus, a PSS signature, and the
32-byte message digest the signature covers. No capture script
for these files existed in the repo, so the v1.1.4 regression
runner calls this generator before building/running host_pss.
The kernel verifier (rsa_verify_pss_sha256) takes the digest
itself as mHash, so the signature is made over the prehashed
digest with PSS/MGF1-SHA-256 and a 32-byte salt.
Usage: python3 tests/gen_pss_vectors.py
Writes /tmp/pss-mod.bin, /tmp/pss-sig.bin, /tmp/pss-hash.bin.
"""
import hashlib, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
msg = b"nxtsOS host PSS test vector"
digest = hashlib.sha256(msg).digest()
sig = key.sign(
    digest,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
    utils.Prehashed(hashes.SHA256()))
mod = key.public_key().public_numbers().n.to_bytes(256, "big")
for name, data in (("pss-mod.bin", mod), ("pss-sig.bin", sig),
                   ("pss-hash.bin", digest)):
    with open(os.path.join("/tmp", name), "wb") as f:
        f.write(data)
print(f"wrote mod={len(mod)} sig={len(sig)} hash={len(digest)}")
