#!/usr/bin/env python3
"""Create an encrypted nxtsOS disk image, see docs/ENCRYPTION.md.
Usage: mkdisk_enc.py INPUT_FS_IMG OUTPUT_ENC_IMG --passphrase PASS
       [--salt HEX32] [--iterations 10000]
INPUT must be an unencrypted nxtsFS disk image (from tools/mkdisk.py).
OUTPUT is 512 bytes larger: a plaintext header sector, then the
filesystem encrypted with AES-256-CTR (OpenSSL, IV 0, key derived
below). The kernel's CTR counter for logical sector L, block B is
L*32+B as a big-endian 128-bit integer — exactly OpenSSL's CTR
counter starting from IV 0, so the kernel decrypts what OpenSSL
encrypts here.
Key derivation (must match kernel/enc.c exactly):
  h = SHA256(salt + passphrase)
  repeat 9999 times: h = SHA256(h + salt)   # 10000 hashes total
Key check: AES-256-ECB encryption of "NXTS-KEY-CHECK!!" with the key,
stored in the header. The passphrase itself is never stored.
The header salt is random unless --salt is given (for reproducible
test disks); the passphrase is never written to the output file.
Requires the `openssl` command. Lose the passphrase and the data
is lost — there is no recovery key in this version.
"""
import argparse, hashlib, os, subprocess, sys, tempfile

CHECK = b"NXTS-KEY-CHECK!!"

def fail(msg):
    sys.exit(f"mkdisk_enc: {msg}")

def run_openssl(args, inp=None):
    r = subprocess.run(["openssl"] + args, input=inp, capture_output=True)
    if r.returncode != 0:
        fail(f"openssl failed: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout

def main():
    p = argparse.ArgumentParser()
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--passphrase", required=True)
    p.add_argument("--salt", default=None, help="32 hex chars (16 bytes); random if omitted")
    p.add_argument("--iterations", type=int, default=10000)
    a = p.parse_args()
    if not (1 <= len(a.passphrase) <= 64):
        fail("passphrase must be 1..64 characters")
    if a.iterations < 1000 or a.iterations > 100000:
        fail("iterations must be 1000..100000")
    if a.salt is None:
        salt = os.urandom(16)
    else:
        try:
            salt = bytes.fromhex(a.salt)
        except ValueError:
            fail("bad --salt, expected 32 hex chars")
        if len(salt) != 16:
            fail("salt must be 16 bytes (32 hex chars)")
    fs = open(a.input, "rb").read()
    if len(fs) % 512 != 0 or len(fs) == 0:
        fail("input size must be a non-zero multiple of 512")
    if fs[:8] != b"NXTSFS01":
        fail("input is not an unencrypted nxtsFS disk (magic NXTSFS01 expected)")
    # Key derivation, matching kernel/enc.c.
    h = hashlib.sha256(salt + a.passphrase.encode()).digest()
    for _ in range(a.iterations - 1):
        h = hashlib.sha256(h + salt).digest()
    key = h
    keyhex = key.hex()
    # Key check via AES-256-ECB, single block, no padding.
    check = run_openssl(["enc", "-aes-256-ecb", "-K", keyhex, "-nopad"], inp=CHECK)
    if len(check) != 16:
        fail("key-check encryption produced the wrong length")
    # Encrypt the whole filesystem with AES-256-CTR, IV 0.
    with tempfile.TemporaryDirectory() as td:
        fs_path = os.path.join(td, "fs.img")
        enc_path = os.path.join(td, "fs_enc.img")
        open(fs_path, "wb").write(fs)
        r = subprocess.run(["openssl", "enc", "-aes-256-ctr", "-K", keyhex,
                            "-iv", "00" * 16, "-nopad", "-in", fs_path, "-out", enc_path],
                           capture_output=True)
        if r.returncode != 0:
            fail(f"openssl CTR failed: {r.stderr.decode(errors='replace')[:200]}")
        enc_fs = open(enc_path, "rb").read()
    if len(enc_fs) != len(fs):
        fail("encrypted filesystem length mismatch")
    header = bytearray(512)
    header[0:8] = b"NXTSENC1"
    header[8:12] = (1).to_bytes(4, "little")
    header[12:16] = a.iterations.to_bytes(4, "little")
    header[16:32] = salt
    header[32:48] = check
    with open(a.output, "wb") as f:
        f.write(header)
        f.write(enc_fs)
    print(f"Wrote {a.output}: encrypted disk, {len(fs)//512} FS sectors + header, "
          f"iterations {a.iterations} (passphrase NOT stored)")

if __name__ == "__main__":
    main()
