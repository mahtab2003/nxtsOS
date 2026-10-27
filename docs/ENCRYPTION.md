# nxtsOS disk encryption (v0.6.0)

## What it is

Real sector encryption, not a toy: AES-256 in CTR mode, one key per
disk, derived from a boot passphrase. It is transparent to the
filesystem, packages, users, and sessions — they see the same logical
sectors as before, and the ATA layer encrypts/decrypts underneath.

## Disk format

```
Physical sector 0 (plaintext header, 512 bytes):
  0-7:   "NXTSENC1"
  8-11:  version, u32 LE = 1
  12-15: iteration count, u32 LE = 10000
  16-31: salt, 16 bytes, random per disk
  32-47: key-check ciphertext (see below)
  48-511: zero (reserved)
Physical sectors 1..: encrypted filesystem, logical sector L at
  physical L+1. Total disk size = filesystem size + 512 bytes.
```

Unencrypted disks are unchanged: sector 0 is "NXTSFS01" and the kernel
boots with no passphrase prompt. An encrypted disk is detected by its
header magic, and the kernel prompts before mounting anything.

## Key derivation and verification

```
key = SHA256(salt + passphrase)
repeat 9999 times: key = SHA256(key + salt)   # 10000 hashes total
```

The salt is stored in the header, so the same passphrase on two disks
gives different keys. The passphrase itself is never stored.

Verification: the header stores the AES-256-ECB encryption of the
16-byte known plaintext "NXTS-KEY-CHECK!!" under the derived key.
At boot, the kernel derives the key from the entered passphrase,
encrypts the same plaintext, and compares. A match unlocks the disk;
a mismatch is a wrong passphrase. Three wrong attempts halt the
system (same rate-limiting idea as the login brute-force halt:
rebooting resets the counter, so this is not a lockout, it is a
per-boot attempt limit).

## CTR mode, exactly

For logical sector L, block B (0..31, 16 bytes each):

```
counter = L*32 + B, as a 128-bit big-endian integer
keystream = AES-256-encrypt(counter)
ciphertext_block = plaintext_block XOR keystream
```

Decryption is the same operation (CTR). This matches OpenSSL
`aes-256-ctr` with IV 0, which is what `tools/mkdisk_enc.py` uses to
create encrypted disks — proven by the QEMU tests, which boot a
disk encrypted on the host and read every file correctly. Counters
never repeat within a disk (L and B are unique), and keys differ
per disk (salt), so CTR nonce reuse is not an issue.

AES itself is AES-256 encrypt only (CTR needs no decrypt function),
with the S-box generated at runtime from GF(2^8) arithmetic. The
shell command `aes-test` prints the FIPS 197 vector
(key 000102...1f, plaintext 001122...ff -> 8ea2b7ca...60089) so the
implementation can be checked without any disk.

## Creating an encrypted disk

```
# 1. Create a normal disk with mkdisk.py (users, files, packages).
python3 tools/mkdisk.py plain.img --add users.txt:users.txt ...
# 2. Encrypt it (needs the `openssl` command).
python3 tools/mkdisk_enc.py plain.img enc.img --passphrase 'your-passphrase'
# 3. Boot QEMU with enc.img. At boot:
#    Encrypted disk detected.
#    Disk passphrase: <type the passphrase, no echo>
#    Disk unlocked.
```

## What is NOT implemented, stated plainly

- **No passphrase change.** Changing a passphrase would require
  re-encrypting the whole disk under a new key. The supported path
  is: create a new encrypted disk with the new passphrase (from
  the plain disk, if you still have it) and copy the files over.
- **No recovery key, no backdoor.** Lose the passphrase and the
  data is lost. There is no "forgot passphrase" flow, and adding
  one would be a security decision, not a bug fix.
- **No authenticated encryption.** CTR gives confidentiality, not
  integrity: a flipped ciphertext bit flips the corresponding
  plaintext bit, and the kernel will notice only if the corrupted
  plaintext breaks a check (superblock magic, file hash, package
  hash — all of which are tested). An attacker who can write to
  the raw disk can corrupt data, but cannot read it or forge a
  valid package/file hash without the key.
- **No protection against offline brute force beyond the work
  factor.** The header salt + key check lets an attacker with the
  disk try passphrases offline, at 10000 SHA-256 rounds per guess.
  A weak passphrase (e.g. "password") is guessable — use a strong
  one. A memory-hard KDF (Argon2/bcrypt) would raise the cost, and
  is a Phase 11 hardening item, same as the password hash.
- **Header tampering is detected, not recovered.** Flipping the
  key-check ciphertext makes every passphrase fail, by design.
- **Performance:** CTR encryption is per sector, on every read and
  write. On QEMU it is fast enough for the test suite; no benchmark
  is claimed for real hardware.
