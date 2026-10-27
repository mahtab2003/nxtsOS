# nxtsOS v0.6.0 — Release Manifest (Disk encryption — dedicated phase)

- Version: 0.6.0 (disk encryption, inserted between Phase 6 and Phase 7;
  later phase versions shift by one minor, Phase 7 graphics is now v0.7.0)
- Kernel binary: `build/nxtsOS.bin` (51,560 bytes)
- Bootable image: `build/nxtsOS.iso` (5,175,296 bytes, El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh` (now fails if kernel/main.c banner != VERSION)
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.6.0` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.6.0-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.6.0-dist.zip`
- Checksums: `releases/v0.6.0/SHA256SUMS`

## Implemented (v0.6.0)

- AES-256 encrypt (kernel/aes.c, S-box generated from GF(2^8)),
  CTR sector encryption (kernel/enc.c), ATA translation (logical L
  -> physical L+1, raw path for the header), boot passphrase prompt
  (no echo, 3 attempts then halt), 10000-round SHA-256 key derivation
  with per-disk salt, key-check via AES-ECB, host tool
  tools/mkdisk_enc.py (needs openssl), shell `aes-test`, docs/ENCRYPTION.md.

## NOT implemented (explicit)

Passphrase change, recovery key, authenticated encryption,
package signing, graphics, desktop, networking. See docs/ROADMAP.md
and releases/v0.6.0/SECURITY_REPORT.md.

## Remote publishing

NOT DONE. Muse GitHub App repository selection for mahtab2003/nxtsOS
is still pending; no push has been made.
