#ifndef NXTS_ENC_H
#define NXTS_ENC_H
#include "common.h"
/* Disk encryption (v0.6.0, docs/ENCRYPTION.md).
   AES-256-CTR, sector level, transparent to the filesystem:
   - Physical sector 0 is a plaintext header ("NXTSENC1", version,
     iterations, 16-byte salt, 16-byte key-check ciphertext).
   - Physical sectors 1.. are the encrypted filesystem, logical
     sector L at physical L+1, CTR counter = L*32 + block index
     (big-endian 128-bit, starting from 0 — matching OpenSSL
     aes-256-ctr with IV 0, which tools/mkdisk_enc.py uses).
   - Unencrypted disks (sector 0 = "NXTSFS01") boot unchanged, with
     no passphrase prompt. No disk at all also boots unchanged.
   - The passphrase is prompted at boot (no echo, 3 attempts, then
     halt). There is no passphrase change and no recovery: lose the
     passphrase and the data is lost — that is stated, not hidden. */
int  enc_unlock(void); /* 0 ok / no disk / unencrypted; never returns on 3 bad passphrases */
int  enc_enabled(void);
void enc_sector_crypt(u32 logical_lba, const u8 in[512], u8 out[512]);
#endif
