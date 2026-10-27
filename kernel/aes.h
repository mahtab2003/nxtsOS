#ifndef NXTS_AES_H
#define NXTS_AES_H
#include "common.h"
/* AES-256 encryption only (FIPS 197). Disk encryption uses CTR mode,
   which needs only the encrypt function, so no decrypt function is
   implemented — that is deliberate, not an omission.
   Test vector: key 000102...1f, plaintext 00112233...ff ->
   ciphertext 8ea2b7ca516745bfeafc49904b496089. See shell `aes-test`.
   The S-box is generated at runtime from GF(2^8) arithmetic, not
   copied as a table, so a table typo cannot silently break it. */
void aes256_expand(const u8 key[32], u32 rk[60]);
void aes256_encrypt(const u32 rk[60], const u8 in[16], u8 out[16]);
void aes128_expand(const u8 key[16], u32 rk[44]); /* Phase 9: TLS GCM */
void aes128_encrypt(const u32 rk[44], const u8 in[16], u8 out[16]);
#endif
