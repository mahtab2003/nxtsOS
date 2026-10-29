#ifndef NXTS_AES_H
#define NXTS_AES_H
#include "common.h"
/* AES (FIPS 197). Disk encryption uses CTR mode, which needs
   only the encrypt function; web/SSL Phase 3 (legacy CBC)
   needs decrypt too, so aes128_decrypt/aes256_decrypt exist
   alongside the encrypt functions. Test vector: key
   000102...1f, plaintext 00112233...ff -> ciphertext
   8ea2b7ca516745bfeafc49904b496089. See shell `aes-test`.
   The S-box is generated at runtime from GF(2^8) arithmetic, not
   copied as a table, so a table typo cannot silently break it. */
void aes256_expand(const u8 key[32], u32 rk[60]);
void aes256_encrypt(const u32 rk[60], const u8 in[16], u8 out[16]);
void aes256_decrypt(const u32 rk[60], const u8 in[16], u8 out[16]);
void aes128_expand(const u8 key[16], u32 rk[44]); /* Phase 9: TLS GCM */
void aes128_encrypt(const u32 rk[44], const u8 in[16], u8 out[16]);
void aes128_decrypt(const u32 rk[44], const u8 in[16], u8 out[16]);
#endif
