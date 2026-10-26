#ifndef NXTS_SHA256_H
#define NXTS_SHA256_H
#include "common.h"
/* SHA-256 (FIPS 180-4), one-shot. Used by the package installer
   (install-time and load-time verification) and the shell `sha256`
   command. Test vectors: sha256("abc") =
   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad,
   sha256("") =
   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. */
void sha256_compute(const u8 *data, u32 len, u8 out[32]);
void sha256_hex(const u8 hash[32], char out[65]); /* lowercase hex + NUL */
int  sha256_parse_hex(const char *hex, u8 out[32]); /* 0 ok, -1 bad */
#endif
