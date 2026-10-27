#ifndef NXTS_RSAVERIFY_H
#define NXTS_RSAVERIFY_H
#include "../kernel/common.h"

/* RSA PKCS#1 v1.5 signature verification with SHA-256, shared by
   the TLS certificate verifier (net/tls.c) and the package
   signature verifier (kernel/pkg.c). Returns 0 iff
   RSA_public(sig) == 0x00 0x01 0xFF.. 0x00 || DigestInfo(SHA-256)
   || SHA-256(msg), with at least 8 bytes of 0xFF padding.
   mod_be/sig are big-endian; mod_len must equal sig_len and be
   between 62 and 256 bytes (2048-bit max, the bignum cap). The
   exponent is a u32 (RSA public exponents are small; 65537 is
   the generated default). No timing guarantees are claimed:
   verification is not a secret operation (the message and the
   signature are both public). */
int rsa_verify_sha256(const u8 *mod_be, u32 mod_len, u32 exp,
                      const u8 *sig, u32 sig_len,
                      const u8 *msg, u32 msg_len);

#endif
