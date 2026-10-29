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

/* RSASSA-PSS signature verification with SHA-256 (RFC 8017
   8.1.2), shared by the TLS 1.3 CertificateVerify handler
   (alg 0x0804) and the TLS 1.2 ServerKeyExchange handler.
   Unlike the PKCS#1 v1.5 entry above, this one takes the
   SHA-256 digest of the signed data (hash32, 32 bytes), not
   the data itself: PSS signs Hash(M), and both TLS call
   sites already hash their signed blob before verifying.
   The salt length is DERIVED from the PSS padding (DB =
   PS || 0x01 || salt), not assumed: TLS 1.3 uses salt length
   32, but any structurally valid salt verifies. MGF1 uses
   SHA-256. Same bounds as above (modulus 62..256 bytes,
   sig length must equal modulus length); moduli whose
   emLen != modulus length fail closed (never true for the
   2048-bit keys this stack speaks). No timing guarantees
   are claimed, same as above. */
int rsa_verify_pss_sha256(const u8 *mod_be, u32 mod_len, u32 exp,
                          const u8 *sig, u32 sig_len,
                          const u8 *hash32);

#endif
