/* P-256 (secp256r1) for ECDHE, see ec256.c for the design note. */
#ifndef NXTS_EC256_H
#define NXTS_EC256_H
#include "../kernel/common.h"

/* A point in affine form, coordinates big-endian byte strings. */
int p256_pub_from_priv(const u8 priv_be[32], u8 pub_x[32], u8 pub_y[32]);
/* Returns 0 and the shared secret (the x coordinate, 32 bytes)
   iff the peer point is valid (coordinates < p, on the curve,
   not infinity) and the shared point is not infinity. */
int p256_ecdh(const u8 priv_be[32],
              const u8 peer_x[32], const u8 peer_y[32],
              u8 shared[32]);
/* Point validity only (used by the TLS layer before ECDH). */
int p256_point_valid(const u8 x_be[32], const u8 y_be[32]);
/* ECDSA P-256 verification (Phase 2): returns 0 iff (r, s) is a
   valid signature over the 32-byte hash under public key
   (qx, qy). r and s must satisfy 1 <= r, s < n; the public
   point must be valid and on the curve; the computed point
   u1*G + u2*Q must not be infinity and its x coordinate mod
   n must equal r. Not constant-time (same documented class
   as the rest of ec256.c). */
int p256_ecdsa_verify(const u8 qx_be[32], const u8 qy_be[32],
                      const u8 hash[32],
                      const u8 r_be[32], const u8 s_be[32]);

#endif
