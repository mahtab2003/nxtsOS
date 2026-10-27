#ifndef NXTS_BIGNUM_H
#define NXTS_BIGNUM_H
#include "../kernel/common.h"

/* Fixed-size bignums for RSA (max 2048-bit modulus, 64 limbs).
   Deliberately simple and obviously correct: schoolbook
   multiplication and BINARY long division (shift/subtract).
   No 64-bit division anywhere (the kernel has no libgcc for
   it); u64 is used only for multiplication carries (a single
   instruction, no library call). modexp with a 2048-bit
   modulus and a 17-bit exponent takes ~30 reductions of
   ~800k limb ops each — well under a second. */
#define BN_LIMBS 64
typedef struct { u32 d[BN_LIMBS]; } bn_t;

void bn_zero(bn_t *a);
void bn_one(bn_t *a);
int  bn_from_be(bn_t *a, const u8 *bytes, u32 len); /* -1 if >2048 bits */
int  bn_to_be(const bn_t *a, u8 *out, u32 len);    /* -1 if it does not fit */
int  bn_cmp(const bn_t *a, const bn_t *b);         /* -1, 0, 1 */
int  bn_is_zero(const bn_t *a);
int  bn_bitlen(const bn_t *a);
/* result = (base ^ exp) mod mod, exp a u32 (RSA public exponents
   are small; 65537 is 17 iterations). Returns 0 or -1 (mod even
   or zero, or result does not fit — both impossible for valid
   RSA keys, but checked anyway). */
int  bn_modexp(bn_t *result, const bn_t *base, u32 exp, const bn_t *mod);

#endif
