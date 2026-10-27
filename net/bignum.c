/* Bignum arithmetic for RSA (see bignum.h for the design note).
   Wide (128-limb) temporaries are used internally so the
   division loop never overflows a limb. */
#include "bignum.h"

#define W_LIMBS 128
typedef struct { u32 d[W_LIMBS]; } bnw_t;

static void w_zero(bnw_t *a) { memset(a->d, 0, sizeof(a->d)); }
static void w_from_bn(bnw_t *w, const bn_t *a) {
    w_zero(w);
    for (int i = 0; i < BN_LIMBS; i++) w->d[i] = a->d[i];
}
static int w_cmp(const bnw_t *a, const bnw_t *b) {
    for (int i = W_LIMBS - 1; i >= 0; i--) {
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    }
    return 0;
}
static int w_bitlen(const bnw_t *a) {
    for (int i = W_LIMBS - 1; i >= 0; i--) {
        if (a->d[i]) {
            int b = 0;
            u32 v = a->d[i];
            while (v) { b++; v >>= 1; }
            return i * 32 + b;
        }
    }
    return 0;
}
static int w_getbit(const bnw_t *a, int bit) {
    return (a->d[bit / 32] >> (bit % 32)) & 1;
}
static void w_setbit(bnw_t *a, int bit) { a->d[bit / 32] |= (1u << (bit % 32)); }
static void w_shl1(bnw_t *a) {
    u32 carry = 0;
    for (int i = 0; i < W_LIMBS; i++) {
        u32 next = a->d[i] >> 31;
        a->d[i] = (a->d[i] << 1) | carry;
        carry = next;
    }
}
static void w_sub(bnw_t *a, const bnw_t *b) { /* requires a >= b */
    u32 borrow = 0;
    for (int i = 0; i < W_LIMBS; i++) {
        /* u64 subtraction: borrow-out is exactly whether the
           64-bit result wrapped (high half nonzero). */
        u64 res = (u64)a->d[i] - (u64)b->d[i] - borrow;
        a->d[i] = (u32)res;
        borrow = (u32)(res >> 32) ? 1 : 0;
    }
}
static void w_mul(bnw_t *c, const bn_t *a, const bn_t *b) {
    w_zero(c);
    for (int i = 0; i < BN_LIMBS; i++) {
        if (a->d[i] == 0) continue;
        u32 carry = 0;
        for (int j = 0; j < BN_LIMBS; j++) {
            u32 k = i + j;
            if (k >= W_LIMBS) break;
            u64 cur = (u64)c->d[k] + (u64)a->d[i] * b->d[j] + carry;
            c->d[k] = (u32)cur;
            carry = (u32)(cur >> 32);
        }
        /* Propagate leftover carry (cannot overflow 128 limbs
           for 64x64-limb inputs: max product is 128 limbs). */
        for (int k = i + BN_LIMBS; carry && k < W_LIMBS; k++) {
            u64 cur = (u64)c->d[k] + carry;
            c->d[k] = (u32)cur;
            carry = (u32)(cur >> 32);
        }
    }
}
/* q = a / b, r = a % b (binary long division). */
static void w_divmod(bnw_t *q, bnw_t *r, const bnw_t *a, const bnw_t *b) {
    w_zero(q); w_zero(r);
    int n = w_bitlen(a);
    for (int i = n - 1; i >= 0; i--) {
        w_shl1(r);
        if (w_getbit(a, i)) r->d[0] |= 1;
        if (w_cmp(r, b) >= 0) {
            w_sub(r, b);
            w_setbit(q, i);
        }
    }
}

void bn_zero(bn_t *a) { memset(a->d, 0, sizeof(a->d)); }
void bn_one(bn_t *a) { bn_zero(a); a->d[0] = 1; }
int bn_from_be(bn_t *a, const u8 *bytes, u32 len) {
    bn_zero(a);
    /* Strip leading zero bytes FIRST: DER integers are signed
       and carry a leading 0x00 when the top bit is set, so a
       2048-bit modulus arrives as 257 bytes. (An earlier
       version checked len > 256 before stripping and rejected
       every real RSA-2048 modulus — caught by testing against
       an openssl-generated certificate.) */
    while (len > 0 && bytes[0] == 0) { bytes++; len--; }
    if (len > 256) return -1;
    for (u32 i = 0; i < len; i++) {
        u32 byte = bytes[len - 1 - i];
        a->d[i / 4] |= byte << ((i % 4) * 8);
    }
    return 0;
}
int bn_to_be(const bn_t *a, u8 *out, u32 len) {
    /* The value must fit in len bytes. */
    for (u32 i = len; i < 256; i++) {
        if (a->d[i / 4] & (0xFFu << ((i % 4) * 8))) return -1;
    }
    for (u32 i = 0; i < len; i++)
        out[i] = (u8)(a->d[(len - 1 - i) / 4] >> (((len - 1 - i) % 4) * 8));
    return 0;
}
int bn_cmp(const bn_t *a, const bn_t *b) {
    for (int i = BN_LIMBS - 1; i >= 0; i--) {
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    }
    return 0;
}
int bn_is_zero(const bn_t *a) {
    for (int i = 0; i < BN_LIMBS; i++) if (a->d[i]) return 0;
    return 1;
}
int bn_bitlen(const bn_t *a) {
    bnw_t w; w_from_bn(&w, a);
    return w_bitlen(&w);
}
static void bn_mulmod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *mod) {
    bnw_t prod, q, rem, m;
    w_mul(&prod, a, b);
    w_from_bn(&m, mod);
    w_divmod(&q, &rem, &prod, &m);
    bn_zero(r);
    for (int i = 0; i < BN_LIMBS; i++) r->d[i] = rem.d[i];
}
int bn_modexp(bn_t *result, const bn_t *base, u32 exp, const bn_t *mod) {
    if (bn_is_zero(mod)) return -1;
    if ((mod->d[0] & 1) == 0) return -1; /* even modulus is not RSA */
    bn_t res, b;
    bn_one(&res);
    b = *base;
    /* Reduce base first (base may be >= mod for signatures). */
    {
        bnw_t bw, mw, q, rem;
        w_from_bn(&bw, &b); w_from_bn(&mw, mod);
        if (w_cmp(&bw, &mw) >= 0) {
            w_divmod(&q, &rem, &bw, &mw);
            bn_zero(&b);
            for (int i = 0; i < BN_LIMBS; i++) b.d[i] = rem.d[i];
        }
    }
    for (int i = 31; i >= 0; i--) {
        bn_mulmod(&res, &res, &res, mod);
        if ((exp >> i) & 1) bn_mulmod(&res, &res, &b, mod);
    }
    *result = res;
    return 0;
}
