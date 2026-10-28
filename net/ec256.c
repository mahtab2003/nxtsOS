/* P-256 (secp256r1) arithmetic for ECDHE key exchange.
   Design (deliberately simple, following bignum.c):
   - Field elements are 8 little-endian u32 limbs. mulmod is a
     schoolbook 16-limb product followed by binary long
     division by p — no fast pseudo-Mersenne reduction, no
     64-bit division (the freestanding kernel has no libgcc
     for it; u64 is used only for multiply carries).
   - Scalar multiplication uses Jacobian coordinates, so only
     ONE modular inversion is needed per multiplication (at
     the affine conversion); the inversion is Fermat's little
     theorem (a^(p-2) by square-and-multiply), not an
     extended-GCD routine. Point addition is the generic
     Jacobian formula (add-2007-bl), doubling is the a=-3
     formula; both are verified against the SEC2 test
     vectors by the host test (tests/host_ec256.c) before
     any QEMU run claims them.
   - No secret-dependent branching is claimed: scalar bits
     are scanned in order and the double-and-add loop is not
     constant-time (documented limit, same class as the
     existing RSA modexp and GCM tag compare).
   - Stack: all temporaries here are small (<= 16 limbs);
     the caller keeps points in file-scope statics, never
     as large stack arrays, per the 16 KiB kernel-stack rule. */
#include "ec256.h"

/* p = 2^256 - 2^224 + 2^192 + 2^96 - 1, little-endian limbs. */
static const u32 P256_P[8] = {
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu
};
/* n = order of the base point, little-endian limbs. */
static const u32 P256_N[8] = {
    0xFC632551u, 0xF3B9CAC2u, 0xA7179E84u, 0xBCE6FAADu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u, 0xFFFFFFFFu
};
/* b coefficient, little-endian limbs. */
static const u32 P256_B[8] = {
    0x27D2604Bu, 0x3BCE3C3Eu, 0xCC53B0F6u, 0x651D06B0u,
    0x769886BCu, 0xB3EBBD55u, 0xAA3A93E7u, 0x5AC635D8u
};
static const u8 P256_GX[32] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
};
static const u8 P256_GY[32] = {
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
};

typedef struct { u32 d[8]; } fe_t;
typedef struct { fe_t x, y, z; int inf; } jac_t;

static void fe_zero(fe_t *a) { memset(a->d, 0, sizeof(a->d)); }
static void fe_one(fe_t *a) { fe_zero(a); a->d[0] = 1; }
static void fe_copy(fe_t *dst, const fe_t *src) { *dst = *src; }
static int fe_is_zero(const fe_t *a) {
    for (int i = 0; i < 8; i++) if (a->d[i]) return 0;
    return 1;
}
static int fe_cmp(const fe_t *a, const fe_t *b) {
    for (int i = 7; i >= 0; i--) {
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    }
    return 0;
}
static int fe_from_be(fe_t *a, const u8 *bytes) {
    fe_zero(a);
    for (int i = 0; i < 32; i++) {
        int limb = (31 - i) / 4, shift = ((31 - i) % 4) * 8;
        a->d[limb] |= (u32)bytes[i] << shift;
    }
    return 0;
}
static void fe_to_be(const fe_t *a, u8 *out) {
    for (int i = 0; i < 32; i++) {
        int limb = (31 - i) / 4, shift = ((31 - i) % 4) * 8;
        out[i] = (u8)(a->d[limb] >> shift);
    }
}
static void fe_const(fe_t *a, const u32 *c) {
    for (int i = 0; i < 8; i++) a->d[i] = c[i];
}
/* r = (a + b) mod p. */
static void fe_add(fe_t *r, const fe_t *a, const fe_t *b) {
    u32 carry = 0;
    fe_t s;
    for (int i = 0; i < 8; i++) {
        u64 cur = (u64)a->d[i] + b->d[i] + carry;
        s.d[i] = (u32)cur;
        carry = (u32)(cur >> 32);
    }
    /* If the sum carried out or reached p, subtract p once
       (a, b < p, so the sum is < 2p and one subtraction
       suffices; a carry-out means sum >= 2^256 > p). */
    if (carry) {
        u32 borrow = 0;
        for (int i = 0; i < 8; i++) {
            u64 cur = (u64)s.d[i] - P256_P[i] - borrow;
            s.d[i] = (u32)cur;
            borrow = (u32)(cur >> 32) ? 1 : 0;
        }
    } else {
        fe_t p;
        fe_const(&p, P256_P);
        if (fe_cmp(&s, &p) >= 0) {
            u32 borrow = 0;
            for (int i = 0; i < 8; i++) {
                u64 cur = (u64)s.d[i] - P256_P[i] - borrow;
                s.d[i] = (u32)cur;
                borrow = (u32)(cur >> 32) ? 1 : 0;
            }
        }
    }
    *r = s;
}
/* r = (a - b) mod p. */
static void fe_sub(fe_t *r, const fe_t *a, const fe_t *b) {
    fe_t s;
    u32 borrow = 0;
    for (int i = 0; i < 8; i++) {
        u64 cur = (u64)a->d[i] - b->d[i] - borrow;
        s.d[i] = (u32)cur;
        borrow = (u32)(cur >> 32) ? 1 : 0;
    }
    if (borrow) { /* a < b: add p back once. */
        u32 carry = 0;
        for (int i = 0; i < 8; i++) {
            u64 cur = (u64)s.d[i] + P256_P[i] + carry;
            s.d[i] = (u32)cur;
            carry = (u32)(cur >> 32);
        }
    }
    *r = s;
}
/* 16-limb helpers for mulmod's binary division. */
typedef struct { u32 d[16]; } fe16_t;
static int w16_bitlen(const fe16_t *a) {
    for (int i = 15; i >= 0; i--) {
        if (a->d[i]) {
            int b = 0;
            u32 v = a->d[i];
            while (v) { b++; v >>= 1; }
            return i * 32 + b;
        }
    }
    return 0;
}
static int w16_getbit(const fe16_t *a, int bit) {
    return (a->d[bit / 32] >> (bit % 32)) & 1;
}
static void w16_shl1(fe16_t *a) {
    u32 carry = 0;
    for (int i = 0; i < 16; i++) {
        u32 next = a->d[i] >> 31;
        a->d[i] = (a->d[i] << 1) | carry;
        carry = next;
    }
}
static int w16_cmp(const fe16_t *a, const fe16_t *b) {
    for (int i = 15; i >= 0; i--) {
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    }
    return 0;
}
static void w16_sub(fe16_t *a, const fe16_t *b) { /* requires a >= b */
    u32 borrow = 0;
    for (int i = 0; i < 16; i++) {
        u64 cur = (u64)a->d[i] - b->d[i] - borrow;
        a->d[i] = (u32)cur;
        borrow = (u32)(cur >> 32) ? 1 : 0;
    }
}
/* r = (a * b) mod p. */
static void fe_mul(fe_t *r, const fe_t *a, const fe_t *b) {
    fe16_t prod, rem, p16;
    memset(&prod, 0, sizeof(prod));
    for (int i = 0; i < 8; i++) {
        if (a->d[i] == 0) continue;
        u32 carry = 0;
        for (int j = 0; j < 8; j++) {
            int k = i + j;
            u64 cur = (u64)prod.d[k] + (u64)a->d[i] * b->d[j] + carry;
            prod.d[k] = (u32)cur;
            carry = (u32)(cur >> 32);
        }
        for (int k = i + 8; carry && k < 16; k++) {
            u64 cur = (u64)prod.d[k] + carry;
            prod.d[k] = (u32)cur;
            carry = (u32)(cur >> 32);
        }
    }
    memset(&p16, 0, sizeof(p16));
    for (int i = 0; i < 8; i++) p16.d[i] = P256_P[i];
    memset(&rem, 0, sizeof(rem));
    int n = w16_bitlen(&prod);
    for (int i = n - 1; i >= 0; i--) {
        w16_shl1(&rem);
        if (w16_getbit(&prod, i)) rem.d[0] |= 1;
        if (w16_cmp(&rem, &p16) >= 0) w16_sub(&rem, &p16);
    }
    fe_zero(r);
    for (int i = 0; i < 8; i++) r->d[i] = rem.d[i];
}
/* r = a^2 mod p, r = a^3 helper via fe_mul. */
static void fe_sqr(fe_t *r, const fe_t *a) { fe_mul(r, a, a); }
/* r = a^-1 mod p (a != 0), via a^(p-2). */
static void fe_inv(fe_t *r, const fe_t *a) {
    fe_t res, base, pminus2;
    fe_one(&res);
    fe_copy(&base, a);
    fe_const(&pminus2, P256_P);
    /* p - 2: only the low limb changes (p is odd). */
    pminus2.d[0] -= 2;
    for (int i = 255; i >= 0; i--) {
        fe_sqr(&res, &res);
        if ((pminus2.d[i / 32] >> (i % 32)) & 1) fe_mul(&res, &res, &base);
    }
    *r = res;
}
/* Scalar < n check (for private keys): 0 < k < n. */
static int scalar_valid(const fe_t *k) {
    fe_t n;
    fe_const(&n, P256_N);
    if (fe_is_zero(k)) return 0;
    return fe_cmp(k, &n) < 0;
}

static void jac_inf(jac_t *p) { p->inf = 1; }
static void jac_from_affine(jac_t *j, const fe_t *x, const fe_t *y) {
    fe_copy(&j->x, x);
    fe_copy(&j->y, y);
    fe_one(&j->z);
    j->inf = 0;
}
/* Double a Jacobian point (a = -3 formula). */
static void jac_double(jac_t *r, const jac_t *p) {
    if (p->inf || fe_is_zero(&p->y)) { jac_inf(r); return; }
    fe_t xx, yy, yyyy, zz, s, m, t, tmp;
    fe_sqr(&xx, &p->x);
    fe_sqr(&yy, &p->y);
    fe_sqr(&yyyy, &yy);
    fe_sqr(&zz, &p->z);
    /* S = 2*((X+YY)^2 - XX - YYYY) = 4*X*YY. */
    fe_add(&tmp, &p->x, &yy);
    fe_sqr(&tmp, &tmp);
    fe_sub(&tmp, &tmp, &xx);
    fe_sub(&tmp, &tmp, &yyyy);
    fe_add(&s, &tmp, &tmp);
    /* M = 3*(XX - ZZ^2). */
    fe_sqr(&tmp, &zz);
    fe_sub(&tmp, &xx, &tmp);
    fe_add(&m, &tmp, &tmp);
    fe_add(&m, &m, &tmp);
    /* T = M^2 - 2*S. */
    fe_sqr(&t, &m);
    fe_add(&tmp, &s, &s);
    fe_sub(&t, &t, &tmp);
    fe_copy(&r->x, &t);
    /* Y' = M*(S-T) - 8*YYYY. */
    fe_sub(&tmp, &s, &t);
    fe_mul(&tmp, &m, &tmp);
    fe_t y8;
    fe_add(&y8, &yyyy, &yyyy);
    fe_add(&y8, &y8, &y8);
    fe_add(&y8, &y8, &y8);
    fe_sub(&r->y, &tmp, &y8);
    /* Z' = 2*Y*Z. */
    fe_mul(&tmp, &p->y, &p->z);
    fe_add(&r->z, &tmp, &tmp);
    r->inf = 0;
}
/* Add two Jacobian points (generic formula). */
static void jac_add(jac_t *r, const jac_t *p, const jac_t *q) {
    if (p->inf) { *r = *q; return; }
    if (q->inf) { *r = *p; return; }
    fe_t z1z1, z2z2, u1, u2, s1, s2, h, i2, j2, rr, v, tmp;
    fe_sqr(&z1z1, &p->z);
    fe_sqr(&z2z2, &q->z);
    fe_mul(&u1, &p->x, &z2z2);
    fe_mul(&u2, &q->x, &z1z1);
    fe_mul(&tmp, &q->z, &z2z2);
    fe_mul(&s1, &p->y, &tmp);
    fe_mul(&tmp, &p->z, &z1z1);
    fe_mul(&s2, &q->y, &tmp);
    fe_sub(&h, &u2, &u1);
    fe_sub(&tmp, &s2, &s1);
    fe_add(&rr, &tmp, &tmp);
    if (fe_is_zero(&h)) {
        if (fe_is_zero(&rr)) { jac_double(r, p); return; }
        jac_inf(r);
        return;
    }
    /* I = (2H)^2, J = H*I, V = U1*I. */
    fe_add(&tmp, &h, &h);
    fe_sqr(&i2, &tmp);
    fe_mul(&j2, &h, &i2);
    fe_mul(&v, &u1, &i2);
    /* X3 = R^2 - J - 2V. */
    fe_sqr(&r->x, &rr);
    fe_sub(&r->x, &r->x, &j2);
    fe_add(&tmp, &v, &v);
    fe_sub(&r->x, &r->x, &tmp);
    /* Y3 = R*(V-X3) - 2*S1*J. */
    fe_sub(&tmp, &v, &r->x);
    fe_mul(&tmp, &rr, &tmp);
    fe_t s1j;
    fe_mul(&s1j, &s1, &j2);
    fe_add(&s1j, &s1j, &s1j);
    fe_sub(&r->y, &tmp, &s1j);
    /* Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2)*H. */
    fe_add(&tmp, &p->z, &q->z);
    fe_sqr(&tmp, &tmp);
    fe_sub(&tmp, &tmp, &z1z1);
    fe_sub(&tmp, &tmp, &z2z2);
    fe_mul(&r->z, &tmp, &h);
    r->inf = 0;
}
/* R = k * P (P affine), Jacobian double-and-add. */
static void point_mul(jac_t *r, const fe_t *px, const fe_t *py,
                      const u8 scalar_be[32]) {
    jac_t acc, base;
    jac_inf(&acc);
    jac_from_affine(&base, px, py);
    for (int i = 255; i >= 0; i--) {
        jac_t d;
        jac_double(&d, &acc);
        acc = d;
        if ((scalar_be[31 - i / 8] >> (i % 8)) & 1) {
            jac_t s;
            jac_add(&s, &acc, &base);
            acc = s;
        }
    }
    *r = acc;
}
/* Affine conversion; returns -1 for the point at infinity. */
static int jac_to_affine(const jac_t *p, fe_t *x, fe_t *y) {
    if (p->inf || fe_is_zero(&p->z)) return -1;
    fe_t zinv, zinv2, zinv3;
    fe_inv(&zinv, &p->z);
    fe_sqr(&zinv2, &zinv);
    fe_mul(&zinv3, &zinv2, &zinv);
    fe_mul(x, &p->x, &zinv2);
    fe_mul(y, &p->y, &zinv3);
    return 0;
}
/* On-curve check: y^2 == x^3 - 3x + b (mod p). */
static int point_on_curve(const fe_t *x, const fe_t *y) {
    fe_t lhs, rhs, tmp, x3, three_x, b;
    fe_sqr(&lhs, y);
    fe_sqr(&tmp, x);
    fe_mul(&x3, &tmp, x);
    fe_add(&tmp, x, x);
    fe_add(&three_x, &tmp, x);
    fe_sub(&rhs, &x3, &three_x);
    fe_const(&b, P256_B);
    fe_add(&rhs, &rhs, &b);
    return fe_cmp(&lhs, &rhs) == 0;
}

int p256_point_valid(const u8 x_be[32], const u8 y_be[32]) {
    fe_t x, y, p;
    fe_from_be(&x, x_be);
    fe_from_be(&y, y_be);
    fe_const(&p, P256_P);
    if (fe_cmp(&x, &p) >= 0 || fe_cmp(&y, &p) >= 0) return -1;
    if (!point_on_curve(&x, &y)) return -1;
    return 0;
}

int p256_pub_from_priv(const u8 priv_be[32], u8 pub_x[32], u8 pub_y[32]) {
    fe_t k, gx, gy;
    fe_from_be(&k, priv_be);
    if (!scalar_valid(&k)) return -1;
    fe_from_be(&gx, P256_GX);
    fe_from_be(&gy, P256_GY);
    jac_t r;
    point_mul(&r, &gx, &gy, priv_be);
    fe_t x, y;
    if (jac_to_affine(&r, &x, &y) != 0) return -1;
    fe_to_be(&x, pub_x);
    fe_to_be(&y, pub_y);
    return 0;
}

int p256_ecdh(const u8 priv_be[32],
              const u8 peer_x[32], const u8 peer_y[32],
              u8 shared[32]) {
    fe_t k, px, py;
    fe_from_be(&k, priv_be);
    if (!scalar_valid(&k)) return -1;
    if (p256_point_valid(peer_x, peer_y) != 0) return -1;
    fe_from_be(&px, peer_x);
    fe_from_be(&py, peer_y);
    jac_t r;
    point_mul(&r, &px, &py, priv_be);
    fe_t x, y;
    if (jac_to_affine(&r, &x, &y) != 0) return -1;
    fe_to_be(&x, shared);
    return 0;
}

/* ---------- mod-n arithmetic (ECDSA only) ----------
   Same schoolbook + binary-division design as fe_mul, but
   modulo the curve order n instead of the field prime p.
   n_mul/n_inv are used only by ECDSA verification (small
   counts: a handful of multiplies and one inversion per
   signature), so the slow division is irrelevant here. */
/* r = (a * b) mod n. */
static void n_mul(fe_t *r, const fe_t *a, const fe_t *b) {
    fe16_t prod, rem, n16;
    memset(&prod, 0, sizeof(prod));
    for (int i = 0; i < 8; i++) {
        if (a->d[i] == 0) continue;
        u32 carry = 0;
        for (int j = 0; j < 8; j++) {
            int k = i + j;
            u64 cur = (u64)prod.d[k] + (u64)a->d[i] * b->d[j] + carry;
            prod.d[k] = (u32)cur;
            carry = (u32)(cur >> 32);
        }
        for (int k = i + 8; carry && k < 16; k++) {
            u64 cur = (u64)prod.d[k] + carry;
            prod.d[k] = (u32)cur;
            carry = (u32)(cur >> 32);
        }
    }
    memset(&n16, 0, sizeof(n16));
    for (int i = 0; i < 8; i++) n16.d[i] = P256_N[i];
    memset(&rem, 0, sizeof(rem));
    int n = w16_bitlen(&prod);
    for (int i = n - 1; i >= 0; i--) {
        w16_shl1(&rem);
        if (w16_getbit(&prod, i)) rem.d[0] |= 1;
        if (w16_cmp(&rem, &n16) >= 0) w16_sub(&rem, &n16);
    }
    fe_zero(r);
    for (int i = 0; i < 8; i++) r->d[i] = rem.d[i];
}
/* r = a^-1 mod n (a != 0), via a^(n-2). */
static void n_inv(fe_t *r, const fe_t *a) {
    fe_t res, base, nminus2;
    fe_one(&res);
    fe_copy(&base, a);
    fe_const(&nminus2, P256_N);
    nminus2.d[0] -= 2; /* n is odd: no borrow */
    for (int i = 255; i >= 0; i--) {
        /* Square-and-multiply mod n (not mod p: the
           squaring/multiplying here must reduce by n). */
        n_mul(&res, &res, &res);
        if ((nminus2.d[i / 32] >> (i % 32)) & 1) n_mul(&res, &res, &base);
    }
    *r = res;
}
/* r = a - b, requires a >= b (single borrow chain, no mod). */
static void n_sub_raw(fe_t *r, const fe_t *a, const fe_t *b) {
    fe_t s;
    u32 borrow = 0;
    for (int i = 0; i < 8; i++) {
        u64 cur = (u64)a->d[i] - b->d[i] - borrow;
        s.d[i] = (u32)cur;
        borrow = (u32)(cur >> 32) ? 1 : 0;
    }
    *r = s;
}

int p256_ecdsa_verify(const u8 qx_be[32], const u8 qy_be[32],
                      const u8 hash[32],
                      const u8 r_be[32], const u8 s_be[32]) {
    if (p256_point_valid(qx_be, qy_be) != 0) return -1;
    fe_t n, r, s, e;
    fe_const(&n, P256_N);
    fe_from_be(&r, r_be);
    fe_from_be(&s, s_be);
    if (fe_is_zero(&r) || fe_is_zero(&s)) return -1;
    if (fe_cmp(&r, &n) >= 0 || fe_cmp(&s, &n) >= 0) return -1;
    fe_from_be(&e, hash);
    /* e < 2^256 < 2n (n is ~2^256 - 2^224), so one conditional
       subtraction reduces e mod n. */
    if (fe_cmp(&e, &n) >= 0) n_sub_raw(&e, &e, &n);
    fe_t w, u1, u2;
    n_inv(&w, &s);
    n_mul(&u1, &e, &w);
    n_mul(&u2, &r, &w);
    u8 u1be[32], u2be[32];
    fe_to_be(&u1, u1be);
    fe_to_be(&u2, u2be);
    fe_t gx, gy, px, py;
    fe_from_be(&gx, P256_GX);
    fe_from_be(&gy, P256_GY);
    fe_from_be(&px, qx_be);
    fe_from_be(&py, qy_be);
    jac_t a, b, sum;
    point_mul(&a, &gx, &gy, u1be);
    point_mul(&b, &px, &py, u2be);
    jac_add(&sum, &a, &b);
    fe_t x, y;
    if (jac_to_affine(&sum, &x, &y) != 0) return -1;
    /* x < p < 2n, so again one conditional subtraction. */
    if (fe_cmp(&x, &n) >= 0) n_sub_raw(&x, &x, &n);
    return fe_cmp(&x, &r) == 0 ? 0 : -1;
}
