/* TLS 1.2 client (Phase 9.2): one cipher suite,
   TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C), RSA key exchange,
   X.509 chain verification, AES-128-GCM record protection.
   What it is NOT (stated plainly, because TLS security claims
   must not be inflated):
   - No CA trust store ships with nxtsOS. A chain must
     terminate in a self-signed root whose signature verifies
     with its own key, whose dates are valid, and whose leaf
     matches the requested host. That proves the certificate
     is self-consistent, bound to the host, and that the
     server holds the matching private key — but it is TOFU
     (trust on first use), not CA authentication: a man in
     the middle with their own self-signed certificate for
     the same hostname would also pass. A provisioned anchor
     store is future work, not silently claimed here.
   - No ECDHE, no session resumption, no ALPN, no wildcard
     hostname matching (exact match only), no certificate
     revocation checking, no TLS 1.3.
   - Randomness comes from a timer/MAC-seeded xorshift, NOT
     a cryptographic RNG: fine for lab tests, NOT for
     production secrecy (premaster/key randomness is only as
     strong as that seed). This is the release's weakest
     link and is recorded as such.
   - Only one connection at a time, like the TCP client. */
#include "net.h"
#include "bignum.h"
#include "../kernel/sha256.h"
#include "../kernel/aes.h"
#include "../drivers/pit.h"

/* ---------- small helpers ---------- */
static void tput16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void tput24(u8 *p, u32 v) { p[0] = (u8)(v >> 16); p[1] = (u8)(v >> 8); p[2] = (u8)v; }
static void tput32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v;
}
static u16 tget16(const u8 *p) { return (u16)(((u16)p[0] << 8) | p[1]); }
static u32 tget24(const u8 *p) { return ((u32)p[0] << 16) | ((u32)p[1] << 8) | p[2]; }

/* Weak RNG (see header note): xorshift32 seeded from timer +
   MAC. Used for ClientHello random, premaster, and GCM padding. */
static u32 tls_rng_state = 0;
static void tls_rand_seed(void) {
    mac_t m; net_mac(&m);
    u32 s = timer_ticks * 0x9E3779B9u;
    for (int i = 0; i < 6; i++) s ^= (u32)m.b[i] << ((i % 4) * 8);
    s ^= 0xA5A55A5Au;
    if (s == 0) s = 0x12345678u;
    tls_rng_state = s;
}
static void tls_rand(u8 *out, u32 len) {
    for (u32 i = 0; i < len; i++) {
        u32 x = tls_rng_state ^ timer_ticks;
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        tls_rng_state = x;
        out[i] = (u8)(x >> 24);
    }
}

/* ---------- HMAC-SHA256 + TLS PRF ---------- */
static void hmac_sha256(const u8 *key, u32 key_len, const u8 *data, u32 data_len, u8 out[32]) {
    u8 kbuf[64];
    memset(kbuf, 0, sizeof(kbuf));
    if (key_len > 64) {
        sha256_compute(key, key_len, kbuf);
    } else {
        memcpy(kbuf, key, key_len);
    }
    u8 inner[512], outer[96];
    for (int i = 0; i < 64; i++) inner[i] = (u8)(kbuf[i] ^ 0x36);
    if (64 + data_len > sizeof(inner)) return; /* caller keeps data small */
    memcpy(inner + 64, data, data_len);
    u8 ihash[32];
    sha256_compute(inner, 64 + data_len, ihash);
    for (int i = 0; i < 64; i++) outer[i] = (u8)(kbuf[i] ^ 0x5C);
    memcpy(outer + 64, ihash, 32);
    sha256_compute(outer, 96, out);
}
/* P_hash(secret, label+seed) truncated to out_len. */
static void tls_prf(const u8 *secret, u32 secret_len, const char *label,
                    const u8 *seed, u32 seed_len, u8 *out, u32 out_len) {
    u8 label_seed[256];
    u32 ls_len = 0;
    while (label[ls_len] && ls_len < 200) { label_seed[ls_len] = (u8)label[ls_len]; ls_len++; }
    if (ls_len + seed_len > sizeof(label_seed)) return;
    memcpy(label_seed + ls_len, seed, seed_len);
    ls_len += seed_len;
    u8 a[32], buf[512];
    hmac_sha256(secret, secret_len, label_seed, ls_len, a);
    u32 done = 0;
    while (done < out_len) {
        /* buf = A(i) + label + seed */
        if (32 + ls_len > sizeof(buf)) return;
        memcpy(buf, a, 32);
        memcpy(buf + 32, label_seed, ls_len);
        u8 chunk[32];
        hmac_sha256(secret, secret_len, buf, 32 + ls_len, chunk);
        u32 take = out_len - done < 32 ? out_len - done : 32;
        memcpy(out + done, chunk, take);
        done += take;
        /* A(i+1) = HMAC(secret, A(i)) */
        u8 anext[32];
        hmac_sha256(secret, secret_len, a, 32, anext);
        memcpy(a, anext, 32);
    }
}

/* ---------- AES-128-GCM ---------- */
/* GF(2^128) multiply (NIST bit-reflected algorithm). */
static void gcm_mul(const u8 x[16], const u8 y[16], u8 out[16]) {
    u8 z[16], v[16];
    memset(z, 0, 16);
    memcpy(v, y, 16);
    for (int i = 0; i < 128; i++) {
        int bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        if (bit) for (int j = 0; j < 16; j++) z[j] ^= v[j];
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) v[j] = (u8)((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xE1;
    }
    memcpy(out, z, 16);
}
static void ghash(const u8 h[16], const u8 *aad, u32 aad_len,
                  const u8 *cipher, u32 cipher_len, u8 out[16]) {
    u8 y[16];
    memset(y, 0, 16);
    u8 block[16];
    /* AAD blocks (zero-padded). */
    for (u32 off = 0; off < aad_len; off += 16) {
        memset(block, 0, 16);
        u32 take = aad_len - off < 16 ? aad_len - off : 16;
        memcpy(block, aad + off, take);
        for (int j = 0; j < 16; j++) y[j] ^= block[j];
        gcm_mul(y, h, y);
    }
    for (u32 off = 0; off < cipher_len; off += 16) {
        memset(block, 0, 16);
        u32 take = cipher_len - off < 16 ? cipher_len - off : 16;
        memcpy(block, cipher + off, take);
        for (int j = 0; j < 16; j++) y[j] ^= block[j];
        gcm_mul(y, h, y);
    }
    /* Length block is 64-bit BE bit lengths; aad/cipher here are
       < 2^29 bytes, so the high words are zero and the low word
       is len*8 (computed with u32 shifts, no division). */
    {
        u8 lb[16];
        memset(lb, 0, 16);
        u32 ab = aad_len * 8, cb = cipher_len * 8;
        /* aad bit length in bytes 0..7 (only low word nonzero). */
        lb[7] = (u8)ab; lb[6] = (u8)(ab >> 8); lb[5] = (u8)(ab >> 16); lb[4] = (u8)(ab >> 24);
        lb[15] = (u8)cb; lb[14] = (u8)(cb >> 8); lb[13] = (u8)(cb >> 16); lb[12] = (u8)(cb >> 24);
        for (int j = 0; j < 16; j++) y[j] ^= lb[j];
        gcm_mul(y, h, y);
    }
    memcpy(out, y, 16);
}
/* GCM encrypt: iv12 = salt(4) || nonce_explicit(8) is passed as
   the full 12-byte nonce. out = ciphertext, tag 16 bytes. */
static void gcm_encrypt(const u8 key[16], const u8 nonce[12],
                        const u8 *aad, u32 aad_len,
                        const u8 *plain, u32 plain_len,
                        u8 *cipher, u8 tag[16]) {
    u32 rk[44];
    aes128_expand(key, rk);
    u8 h[16], zero[16];
    memset(zero, 0, 16);
    aes128_encrypt(rk, zero, h);
    u8 j0[16];
    memcpy(j0, nonce, 12);
    tput32(j0 + 12, 1);
    /* GCTR starting at J0+1 (last 32 bits incremented). */
    u32 ctr = 2;
    for (u32 off = 0; off < plain_len; off += 16) {
        u8 ks[16], cb[16];
        memcpy(cb, j0, 16);
        tput32(cb + 12, ctr++);
        aes128_encrypt(rk, cb, ks);
        u32 take = plain_len - off < 16 ? plain_len - off : 16;
        for (u32 j = 0; j < take; j++) cipher[off + j] = (u8)(plain[off + j] ^ ks[j]);
    }
    u8 s[16];
    ghash(h, aad, aad_len, cipher, plain_len, s);
    u8 ej0[16];
    aes128_encrypt(rk, j0, ej0);
    for (int j = 0; j < 16; j++) tag[j] = (u8)(s[j] ^ ej0[j]);
}
/* Returns 0 if the tag verifies (then decrypts), -1 otherwise. */
static int gcm_decrypt(const u8 key[16], const u8 nonce[12],
                       const u8 *aad, u32 aad_len,
                       const u8 *cipher, u32 cipher_len,
                       const u8 tag[16], u8 *plain) {
    u32 rk[44];
    aes128_expand(key, rk);
    u8 h[16], zero[16];
    memset(zero, 0, 16);
    aes128_encrypt(rk, zero, h);
    u8 j0[16];
    memcpy(j0, nonce, 12);
    tput32(j0 + 12, 1);
    u8 s[16];
    ghash(h, aad, aad_len, cipher, cipher_len, s);
    u8 ej0[16];
    aes128_encrypt(rk, j0, ej0);
    u8 expect[16];
    for (int j = 0; j < 16; j++) expect[j] = (u8)(s[j] ^ ej0[j]);
    /* Tag comparison is not constant-time (documented limit;
       the tag is not a secret key, and this is a lab client). */
    if (memcmp(expect, tag, 16) != 0) return -1;
    u32 ctr = 2;
    for (u32 off = 0; off < cipher_len; off += 16) {
        u8 ks[16], cb[16];
        memcpy(cb, j0, 16);
        tput32(cb + 12, ctr++);
        aes128_encrypt(rk, cb, ks);
        u32 take = cipher_len - off < 16 ? cipher_len - off : 16;
        for (u32 j = 0; j < take; j++) plain[off + j] = (u8)(cipher[off + j] ^ ks[j]);
    }
    return 0;
}

/* ---------- RTC date (for certificate validity) ---------- */
static u8 rtc_reg(u8 reg) {
    outb(0x70, (u8)(0x80 | reg));
    io_wait();
    return inb(0x71);
}
static int bcd_to_int(u8 v, int bcd) {
    if (!bcd) return v;
    return ((v >> 4) * 10) + (v & 0x0F);
}
/* Canonical "YYYYMMDDHHMMSS" (14 chars + NUL) from the RTC. */
static void rtc_now_str(char out[15]) {
    u8 mode = rtc_reg(0x0B);
    int bcd = (mode & 0x04) == 0;
    int h24 = (mode & 0x02) != 0;
    int sec = bcd_to_int(rtc_reg(0x00), bcd);
    int min = bcd_to_int(rtc_reg(0x02), bcd);
    /* 12-hour mode: strip the PM bit from the RAW hour byte
       BEFORE BCD conversion (converting first, as an earlier
       draft did, corrupts the value: BCD 0x82 becomes 82,
       and 82 & 0x7F is still 82, not 2). */
    u8 raw_hour = rtc_reg(0x04);
    int pm = 0;
    if (!h24) { pm = (raw_hour & 0x80) != 0; raw_hour &= 0x7F; }
    int hour = bcd_to_int(raw_hour, bcd);
    if (!h24) {
        if (pm) { if (hour != 12) hour += 12; }
        else { if (hour == 12) hour = 0; }
    }
    int day = bcd_to_int(rtc_reg(0x07), bcd);
    int mon = bcd_to_int(rtc_reg(0x08), bcd);
    int year = bcd_to_int(rtc_reg(0x09), bcd);
    int vals[6];
    vals[0] = 2000 + year; vals[1] = mon; vals[2] = day;
    vals[3] = hour; vals[4] = min; vals[5] = sec;
    int widths[6] = {4, 2, 2, 2, 2, 2};
    int o = 0;
    for (int f = 0; f < 6; f++) {
        int w = widths[f], v = vals[f];
        char digits[5];
        for (int d = w - 1; d >= 0; d--) { digits[d] = (char)('0' + (v % 10)); v /= 10; }
        for (int d = 0; d < w; d++) out[o++] = digits[d];
    }
    out[o] = 0;
}

/* ---------- DER parsing ---------- */
/* Parse one TLV at pos. Returns 0, filling tag, header length,
   value length and value position. Rejects multi-byte tags,
   indefinite lengths, and lengths that run past the buffer. */
static int der_tlv(const u8 *buf, u32 buflen, u32 pos, u8 *tag,
                   u32 *hdr_len, u32 *val_len, u32 *val_pos) {
    if (pos >= buflen) return -1;
    u8 t = buf[pos];
    if ((t & 0x1F) == 0x1F) return -1; /* multi-byte tag: unsupported */
    if (pos + 1 >= buflen) return -1;
    u8 lb = buf[pos + 1];
    u32 hl, vl;
    if (lb < 0x80) { hl = 2; vl = lb; }
    else {
        u32 n = lb & 0x7F;
        if (n == 0 || n > 4) return -1;
        if (pos + 2 + n > buflen) return -1;
        vl = 0;
        for (u32 i = 0; i < n; i++) vl = (vl << 8) | buf[pos + 2 + i];
        hl = 2 + n;
    }
    if (pos + hl + vl > buflen) return -1;
    *tag = t; *hdr_len = hl; *val_len = vl; *val_pos = pos + hl;
    return 0;
}
static int der_oid_equal(const u8 *a, u32 a_len, const u8 *b, u32 b_len) {
    return a_len == b_len && memcmp(a, b, a_len) == 0;
}
/* OID bytes (content only, without tag/length): */
static const u8 OID_RSA_ENC[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
static const u8 OID_SHA256_RSA[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
static const u8 OID_CN[] = {0x55, 0x04, 0x03};
static const u8 OID_BC[] = {0x55, 0x1D, 0x13};
static const u8 OID_SAN[] = {0x55, 0x1D, 0x11};
/* SHA-256 DigestInfo prefix (PKCS#1 v1.5). */
static const u8 SHA256_DER_PREFIX[] = {
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

/* ---------- Certificate ---------- */
#define MAX_SAN_DNS 4
#define MAX_SAN_IP 4
struct cert_info {
    const u8 *tbs; u32 tbs_len;
    const u8 *issuer; u32 issuer_len;
    const u8 *subject; u32 subject_len;
    char not_before[15], not_after[15];
    bn_t modulus; u32 exponent;
    const u8 *sig; u32 sig_len;
    int ca_flag; /* 1 = BC CA:true, 0 = BC CA:false, -1 = no BC */
    char cn[64];
    char san_dns[MAX_SAN_DNS][64];
    int san_dns_count;
    u8 san_ip[MAX_SAN_IP][4];
    int san_ip_count;
    int has_san;
};
/* Parse a time value (UTCTime 0x17 or GeneralizedTime 0x18) at
   the given TLV value into canonical "YYYYMMDDHHMMSS". */
static int parse_cert_time(u8 tag, const u8 *v, u32 len, char out[15]) {
    if (tag == 0x17) {
        if (len < 13 || v[12] != 'Z') return -1;
        int yy = (v[0] - '0') * 10 + (v[1] - '0');
        int yyyy = yy < 50 ? 2000 + yy : 1900 + yy;
        out[0] = (char)('0' + yyyy / 1000); out[1] = (char)('0' + (yyyy / 100) % 10);
        out[2] = (char)('0' + (yyyy / 10) % 10); out[3] = (char)('0' + yyyy % 10);
        for (int i = 0; i < 10; i++) out[4 + i] = (char)v[2 + i];
        out[14] = 0;
        return 0;
    }
    if (tag == 0x18) {
        if (len < 15 || v[14] != 'Z') return -1;
        for (int i = 0; i < 14; i++) out[i] = (char)v[i];
        out[14] = 0;
        return 0;
    }
    return -1;
}
/* Parse a Name's CN (first CN found) into cn (may stay empty). */
static void parse_name_cn(const u8 *name, u32 name_len, char *cn) {
    cn[0] = 0;
    u8 tag; u32 hl, vl, vp;
    if (der_tlv(name, name_len, 0, &tag, &hl, &vl, &vp) != 0 || tag != 0x30) return;
    u32 pos = vp, end = vp + vl;
    while (pos < end) {
        u8 t2; u32 h2, v2, p2;
        if (der_tlv(name, name_len, pos, &t2, &h2, &v2, &p2) != 0) return;
        if (t2 == 0x31) {
            /* SET of AttributeTypeAndValue (SEQUENCE). */
            u32 spos = p2, send = p2 + v2;
            while (spos < send) {
                u8 t3; u32 h3, v3, p3;
                if (der_tlv(name, name_len, spos, &t3, &h3, &v3, &p3) != 0) return;
                if (t3 == 0x30) {
                    u8 ta; u32 ha, va, pa;
                    if (der_tlv(name, name_len, p3, &ta, &ha, &va, &pa) != 0) return;
                    if (ta == 0x06 && der_oid_equal(name + pa, va, OID_CN, sizeof(OID_CN))) {
                        u32 vpos = pa + va;
                        u8 tv; u32 hv, vv, pv;
                        if (der_tlv(name, name_len, vpos, &tv, &hv, &vv, &pv) != 0) return;
                        if ((tv == 0x13 || tv == 0x14 || tv == 0x16 || tv == 0x0C) && vv < 63) {
                            memcpy(cn, name + pv, vv);
                            cn[vv] = 0;
                            return;
                        }
                    }
                }
                spos = p3 + v3;
            }
        }
        pos = p2 + v2;
    }
}
static int parse_cert(const u8 *buf, u32 len, struct cert_info *ci) {
    memset(ci, 0, sizeof(*ci));
    ci->ca_flag = -1;
    u8 tag; u32 hl, vl, vp;
    if (der_tlv(buf, len, 0, &tag, &hl, &vl, &vp) != 0 || tag != 0x30) return -1;
    if (hl + vl != len) return -1;
    u32 pos = vp, end = vp + vl;
    /* tbsCertificate */
    if (der_tlv(buf, len, pos, &tag, &hl, &vl, &vp) != 0 || tag != 0x30) return -1;
    ci->tbs = buf + pos; ci->tbs_len = hl + vl;
    u32 tbs_pos = vp, tbs_end = vp + vl;
    pos = vp + vl;
    /* signatureAlgorithm (outer) */
    u8 alg_tag; u32 alg_hl, alg_vl, alg_vp;
    if (der_tlv(buf, len, pos, &alg_tag, &alg_hl, &alg_vl, &alg_vp) != 0 || alg_tag != 0x30) return -1;
    {
        u8 ot; u32 oh, ov, op;
        if (der_tlv(buf, len, alg_vp, &ot, &oh, &ov, &op) != 0 || ot != 0x06) return -1;
        if (!der_oid_equal(buf + op, ov, OID_SHA256_RSA, sizeof(OID_SHA256_RSA))) return -1;
    }
    pos = pos + alg_hl + alg_vl;
    /* signatureValue BIT STRING */
    if (der_tlv(buf, len, pos, &tag, &hl, &vl, &vp) != 0 || tag != 0x03) return -1;
    if (vl < 1 || buf[vp] != 0) return -1;
    ci->sig = buf + vp + 1; ci->sig_len = vl - 1;
    if (pos + hl + vl != len) return -1;
    /* --- inside tbsCertificate --- */
    u32 tp = tbs_pos;
    /* optional [0] version */
    if (der_tlv(buf, len, tp, &tag, &hl, &vl, &vp) != 0) return -1;
    if (tag == 0xA0) tp = vp + vl;
    /* serial INTEGER */
    if (der_tlv(buf, len, tp, &tag, &hl, &vl, &vp) != 0 || tag != 0x02) return -1;
    tp = vp + vl;
    /* signature (tbs) — must match the outer algorithm OID */
    if (der_tlv(buf, len, tp, &tag, &hl, &vl, &vp) != 0 || tag != 0x30) return -1;
    {
        u8 ot; u32 oh, ov, op;
        if (der_tlv(buf, len, vp, &ot, &oh, &ov, &op) != 0 || ot != 0x06) return -1;
        if (!der_oid_equal(buf + op, ov, OID_SHA256_RSA, sizeof(OID_SHA256_RSA))) return -1;
    }
    tp = vp + vl;
    /* issuer Name (raw TLV) */
    if (der_tlv(buf, len, tp, &tag, &hl, &vl, &vp) != 0 || tag != 0x30) return -1;
    ci->issuer = buf + tp; ci->issuer_len = hl + vl;
    tp = vp + vl;
    /* validity SEQUENCE of two times */
    if (der_tlv(buf, len, tp, &tag, &hl, &vl, &vp) != 0 || tag != 0x30) return -1;
    {
        u8 t1; u32 h1, v1, p1;
        if (der_tlv(buf, len, vp, &t1, &h1, &v1, &p1) != 0) return -1;
        if (parse_cert_time(t1, buf + p1, v1, ci->not_before) != 0) return -1;
        u32 np = p1 + v1;
        u8 t2; u32 h2, v2, p2;
        if (der_tlv(buf, len, np, &t2, &h2, &v2, &p2) != 0) return -1;
        if (parse_cert_time(t2, buf + p2, v2, ci->not_after) != 0) return -1;
    }
    tp = vp + vl;
    /* subject Name (raw TLV) */
    if (der_tlv(buf, len, tp, &tag, &hl, &vl, &vp) != 0 || tag != 0x30) return -1;
    ci->subject = buf + tp; ci->subject_len = hl + vl;
    parse_name_cn(ci->subject, ci->subject_len, ci->cn);
    tp = vp + vl;
    /* subjectPublicKeyInfo */
    if (der_tlv(buf, len, tp, &tag, &hl, &vl, &vp) != 0 || tag != 0x30) return -1;
    {
        u8 at; u32 ah, av, ap;
        if (der_tlv(buf, len, vp, &at, &ah, &av, &ap) != 0 || at != 0x30) return -1;
        u8 ot; u32 oh, ov, op;
        if (der_tlv(buf, len, ap, &ot, &oh, &ov, &op) != 0 || ot != 0x06) return -1;
        if (!der_oid_equal(buf + op, ov, OID_RSA_ENC, sizeof(OID_RSA_ENC))) return -1;
        u32 bp = ap + av;
        u8 bt; u32 bh, bv, bpos;
        if (der_tlv(buf, len, bp, &bt, &bh, &bv, &bpos) != 0 || bt != 0x03) return -1;
        if (bv < 1 || buf[bpos] != 0) return -1;
        /* RSAPublicKey SEQUENCE inside the BIT STRING. */
        u8 rt; u32 rh, rv, rp;
        if (der_tlv(buf, len, bpos + 1, &rt, &rh, &rv, &rp) != 0 || rt != 0x30) return -1;
        u8 mt; u32 mh, mv, mp;
        if (der_tlv(buf, len, rp, &mt, &mh, &mv, &mp) != 0 || mt != 0x02) return -1;
        if (bn_from_be(&ci->modulus, buf + mp, mv) != 0) return -1;
        u32 ep = mp + mv;
        u8 et; u32 eh, ev, epos;
        if (der_tlv(buf, len, ep, &et, &eh, &ev, &epos) != 0 || et != 0x02) return -1;
        /* Exponent: strip leading zeros, must fit u32, be odd, >= 3. */
        while (ev > 0 && buf[epos] == 0) { epos++; ev--; }
        if (ev == 0 || ev > 4) return -1;
        u32 e = 0;
        for (u32 i = 0; i < ev; i++) e = (e << 8) | buf[epos + i];
        if (e < 3 || (e & 1) == 0) return -1;
        ci->exponent = e;
    }
    tp = vp + vl;
    /* Optional [1], [2], [3] (extensions). Only [3] is parsed;
       any other tag here is a malformed tbsCertificate. */
    while (tp < tbs_end) {
        if (der_tlv(buf, len, tp, &tag, &hl, &vl, &vp) != 0) return -1;
        if (tag != 0xA1 && tag != 0xA2 && tag != 0xA3) return -1;
        if (tag == 0xA3) {
            /* Explicit: value is a SEQUENCE TLV of extensions. */
            u8 st; u32 sh, sv, sp;
            if (der_tlv(buf, len, vp, &st, &sh, &sv, &sp) != 0 || st != 0x30) return -1;
            u32 epos = sp, eend = sp + sv;
            while (epos < eend) {
                u8 xt; u32 xh, xv, xp;
                if (der_tlv(buf, len, epos, &xt, &xh, &xv, &xp) != 0 || xt != 0x30) return -1;
                u8 ot; u32 oh, ov, op;
                if (der_tlv(buf, len, xp, &ot, &oh, &ov, &op) != 0 || ot != 0x06) return -1;
                u32 vpos = op + ov;
                /* Optional BOOLEAN critical. */
                u8 vt; u32 vh, vv, vpos2;
                if (der_tlv(buf, len, vpos, &vt, &vh, &vv, &vpos2) != 0) return -1;
                if (vt == 0x01) {
                    vpos = vpos2 + vv;
                    if (der_tlv(buf, len, vpos, &vt, &vh, &vv, &vpos2) != 0) return -1;
                }
                if (vt != 0x04) return -1; /* value must be OCTET STRING */
                const u8 *ext_val = buf + vpos2;
                u32 ext_len = vv;
                if (der_oid_equal(buf + op, ov, OID_BC, sizeof(OID_BC))) {
                    /* BC value: SEQUENCE, optional BOOLEAN cA. */
                    u8 bt; u32 bh, bv, bp;
                    if (der_tlv(ext_val, ext_len, 0, &bt, &bh, &bv, &bp) != 0 || bt != 0x30) return -1;
                    ci->ca_flag = 0;
                    if (bv > 0) {
                        u8 ct; u32 ch, cv, cp;
                        if (der_tlv(ext_val, ext_len, bp, &ct, &ch, &cv, &cp) == 0 && ct == 0x01 && cv == 1)
                            ci->ca_flag = buf[cp] ? 1 : 0;
                    }
                } else if (der_oid_equal(buf + op, ov, OID_SAN, sizeof(OID_SAN))) {
                    ci->has_san = 1;
                    u8 st2; u32 sh2, sv2, sp2;
                    if (der_tlv(ext_val, ext_len, 0, &st2, &sh2, &sv2, &sp2) != 0 || st2 != 0x30) return -1;
                    u32 spos = sp2, send = sp2 + sv2;
                    while (spos < send) {
                        u8 gt; u32 gh, gv, gp;
                        if (der_tlv(ext_val, ext_len, spos, &gt, &gh, &gv, &gp) != 0) return -1;
                        if (gt == 0x82 && gv < 63 && ci->san_dns_count < MAX_SAN_DNS) {
                            memcpy(ci->san_dns[ci->san_dns_count], ext_val + gp, gv);
                            ci->san_dns[ci->san_dns_count][gv] = 0;
                            ci->san_dns_count++;
                        } else if (gt == 0x87 && gv == 4 && ci->san_ip_count < MAX_SAN_IP) {
                            memcpy(ci->san_ip[ci->san_ip_count], ext_val + gp, 4);
                            ci->san_ip_count++;
                        }
                        spos = gp + gv;
                    }
                }
                epos = xp + xv;
            }
        }
        tp = vp + vl;
    }
    if (tp != tbs_end) return -1;
    return 0;
}
/* Verify cert's RSA/SHA-256 signature with issuer_pubkey. */
static int verify_signature(const struct cert_info *cert, const bn_t *mod, u32 exp) {
    bn_t sig, em;
    if (bn_from_be(&sig, cert->sig, cert->sig_len) != 0) return -1;
    if (bn_modexp(&em, &sig, exp, mod) != 0) return -1;
    /* Modulus length in bytes (round bit length up). */
    int bl = bn_bitlen(mod);
    u32 k = (u32)((bl + 7) / 8);
    if (k < 51 + 11) return -1; /* too small for DigestInfo + padding */
    u8 em_bytes[256];
    if (k > sizeof(em_bytes)) return -1;
    if (bn_to_be(&em, em_bytes, k) != 0) return -1;
    if (em_bytes[0] != 0x00 || em_bytes[1] != 0x01) return -1;
    u32 i = 2;
    while (i < k && em_bytes[i] == 0xFF) i++;
    if (i - 2 < 8) return -1; /* padding too short */
    if (i >= k || em_bytes[i] != 0x00) return -1;
    i++;
    if (k - i != sizeof(SHA256_DER_PREFIX) + 32) return -1;
    if (memcmp(em_bytes + i, SHA256_DER_PREFIX, sizeof(SHA256_DER_PREFIX)) != 0) return -1;
    u8 hash[32];
    sha256_compute(cert->tbs, cert->tbs_len, hash);
    if (memcmp(em_bytes + i + sizeof(SHA256_DER_PREFIX), hash, 32) != 0) return -1;
    return 0;
}
static int ascii_equal_nocase(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}
/* Hostname check for the leaf. Returns 0 on match. */
static int verify_host(const struct cert_info *leaf, const char *host) {
    ip_t hip;
    int host_is_ip = net_parse_ip(host, &hip);
    if (leaf->has_san) {
        if (host_is_ip) {
            for (int i = 0; i < leaf->san_ip_count; i++)
                if (memcmp(leaf->san_ip[i], hip.b, 4) == 0) return 0;
            return -1;
        }
        for (int i = 0; i < leaf->san_dns_count; i++)
            if (ascii_equal_nocase(leaf->san_dns[i], host)) return 0;
        return -1; /* SAN present but no match: no CN fallback */
    }
    if (host_is_ip) {
        /* No SAN: compare CN textually to the dotted host. */
        return ascii_equal_nocase(leaf->cn, host) ? 0 : -1;
    }
    return ascii_equal_nocase(leaf->cn, host) ? 0 : -1;
}
/* Full chain verification. certs[0] is the leaf. Returns 0 or -1.
   -2 is reserved by the caller for certificate failures; this
   function only returns 0/-1 (the caller maps -1 to -2). */
static int verify_chain(const struct cert_info *certs, int count, const char *host) {
    char now[15];
    rtc_now_str(now);
    for (int i = 0; i < count; i++) {
        /* Validity dates (lexicographic on canonical strings). */
        if (strcmp(certs[i].not_before, now) > 0) { return -1; }
        if (strcmp(now, certs[i].not_after) > 0) { return -1; }
    }
    if (verify_host(&certs[0], host) != 0) { return -1; }
    for (int i = 0; i + 1 < count; i++) {
        /* Issuer name must equal the next cert's subject. */
        if (certs[i].issuer_len != certs[i + 1].subject_len) return -1;
        if (memcmp(certs[i].issuer, certs[i + 1].subject, certs[i].issuer_len) != 0) return -1;
        /* Non-leaf certs used as issuers must be CAs. */
        if (certs[i + 1].ca_flag != 1) return -1;
        if (verify_signature(&certs[i], &certs[i + 1].modulus, certs[i + 1].exponent) != 0) return -1;
    }
    /* Last cert must be self-signed (TOFU root, see header). */
    const struct cert_info *root = &certs[count - 1];
    if (root->issuer_len != root->subject_len) { return -1; }
    if (memcmp(root->issuer, root->subject, root->issuer_len) != 0) { return -1; }
    if (root->ca_flag == 0) { return -1; }
    if (verify_signature(root, &root->modulus, root->exponent) != 0) { return -1; }
    return 0;
}

/* ---------- TLS record + handshake layer ---------- */
#define TLS_REC_MAX 16384
static u8 tls_rec_buf[TLS_REC_MAX + 64];
static u8 tls_plain_buf[TLS_REC_MAX + 64];
static u8 tls_cipher_buf[TLS_REC_MAX + 64];
static u8 tls_payload_buf[TLS_REC_MAX + 64];
static u8 tls_msg_buf[8192];
static u8 tls_hs_buf[TLS_REC_MAX + 64];
static u8 tls_app_spill[TLS_REC_MAX];
static u32 tls_app_spill_len = 0, tls_app_spill_pos = 0;
static u32 tls_hs_len = 0;
static u8 tls_transcript[16384];
static u32 tls_transcript_len = 0;
static u8 tls_client_random[32], tls_server_random[32];
static bn_t tls_leaf_mod;
static u32 tls_leaf_exp = 0;
static u8 tls_master[48];
static u8 tls_client_key[16], tls_server_key[16];
static u8 tls_client_iv[4], tls_server_iv[4];
static u32 tls_send_seq = 0, tls_recv_seq = 0;
static int tls_client_enc = 0, tls_server_enc = 0;

static int transcript_append(const u8 *data, u32 len) {
    if (tls_transcript_len + len > sizeof(tls_transcript)) return -1;
    memcpy(tls_transcript + tls_transcript_len, data, len);
    tls_transcript_len += len;
    return 0;
}
/* Read exactly len bytes from the TCP stream (or -1). */
static int tcp_read_exact(u8 *buf, u32 len, u32 deadline_ticks) {
    u32 got = 0;
    u32 start = timer_ticks;
    while (got < len) {
        if (timer_ticks - start > deadline_ticks) return -1;
        int n = net_tcp_recv(buf + got, len - got, 100);
        if (n < 0) return -1;
        if (n == 0) continue;
        got += (u32)n;
    }
    return 0;
}
/* Read one TLS record. Returns record type, or -1. The payload
   (decrypted if tls_server_enc) is left in tls_rec_buf. */
static int tls_recv_record(u32 *out_len) {
    u8 hdr[5];
    if (tcp_read_exact(hdr, 5, 1000) != 0) { return -1; }
    u8 type = hdr[0];
    if (type != 20 && type != 21 && type != 22 && type != 23) return -1;
    if (hdr[1] != 0x03 || hdr[2] != 0x03) return -1;
    u32 len = tget16(hdr + 3);
    if (len == 0 || len > TLS_REC_MAX) return -1;
    if (tcp_read_exact(tls_rec_buf, len, 1000) != 0) return -1;
    if (!tls_server_enc) {
        *out_len = len;
        return type;
    }
    /* Encrypted record: nonce_explicit(8) || ciphertext || tag(16). */
    if (type != 22 && type != 23) return -1;
    if (len < 8 + 16) return -1;
    u8 nonce[12], aad[13];
    memcpy(nonce, tls_server_iv, 4);
    memcpy(nonce + 4, tls_rec_buf, 8);
    memset(aad, 0, 4);
    tput32(aad + 4, tls_recv_seq);
    aad[8] = type;
    aad[9] = 0x03; aad[10] = 0x03;
    u32 plain_len = len - 8 - 16;
    tput16(aad + 11, (u16)plain_len);
    /* NOTE: plain must be a static buffer, not a stack array:
       the kernel stack is 16 KiB and a 16 KiB local would
       overflow it. Same for the send-side buffers below. */
    if (gcm_decrypt(tls_server_key, nonce, aad, 13,
                    tls_rec_buf + 8, plain_len,
                    tls_rec_buf + 8 + plain_len, tls_plain_buf) != 0) return -1;
    tls_recv_seq++;
    memcpy(tls_rec_buf, tls_plain_buf, plain_len);
    *out_len = plain_len;
    return type;
}
/* Send one record (plaintext; encrypted if tls_client_enc and
   the type is handshake/app data — CCS itself is never
   encrypted). */
static int tls_send_record(u8 type, const u8 *data, u32 len) {
    u8 hdr[5];
    hdr[0] = type; hdr[1] = 0x03; hdr[2] = 0x03;
    if (!tls_client_enc || type == 20) {
        tput16(hdr + 3, (u16)len);
        if (net_tcp_send(hdr, 5) != 0) return -1;
        if (len > 0 && net_tcp_send(data, len) != 0) return -1;
        return 0;
    }
    /* GCM: nonce_explicit = send sequence (8 bytes BE). */
    u8 nonce[12], aad[13];
    memcpy(nonce, tls_client_iv, 4);
    memset(nonce + 4, 0, 4);
    tput32(nonce + 8, tls_send_seq);
    memset(aad, 0, 4);
    tput32(aad + 4, tls_send_seq);
    aad[8] = type; aad[9] = 0x03; aad[10] = 0x03;
    tput16(aad + 11, (u16)len);
    u8 tag[16];
    if (len > TLS_REC_MAX) return -1;
    gcm_encrypt(tls_client_key, nonce, aad, 13, data, len, tls_cipher_buf, tag);
    memcpy(tls_payload_buf, nonce + 4, 8);
    memcpy(tls_payload_buf + 8, tls_cipher_buf, len);
    memcpy(tls_payload_buf + 8 + len, tag, 16);
    tput16(hdr + 3, (u16)(len + 24));
    if (net_tcp_send(hdr, 5) != 0) return -1;
    if (net_tcp_send(tls_payload_buf, len + 24) != 0) return -1;
    tls_send_seq++;
    return 0;
}
/* Send one handshake message (appends to the transcript). */
static int tls_send_hs(u8 type, const u8 *body, u32 body_len) {
    u8 msg[2048];
    if (body_len + 4 > 8192) return -1;
    msg[0] = type;
    tput24(msg + 1, body_len);
    memcpy(msg + 4, body, body_len);
    if (transcript_append(msg, body_len + 4) != 0) return -1;
    return tls_send_record(22, msg, body_len + 4);
}
/* Read the next complete handshake message into msg_out
   (returns its type, or -1). Handles messages split across
   records and multiple messages per record. */
static int tls_next_hs(u8 *msg_out, u32 max, u32 *msg_len_out) {
    while (1) {
        if (tls_hs_len >= 4) {
            u32 body_len = tget24(tls_hs_buf + 1);
            if (body_len + 4 <= max && tls_hs_len >= body_len + 4) {
                u8 type = tls_hs_buf[0];
                memcpy(msg_out, tls_hs_buf, body_len + 4);
                memmove(tls_hs_buf, tls_hs_buf + body_len + 4,
                        tls_hs_len - (body_len + 4));
                tls_hs_len -= body_len + 4;
                *msg_len_out = body_len + 4;
                return type;
            }
            if (body_len + 4 > max) return -1;
        }
        u32 rec_len = 0;
        int rtype = tls_recv_record(&rec_len);
        if (rtype != 22) return -1;
        if (tls_hs_len + rec_len > sizeof(tls_hs_buf)) return -1;
        memcpy(tls_hs_buf + tls_hs_len, tls_rec_buf, rec_len);
        tls_hs_len += rec_len;
    }
}

/* ---------- Handshake ---------- */
/* Returns 0 (handshake done), -1 (protocol/IO failure),
   -2 (certificate failure — never fall through to plaintext). */
static int tls_handshake(const char *host) {
    tls_rng_state = 0;
    tls_rand_seed();
    tls_hs_len = 0;
    tls_transcript_len = 0;
    tls_app_spill_len = 0; tls_app_spill_pos = 0;
    tls_send_seq = 0; tls_recv_seq = 0;
    tls_client_enc = 0; tls_server_enc = 0;
    /* ClientHello. */
    u8 hello[512];
    u32 pos = 0;
    hello[pos++] = 0x03; hello[pos++] = 0x03; /* TLS 1.2 */
    tls_rand(tls_client_random, 32);
    memcpy(hello + pos, tls_client_random, 32); pos += 32;
    hello[pos++] = 0; /* session id length */
    tput16(hello + pos, 2); pos += 2;
    tput16(hello + pos, 0x009C); pos += 2; /* RSA AES-128-GCM SHA256 */
    hello[pos++] = 1; /* compression methods length */
    hello[pos++] = 0; /* null compression */
    /* Extensions: SNI only. Layout, each length counting only
       the bytes AFTER its own field:
       extensions_length(2) | type(2)=0 | ext_length(2) |
       list_length(2) | name_type(1)=0 | name_length(2) | name.
       (An earlier draft omitted ext_length, which made
       openssl s_server reject the hello with
       "bad extension" — caught by testing against s_server.) */
    u32 ext_len_field = pos;
    pos += 2; /* extensions_length */
    tput16(hello + pos, 0); pos += 2; /* server_name extension type */
    u32 ext_data_len_field = pos;
    pos += 2; /* extension data length */
    u32 list_len_field = pos;
    pos += 2; /* server_name_list length */
    hello[pos++] = 0; /* host_name type */
    u32 host_len = strlen(host);
    if (host_len > 255) return -1;
    tput16(hello + pos, (u16)host_len); pos += 2;
    memcpy(hello + pos, host, host_len); pos += host_len;
    tput16(hello + list_len_field, (u16)(pos - list_len_field - 2));
    tput16(hello + ext_data_len_field, (u16)(pos - ext_data_len_field - 2));
    /* signature_algorithms extension (type 13): OpenSSL 3
       servers abort with "no suitable signature algorithm"
       without it. Offer SHA256+RSA only (the one suite
       this client verifies). */
    tput16(hello + pos, 13); pos += 2;
    tput16(hello + pos, 4); pos += 2; /* extension data length */
    tput16(hello + pos, 2); pos += 2; /* list length */
    hello[pos++] = 0x04; /* SHA256 */
    hello[pos++] = 0x01; /* RSA */
    tput16(hello + ext_len_field, (u16)(pos - ext_len_field - 2));
    if (tls_send_hs(1, hello, pos) != 0) return -1;
    /* ServerHello. (msg is a static buffer: an 8 KiB stack array
       would leave almost no room on the 16 KiB kernel stack.) */
    u8 *msg = tls_msg_buf;
    u32 msg_len = 0;
    int mtype = tls_next_hs(msg, 8192, &msg_len);
    if (mtype != 2) { return -1; }
    const u8 *sh = msg + 4;
    u32 sh_len = msg_len - 4;
    if (sh_len < 34) return -1;
    if (sh[0] != 0x03 || sh[1] != 0x03) return -1;
    memcpy(tls_server_random, sh + 2, 32);
    u32 spos = 34;
    if (spos >= sh_len) return -1;
    u32 sid_len = sh[spos++];
    if (spos + sid_len + 2 + 1 > sh_len) return -1;
    spos += sid_len;
    if (tget16(sh + spos) != 0x009C) return -1; /* cipher suite */
    spos += 2;
    if (sh[spos] != 0) return -1; /* compression must be null */
    if (transcript_append(msg, msg_len) != 0) return -1;
    /* Certificate. */
    mtype = tls_next_hs(msg, 8192, &msg_len);
    if (mtype != 11) { return -1; }
    const u8 *cm = msg + 4;
    u32 cm_len = msg_len - 4;
    if (cm_len < 3) return -1;
    u32 total_certs_len = tget24(cm);
    if (total_certs_len + 3 > cm_len) return -1;
    struct cert_info certs[4];
    int cert_count = 0;
    u32 cpos = 3;
    while (cpos < 3 + total_certs_len) {
        if (cpos + 3 > cm_len) return -2;
        u32 clen = tget24(cm + cpos);
        if (cpos + 3 + clen > cm_len) return -2;
        if (cert_count >= 4) return -2; /* chain too long */
        if (parse_cert(cm + cpos + 3, clen, &certs[cert_count]) != 0) return -2;
        cert_count++;
        cpos += 3 + clen;
    }
    if (cert_count == 0) return -2;
    if (verify_chain(certs, cert_count, host) != 0) { return -2; }
    tls_leaf_mod = certs[0].modulus;
    tls_leaf_exp = certs[0].exponent;
    if (transcript_append(msg, msg_len) != 0) return -1;
    /* ServerHelloDone (may share a record with Certificate in
       theory; the stream parser already handles that). */
    mtype = tls_next_hs(msg, 8192, &msg_len);
    if (mtype != 14) { return -1; }
    if (transcript_append(msg, msg_len) != 0) return -1;
    /* ClientKeyExchange: RSA-encrypted premaster. */
    u8 premaster[48];
    premaster[0] = 0x03; premaster[1] = 0x03;
    tls_rand(premaster + 2, 46);
    int bl = bn_bitlen(&tls_leaf_mod);
    u32 k = (u32)((bl + 7) / 8);
    if (k < 48 + 11 || k > 256) return -1;
    u8 em[256];
    em[0] = 0x00; em[1] = 0x02;
    for (u32 i = 2; i < k - 48 - 1; i++) {
        u8 r;
        do { tls_rand(&r, 1); } while (r == 0);
        em[i] = r;
    }
    em[k - 48 - 1] = 0x00;
    memcpy(em + k - 48, premaster, 48);
    bn_t em_bn, ct_bn;
    if (bn_from_be(&em_bn, em, k) != 0) return -1;
    if (bn_modexp(&ct_bn, &em_bn, tls_leaf_exp, &tls_leaf_mod) != 0) return -1;
    u8 ct[256];
    if (bn_to_be(&ct_bn, ct, k) != 0) return -1;
    u8 ckx[512];
    tput16(ckx, (u16)k);
    memcpy(ckx + 2, ct, k);
    if (tls_send_hs(16, ckx, k + 2) != 0) { return -1; }
    /* Master secret + key block. */
    u8 seed_ms[64];
    memcpy(seed_ms, tls_client_random, 32);
    memcpy(seed_ms + 32, tls_server_random, 32);
    tls_prf(premaster, 48, "master secret", seed_ms, 64, tls_master, 48);
    u8 seed_ke[64];
    memcpy(seed_ke, tls_server_random, 32);
    memcpy(seed_ke + 32, tls_client_random, 32);
    u8 key_block[40];
    tls_prf(tls_master, 48, "key expansion", seed_ke, 64, key_block, 40);
    memcpy(tls_client_key, key_block, 16);
    memcpy(tls_server_key, key_block + 16, 16);
    memcpy(tls_client_iv, key_block + 32, 4);
    memcpy(tls_server_iv, key_block + 36, 4);
    /* ChangeCipherSpec, then Finished. */
    {
        u8 ccs = 0x01;
        if (tls_send_record(20, &ccs, 1) != 0) return -1;
    }
    tls_client_enc = 1;
    {
        u8 hash[32];
        sha256_compute(tls_transcript, tls_transcript_len, hash);
        u8 verify[12];
        tls_prf(tls_master, 48, "client finished", hash, 32, verify, 12);
        if (tls_send_hs(20, verify, 12) != 0) { return -1; }
    }
    /* Server CCS + Finished. */
    {
        u32 rec_len = 0;
        int rt = tls_recv_record(&rec_len);
        if (rt != 20 || rec_len != 1 || tls_rec_buf[0] != 0x01) return -1;
    }
    tls_server_enc = 1;
    mtype = tls_next_hs(msg, 8192, &msg_len);
    if (mtype != 20) { return -1; }
    {
        /* Verify server Finished over the transcript that
           includes our Finished but not yet theirs. */
        u8 hash[32];
        sha256_compute(tls_transcript, tls_transcript_len, hash);
        u8 expect[12];
        tls_prf(tls_master, 48, "server finished", hash, 32, expect, 12);
        if (msg_len != 16) return -1; /* 4 header + 12 verify */
        if (memcmp(msg + 4, expect, 12) != 0) return -1;
    }
    return 0;
}

/* ---------- App data + HTTPS ---------- */
static int tls_send_app(const u8 *data, u32 len) {
    return tls_send_record(23, data, len);
}
/* App-data spill: a server may send a record larger than the
   caller's buffer (s_server's -www page arrived as one 1534-byte
   plaintext record against a 1024-byte read buffer, which used
   to fail the whole fetch). Leftover bytes wait in the static
   spill buffer (declared with the other statics above) and are
   returned by later calls. */
/* Returns bytes read, 0 on timeout slice, -1 on close/error. */
static int tls_recv_app(u8 *buf, u32 max) {
    if (tls_app_spill_pos < tls_app_spill_len) {
        u32 avail = tls_app_spill_len - tls_app_spill_pos;
        u32 n = avail < max ? avail : max;
        memcpy(buf, tls_app_spill + tls_app_spill_pos, n);
        tls_app_spill_pos += n;
        if (tls_app_spill_pos == tls_app_spill_len) {
            tls_app_spill_len = 0; tls_app_spill_pos = 0;
        }
        return (int)n;
    }
    u32 rec_len = 0;
    int rt = tls_recv_record(&rec_len);
    if (rt < 0) return -1;
    if (rt == 21) return -1; /* alert: treat as close/error */
    if (rt != 23) return -1;
    if (rec_len > max) {
        memcpy(buf, tls_rec_buf, max);
        memcpy(tls_app_spill, tls_rec_buf + max, rec_len - max);
        tls_app_spill_len = rec_len - max;
        tls_app_spill_pos = 0;
        return (int)max;
    }
    memcpy(buf, tls_rec_buf, rec_len);
    return (int)rec_len;
}
int net_https_get(const char *host, u16 port, const char *path, char *buf, u32 max) {
    if (max < 2) return -1;
    ip_t hip;
    if (!net_parse_ip(host, &hip)) {
        if (net_dns_lookup(host, &hip) != 0) return -1;
    }
    if (net_tcp_connect(hip, port) != 0) return -1;
    int hs = tls_handshake(host);
    if (hs != 0) { net_tcp_close(); return hs; }
    char req[512];
    int ri = 0;
    const char *p;
    p = "GET "; while (*p) req[ri++] = *p++;
    p = path; while (*p && ri < 400) req[ri++] = *p++;
    p = " HTTP/1.0\r\nHost: "; while (*p) req[ri++] = *p++;
    p = host; while (*p && ri < 480) req[ri++] = *p++;
    p = "\r\n\r\n"; while (*p) req[ri++] = *p++;
    req[ri] = 0;
    if (tls_send_app((const u8 *)req, (u32)ri) != 0) { net_tcp_close(); return -1; }
    u8 tmp[1024];
    u32 total = 0, header_end = 0, content_len = 0xFFFFFFFFu;
    u32 start = timer_ticks;
    while (timer_ticks - start < 1000) {
        int n = tls_recv_app(tmp, sizeof(tmp));
        if (n < 0) break;
        if (n == 0) {
            if (header_end && content_len != 0xFFFFFFFFu &&
                total >= header_end + content_len) break;
            continue;
        }
        if (total + (u32)n > max - 1) { net_tcp_close(); return -1; }
        memcpy(buf + total, tmp, (u32)n);
        total += (u32)n;
        buf[total] = 0;
        if (!header_end) {
            for (u32 i = 0; i + 3 < total; i++) {
                if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
                    header_end = i + 4;
                    break;
                }
            }
            if (header_end) {
                for (u32 i = 0; i + 15 < header_end; i++) {
                    if ((buf[i]=='C' || buf[i]=='c') &&
                        memcmp(buf + i, "ontent-Length:", 14) == 0) {
                        u32 j = i + 15, v = 0;
                        while (j < header_end && buf[j] == ' ') j++;
                        while (j < header_end && buf[j] >= '0' && buf[j] <= '9') {
                            v = v * 10 + (u32)(buf[j] - '0'); j++;
                        }
                        content_len = v;
                        break;
                    }
                }
                for (u32 i = 0; i + 17 < header_end; i++) {
                    if (memcmp(buf + i, "Transfer-Encoding:", 18) == 0) {
                        net_tcp_close(); return -1;
                    }
                }
            }
        }
        if (header_end && content_len != 0xFFFFFFFFu && total >= header_end + content_len) break;
    }
    net_tcp_close();
    if (!header_end) return -1;
    u32 body_len = total - header_end;
    memmove(buf, buf + header_end, body_len);
    buf[body_len] = 0;
    return (int)body_len;
}
