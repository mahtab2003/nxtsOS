/* TLS 1.3 + TLS 1.2 client (Phases 9.2, web/SSL Phase 2).
   Suites: TLS_AES_128_GCM_SHA256 (0x1301, TLS 1.3 only),
   ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F),
   ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC00A),
   TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C).
   ECDHE is P-256 only (net/ec256.c); certificates may be RSA
   or ECDSA P-256. X.509 chain verification with the same
   three trust modes and the same chain-termination rule as
   the TLS 1.2 client (stop at the first anchor / store
   member, or — TOFU — before the first oversize key).
   What it is NOT (stated plainly, because TLS security
   claims must not be inflated):
   - Three trust modes. Default (`https`) is TOFU: every link's
     signature must verify with the next certificate's key,
     dates must be valid, the leaf must match the requested
     host, and the terminal certificate must either be
     self-signed with a verifying self-signature (the
     single-cert case) or a real CA (CA:true). Real servers
     never send their root, so the terminal is normally an
     intermediate — demanding a self-signed terminal refused
     every real site (fixed after the v1.1.0 real-device
     report: example.com always "certificate refused").
     TOFU proves the chain is self-consistent, bound to the
     host, and that the server holds the matching private
     key — but it is NOT CA authentication: a man in the
     middle with their own chain for the same hostname
     would also pass. That is why TOFU now pins the leaf
     fingerprint per host in root-owned tofuprints.txt:
     the first fetch for a host records it, and a later
     fetch with a different leaf for the same host is a
     hard refusal (a changed leaf means re-trust must be
     explicit: `tofprints clear <host>` as root). Without
     a disk there is nothing to pin to, so diskless TOFU
     proceeds without recording (and says so).
     Anchored mode (`httpsa`, and the repository client
     over HTTPS) instead requires the terminal certificate's
     key to equal a pinned anchor: the compiled-in anchor
     (Google Trust Services WR1, which issues *.vercel.app)
     or a key in root-owned tlsanchors.txt. The anchor
     need not be self-signed — WR1 is issued by GTS Root R1,
     whose 4096-bit key this 2048-bit kernel cannot verify,
     so the pin IS the trust root by design. If the anchor
     rotates, anchored handshakes fail closed until the
     kernel carries the new anchor (re-run genanchor.py).
     Store mode (`httpss`) requires a chain certificate's
     key to equal a member of the root-owned CA store
     (castore.txt: RSA-2048 modulus lines, or EC256: P-256
     point lines): the general trust store, updatable by
     root via `castore add` or a vendor-signed bundle
     fetched over anchored HTTPS (`castore update`). In all
     three modes validation stops at the trust point
     (anchor or store member) or, for TOFU, at the first
     oversize key: certificates after that point are not
     part of the validated path, which is what makes a sent
     4096-bit root harmless.
   - Negotiation policy (non-negotiable): the ClientHello
     offers TLS 1.3 + TLS 1.2 ONLY. No legacy version is
     ever offered, and a failed modern handshake NEVER
     retries in legacy — there is no fallback path at all.
     A ServerHello below TLS 1.2, or a TLS 1.3 downgrade
     sentinel in the ServerHello random, is a hard refusal.
     The repository path is modern-only anchored, always.
   - No session resumption, no PSK, no 0-RTT (replay risk),
     no HelloRetryRequest support (a server that demands a
     different group fails closed — this client offers
     secp256r1 only, so a compliant server never sends
     one), no certificate revocation checking.
     KeyUpdate in the application phase fails closed (a
     fetch never runs long enough to rotate keys in
     practice); NewSessionTicket messages are skipped.
     ALPN sends http/1.1 only (the server's selection is
     not parsed); hostname matching allows one left-label
     wildcard (*.example matches foo.example, not example
     or a.b.example), never for IP literals. A
     ServerKeyExchange / CertificateVerify signature that
     does not verify fails closed, never falling back to
     another key exchange or signature algorithm. The
     client sends no ChangeCipherSpec after ClientHello:
     CCS is optional in TLS 1.3 middlebox-compat mode and
     an early CCS would break strict TLS 1.2 servers, so
     it is omitted (a server CCS after ServerHello is
     tolerated and skipped).
   - Randomness comes from the ChaCha20 DRBG (kernel/
     csprng.c): RTC + keyboard/mouse event timing + MAC
     uniqueness. The old timer/MAC xorshift is gone from
     every crypto path (it survives only in window-manager
     test shuffles, which are not security uses).
   - Only one connection at a time, like the TCP client. */
#include "net.h"
#include "bignum.h"
#include "rsaverify.h"
#include "ec256.h"
#include "tls_anchor.h"
#include "../kernel/sha256.h"
#include "../kernel/aes.h"
#include "../kernel/csprng.h"
#include "../kernel/pkg.h"
#include "../kernel/console.h"
#include "../fs/vfs.h"
#include "../drivers/pit.h"

/* ---------- small helpers ---------- */
static void tput16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void tput24(u8 *p, u32 v) { p[0] = (u8)(v >> 16); p[1] = (u8)(v >> 8); p[2] = (u8)v; }
static void tput32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v;
}
static u16 tget16(const u8 *p) { return (u16)(((u16)p[0] << 8) | p[1]); }
static u32 tget24(const u8 *p) { return ((u32)p[0] << 16) | ((u32)p[1] << 8) | p[2]; }

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
static const u8 OID_EC_PUBKEY[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
static const u8 OID_SECP256R1[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static const u8 OID_ECDSA_SHA256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
static const u8 OID_CN[] = {0x55, 0x04, 0x03};
static const u8 OID_BC[] = {0x55, 0x1D, 0x13};
static const u8 OID_SAN[] = {0x55, 0x1D, 0x11};

/* ---------- Certificate ---------- */
#define MAX_SAN_DNS 4
#define MAX_SAN_IP 4
struct cert_info {
    const u8 *tbs; u32 tbs_len;
    const u8 *issuer; u32 issuer_len;
    const u8 *subject; u32 subject_len;
    char not_before[15], not_after[15];
    int key_type; /* 0 = RSA, 1 = EC P-256 */
    int sig_alg; /* 0 = RSA/SHA-256, 1 = ECDSA P-256/SHA-256 */
    bn_t modulus; u32 exponent; /* RSA only */
    u8 ec_x[32], ec_y[32]; /* EC only: uncompressed point */
    const u8 *sig; u32 sig_len;
    int ca_flag; /* 1 = BC CA:true, 0 = BC CA:false, -1 = no BC */
    int key_oversize; /* 1 = public key >2048 bits (bn_from_be
       refused it): the modulus is zeroed, never truncated,
       so no signature can verify with it. parse_cert still
       parses the rest of the cert; verify_chain decides
       whether this cert is inside or beyond the validated
       path (beyond the anchor / past the truncation point
       it is ignored, inside it it fails closed). */
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
        if (der_oid_equal(buf + op, ov, OID_SHA256_RSA, sizeof(OID_SHA256_RSA))) ci->sig_alg = 0;
        else if (der_oid_equal(buf + op, ov, OID_ECDSA_SHA256, sizeof(OID_ECDSA_SHA256))) ci->sig_alg = 1;
        else return -1;
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
        int inner_alg;
        if (der_oid_equal(buf + op, ov, OID_SHA256_RSA, sizeof(OID_SHA256_RSA))) inner_alg = 0;
        else if (der_oid_equal(buf + op, ov, OID_ECDSA_SHA256, sizeof(OID_ECDSA_SHA256))) inner_alg = 1;
        else return -1;
        if (inner_alg != ci->sig_alg) return -1;
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
        if (der_oid_equal(buf + op, ov, OID_EC_PUBKEY, sizeof(OID_EC_PUBKEY))) {
            /* EC P-256: parameters must be exactly the
               secp256r1 OID, then the BIT STRING is the
               65-byte uncompressed point. */
            ci->key_type = 1;
            u8 pt; u32 ph, pv, pp;
            if (der_tlv(buf, len, op + ov, &pt, &ph, &pv, &pp) != 0 || pt != 0x06) return -1;
            if (!der_oid_equal(buf + pp, pv, OID_SECP256R1, sizeof(OID_SECP256R1))) return -1;
            if (pp + pv != ap + av) return -1;
            u8 bt; u32 bh, bv, bpos;
            if (der_tlv(buf, len, ap + av, &bt, &bh, &bv, &bpos) != 0 || bt != 0x03) return -1;
            if (bv != 66 || buf[bpos] != 0 || buf[bpos + 1] != 0x04) return -1;
            memcpy(ci->ec_x, buf + bpos + 2, 32);
            memcpy(ci->ec_y, buf + bpos + 34, 32);
            if (p256_point_valid(ci->ec_x, ci->ec_y) != 0) return -1;
            ci->exponent = 0;
        } else if (der_oid_equal(buf + op, ov, OID_RSA_ENC, sizeof(OID_RSA_ENC))) {
            ci->key_type = 0;
            u32 bp = ap + av;
            u8 bt; u32 bh, bv, bpos;
            if (der_tlv(buf, len, bp, &bt, &bh, &bv, &bpos) != 0 || bt != 0x03) return -1;
            if (bv < 1 || buf[bpos] != 0) return -1;
            /* RSAPublicKey SEQUENCE inside the BIT STRING. */
            u8 rt; u32 rh, rv, rp;
            if (der_tlv(buf, len, bpos + 1, &rt, &rh, &rv, &rp) != 0 || rt != 0x30) return -1;
            u8 mt; u32 mh, mv, mp;
            if (der_tlv(buf, len, rp, &mt, &mh, &mv, &mp) != 0 || mt != 0x02) return -1;
            if (bn_from_be(&ci->modulus, buf + mp, mv) != 0) {
                /* Oversize key (>2048 bits, e.g. a 4096-bit root
                   like GTS Root R1): bn_from_be zeroes the
                   modulus and fails ONLY on size (see
                   net/bignum.c), so this flag is precise and
                   the key is never silently truncated to 2048
                   bits. The rest of the certificate still
                   parses (dates, issuer/subject, CA flag,
                   signature bytes); verify_chain decides
                   whether this cert lies inside the validated
                   path (then it fails closed: no signature
                   verifies with a zeroed modulus) or beyond
                   it (then it is ignored, exactly as if the
                   server had withheld it). */
                ci->key_oversize = 1;
            }
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
        } else {
            return -1; /* unknown public key algorithm */
        }
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
/* Convert a DER INTEGER value to a 32-byte big-endian value:
   strips at most one leading zero (DER sign byte); rejects
   empty values, values longer than 33 bytes, and values that
   still exceed 32 bytes after stripping. */
static int der_int_to_32(const u8 *v, u32 len, u8 out[32]) {
    if (len == 0 || len > 33) return -1;
    u32 off = 0;
    if (len == 33) {
        if (v[0] != 0) return -1;
        off = 1;
    }
    memset(out, 0, 32);
    memcpy(out + (32 - (len - off)), v + off, len - off);
    return 0;
}
/* Parse an ECDSA signature: DER SEQUENCE { INTEGER r, INTEGER s }
   into two 32-byte big-endian values. Strict: the SEQUENCE
   length must cover exactly the input, both INTEGERs must
   be present, and each INTEGER goes through der_int_to_32
   (at most one leading zero sign byte, max 33 bytes). */
static int der_sig_to_rs(const u8 *sig, u32 sig_len, u8 r[32], u8 s[32]) {
    if (sig_len < 2 || sig[0] != 0x30) return -1;
    u32 pos, seq_len;
    if (sig[1] < 0x80) { seq_len = sig[1]; pos = 2; }
    else if (sig[1] == 0x81 && sig_len >= 3) { seq_len = sig[2]; pos = 3; }
    else return -1;
    if (pos + seq_len != sig_len) return -1;
    if (pos + 2 > sig_len || sig[pos] != 0x02) return -1;
    u32 rlen = sig[pos + 1];
    if (rlen == 0 || pos + 2 + rlen > sig_len) return -1;
    if (der_int_to_32(sig + pos + 2, rlen, r) != 0) return -1;
    pos += 2 + rlen;
    if (pos + 2 > sig_len || sig[pos] != 0x02) return -1;
    u32 slen = sig[pos + 1];
    if (slen == 0 || pos + 2 + slen != sig_len) return -1;
    if (der_int_to_32(sig + pos + 2, slen, s) != 0) return -1;
    return 0;
}
/* Verify cert's signature with the issuer's key. The signature
   algorithm recorded in the certificate must match the issuer
   key type: RSA/SHA-256 (PKCS#1 v1.5, net/rsaverify.c) or
   ECDSA P-256/SHA-256 (DER r,s, net/ec256.c). A mismatch
   (e.g. an ECDSA signature claimed under an RSA key) fails
   closed. */
static int verify_signature(const struct cert_info *cert,
                            const struct cert_info *issuer) {
    if (cert->sig_alg == 0) {
        if (issuer->key_type != 0) return -1;
        /* Shared PKCS#1 v1.5 / SHA-256 verifier
           (net/rsaverify.c), also used for package
           signatures. The modulus is passed as the minimal
           big-endian form (bit length rounded up). */
        int bl = bn_bitlen(&issuer->modulus);
        u32 k = (u32)((bl + 7) / 8);
        if (k < 51 + 11) return -1; /* too small for DigestInfo + padding */
        u8 mod_bytes[256];
        if (k > sizeof(mod_bytes)) return -1;
        if (bn_to_be(&issuer->modulus, mod_bytes, k) != 0) return -1;
        return rsa_verify_sha256(mod_bytes, k, issuer->exponent,
                                 cert->sig, cert->sig_len,
                                 cert->tbs, cert->tbs_len);
    }
    if (cert->sig_alg == 1) {
        if (issuer->key_type != 1) return -1;
        /* DER SEQUENCE { INTEGER r, INTEGER s }. */
        u8 tag; u32 hl, vl, vp;
        if (der_tlv(cert->sig, cert->sig_len, 0, &tag, &hl, &vl, &vp) != 0 || tag != 0x30) return -1;
        if (hl + vl != cert->sig_len) return -1;
        u8 rt; u32 rh, rv, rp;
        if (der_tlv(cert->sig, cert->sig_len, vp, &rt, &rh, &rv, &rp) != 0 || rt != 0x02) return -1;
        u8 st; u32 sh, sv, sp;
        if (der_tlv(cert->sig, cert->sig_len, rp + rv, &st, &sh, &sv, &sp) != 0 || st != 0x02) return -1;
        if (sp + sv != cert->sig_len) return -1;
        u8 r[32], s[32];
        if (der_int_to_32(cert->sig + rp, rv, r) != 0) return -1;
        if (der_int_to_32(cert->sig + sp, sv, s) != 0) return -1;
        u8 hash[32];
        sha256_compute(cert->tbs, cert->tbs_len, hash);
        return p256_ecdsa_verify(issuer->ec_x, issuer->ec_y, hash, r, s);
    }
    return -1;
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
/* Trust mode (Phase 12 anchors, Phase 13 store): 0 = TOFU,
   1 = anchored, 2 = CA store. Set by net_https_get (0),
   net_https_get_anchored (1), net_https_get_store (2) before
   the handshake; single connection at a time, so no race. */
static int tls_verify_mode = 0;
/* Well-formed anchor/store line SHAPE (not a match): an RSA
   512-hex line, or an EC line "EC256:" + 130 hex chars whose
   point starts with the 0x04 uncompressed tag. Used by the
   shell `castore list` counter and by bundle validation, so
   all three agree on what counts as a root. */
int tls_key_line_valid(const char *line, u32 ll) {
    if (ll == 512) {
        for (u32 i = 0; i < 512; i++) {
            char c = line[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'))) return 0;
        }
        return 1;
    }
    if (ll == 136 && memcmp(line, "EC256:", 6) == 0) {
        for (u32 i = 6; i < 136; i++) {
            char c = line[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'))) return 0;
        }
        /* First point byte must be the 0x04 tag. */
        char h0 = line[6], h1 = line[7];
        int v0 = (h0 >= '0' && h0 <= '9') ? h0 - '0' :
                 (h0 >= 'a' && h0 <= 'f') ? h0 - 'a' + 10 :
                 (h0 >= 'A' && h0 <= 'F') ? h0 - 'A' + 10 : -1;
        int v1 = (h1 >= '0' && h1 <= '9') ? h1 - '0' :
                 (h1 >= 'a' && h1 <= 'f') ? h1 - 'a' + 10 :
                 (h1 >= 'A' && h1 <= 'F') ? h1 - 'A' + 10 : -1;
        if (v0 < 0 || v1 < 0) return 0;
        return ((v0 << 4) | v1) == 0x04;
    }
    return 0;
}
/* Match a certificate's key against a root-owned key file
   (anchor file or CA store). Lines: one 512-hex-char
   RSA-2048 modulus per line (exponent 65537), or one
   "EC256:" + 130-hex-char P-256 point line. Blank lines
   and '#' comment lines are skipped; malformed lines are
   skipped with a warning, never trusted. A missing file is
   not an error (empty set). Shared by the anchor file
   (tlsanchors.txt) and the CA store (castore.txt): the two
   files differ only in what membership MEANS (a pin vs a
   general trust root), not in format. Returns 1 on match. */
/* One line of an anchor/store file: blank and '#' lines are
   skipped silently, any other malformed line earns one console
   note (same as the old whole-file scan). Returns 1 on a
   key match. */
static int tls_modulus_line_match(const char *line, u32 ll,
                                  const struct cert_info *term,
                                  const char *what) {
    if (ll == 0) return 0;
    if (line[0] == '#') return 0;
    if (ll >= 6 && memcmp(line, "EC256:", 6) == 0) {
        if (term->key_type != 1) return 0; /* EC line, RSA term */
        if (!tls_key_line_valid(line, ll)) {
            console_write("tls: skipping malformed ");
            console_write(what);
            console_write(" line\n");
            return 0;
        }
        u8 pt[65];
        for (int i = 0; i < 65; i++) {
            char h0 = line[6 + i * 2], h1 = line[6 + i * 2 + 1];
            int v0 = (h0 >= '0' && h0 <= '9') ? h0 - '0' :
                     (h0 >= 'a' && h0 <= 'f') ? h0 - 'a' + 10 :
                     (h0 >= 'A' && h0 <= 'F') ? h0 - 'A' + 10 : -1;
            int v1 = (h1 >= '0' && h1 <= '9') ? h1 - '0' :
                     (h1 >= 'a' && h1 <= 'f') ? h1 - 'a' + 10 :
                     (h1 >= 'A' && h1 <= 'F') ? h1 - 'A' + 10 : -1;
            if (v0 < 0 || v1 < 0) return 0; /* already validated */
            pt[i] = (u8)((v0 << 4) | v1);
        }
        return pt[0] == 0x04 &&
               memcmp(pt + 1, term->ec_x, 32) == 0 &&
               memcmp(pt + 33, term->ec_y, 32) == 0;
    }
    if (ll != 512) {
        console_write("tls: skipping malformed ");
        console_write(what);
        console_write(" line\n");
        return 0;
    }
    if (term->key_type != 0) return 0; /* RSA line, EC term */
    u8 mod[256];
    int bad = 0;
    for (int i = 0; i < 256; i++) {
        char h0 = line[i * 2], h1 = line[i * 2 + 1];
        int v0 = (h0 >= '0' && h0 <= '9') ? h0 - '0' :
                 (h0 >= 'a' && h0 <= 'f') ? h0 - 'a' + 10 :
                 (h0 >= 'A' && h0 <= 'F') ? h0 - 'A' + 10 : -1;
        int v1 = (h1 >= '0' && h1 <= '9') ? h1 - '0' :
                 (h1 >= 'a' && h1 <= 'f') ? h1 - 'a' + 10 :
                 (h1 >= 'A' && h1 <= 'F') ? h1 - 'A' + 10 : -1;
        if (v0 < 0 || v1 < 0) { bad = 1; break; }
        mod[i] = (u8)((v0 << 4) | v1);
    }
    if (bad) {
        console_write("tls: skipping malformed ");
        console_write(what);
        console_write(" line\n");
        return 0;
    }
    bn_t cand;
    if (term->exponent == 65537u &&
        bn_from_be(&cand, mod, 256) == 0 &&
        bn_cmp(&cand, &term->modulus) == 0) return 1;
    return 0;
}

/* Windowed modulus-membership scan with exactly the line
   semantics above, but no whole-file size limit: the old
   8192-byte fs_read silently refused every store over ~15
   roots (fs_read refuses when the file exceeds the buffer),
   so a vendor bundle near the 65535-byte install cap would
   install fine and then match NOTHING. Windows are 1024
   bytes via fs_read_range_as (uid 0 = the same kernel-root
   context the old fs_read shortcut ran in); a partial line
   is carried across window boundaries, and a final line
   without a trailing newline still counts. A missing or
   unreadable file is no match, never an error. */
static int tls_file_modulus_match(const char *fname,
                                  const struct cert_info *term,
                                  const char *what) {
    static u8 win[1024];
    char line[513];
    u32 line_len = 0, off = 0;
    for (;;) {
        u32 got = 0;
        if (fs_read_range_as(fname, win, sizeof(win), off, &got, 0) != 0)
            return 0;
        if (got == 0) break;
        off += got;
        for (u32 i = 0; i < got; i++) {
            u8 c = win[i];
            if (c == '\n') {
                if (line_len == 513) {
                    console_write("tls: skipping malformed ");
                    console_write(what);
                    console_write(" line\n");
                } else if (tls_modulus_line_match(line, line_len,
                                                  term, what)) {
                    return 1;
                }
                line_len = 0;
            } else if (line_len < 512) {
                line[line_len++] = (char)c;
            } else {
                line_len = 513; /* overlong: malformed, keep draining */
            }
        }
    }
    if (line_len == 513) {
        console_write("tls: skipping malformed ");
        console_write(what);
        console_write(" line\n");
    } else if (line_len > 0 &&
               tls_modulus_line_match(line, line_len, term, what)) {
        return 1;
    }
    return 0;
}
/* Does the given certificate's key equal a pinned anchor?
   Called on each chain position in anchored mode (the path
   ends at the first match) and on the path terminal as an
   explicit gate. Anchors, tried in order (mirrors the
   package keyring model):
   the compiled-in anchor (Google Trust Services WR1, which
   issues *.vercel.app), then each well-formed line of the
   root-owned tlsanchors.txt file (one 512-hex-char RSA-2048
   modulus per line, exponent 65537). A missing anchor file is
   not an error. The file MUST be root-owned and is a system
   file (see fs/nxtsfs.c): a non-root user who could plant an
   anchor could pin their own MITM key. Returns 1 on match. */
static int tls_anchor_match(const struct cert_info *term) {
    bn_t anchor;
    if (term->key_type == 0 &&
        term->exponent == TLS_ANCHOR_EXP &&
        bn_from_be(&anchor, TLS_ANCHOR_MOD, 256) == 0 &&
        bn_cmp(&anchor, &term->modulus) == 0) return 1;
    return tls_file_modulus_match("tlsanchors.txt", term, "anchor");
}
/* Does the given certificate's key equal a member of the CA
   store? Same format and same root-owned system-file rule as
   the anchor file; membership here means "general trust root"
   instead of "this one pin". Returns 1 on match. */
static int tls_store_match(const struct cert_info *term) {
    return tls_file_modulus_match("castore.txt", term, "store");
}
/* DNS-name match with one left-label wildcard. Returns 1 on
   match. "*.example" matches "foo.example" only: not "example"
   itself, not "a.b.example" (the label must be non-empty and
   contain no dot). Any other "*" placement is not a wildcard
   and falls through to exact match (a literal "*" never
   occurs in a real host, so this fails closed). Callers use
   this for DNS names only, never for IP literals. */
static int host_matches_name(const char *pattern, const char *host) {
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *suffix = pattern + 2;
        if (!*suffix) return 0;
        /* host must end with suffix, preceded by "." + one label. */
        u32 slen = strlen(suffix), hlen = strlen(host);
        if (hlen <= slen + 1) return 0; /* no room for label + dot */
        if (!ascii_equal_nocase(host + hlen - slen, suffix)) return 0;
        if (host[hlen - slen - 1] != '.') return 0;
        for (u32 i = 0; i < hlen - slen - 1; i++)
            if (host[i] == '.') return 0; /* multi-label: no match */
        return 1;
    }
    return ascii_equal_nocase(pattern, host);
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
            if (host_matches_name(leaf->san_dns[i], host)) return 0;
        return -1; /* SAN present but no match: no CN fallback */
    }
    if (host_is_ip) {
        /* No SAN: compare CN textually to the dotted host.
           Wildcards never apply to IP literals. */
        return ascii_equal_nocase(leaf->cn, host) ? 0 : -1;
    }
    return host_matches_name(leaf->cn, host) ? 0 : -1;
}
/* Hostname self-test (shell `hostmatch`, nettest pattern).
   Calls the real verify_host on fabricated leaf structs, so it
   proves the matcher AND its call sites (SAN loop, CN
   fallback, IP branch) without needing guest DNS — guest DNS
   over slirp UDP is sandbox-blocked, so a live wildcard-SAN
   handshake cannot run here (see AUTONOMOUS.md). Returns 0
   when every case matches its expectation. The leaf is a
   file-scope static: verify_host reads only has_san /
   san_dns / san_ip / cn, and a cert_info on the 16 KiB
   kernel stack would be gratuitous. */
static struct cert_info hm_leaf;
static void hm_set_name(char *dst, const char *src) {
    int i = 0;
    while (src[i] && i < 63) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}
static int hm_failures = 0;
static void hm_check(int got, int want, const char *msg) {
    if (got != want) {
        console_printf("hostmatch FAIL: %s (got %d, want %d)\n", msg, got, want);
        hm_failures++;
    }
}
int tls_hostmatch_selftest(void) {
    hm_failures = 0;
    /* SAN wildcard cases. */
    memset(&hm_leaf, 0, sizeof(hm_leaf));
    hm_leaf.has_san = 1; hm_leaf.san_dns_count = 1;
    hm_set_name(hm_leaf.san_dns[0], "*.wild.test");
    hm_check(verify_host(&hm_leaf, "one.wild.test"), 0, "wildcard one label");
    hm_check(verify_host(&hm_leaf, "wild.test"), -1, "wildcard bare domain");
    hm_check(verify_host(&hm_leaf, "a.b.wild.test"), -1, "wildcard multi label");
    hm_check(verify_host(&hm_leaf, "ONE.WILD.TEST"), 0, "wildcard case-insensitive");
    hm_check(verify_host(&hm_leaf, "one.wild.test."), -1, "wildcard trailing dot");
    hm_set_name(hm_leaf.san_dns[0], "other.test");
    hm_check(verify_host(&hm_leaf, "one.wild.test"), -1, "exact mismatch");
    hm_set_name(hm_leaf.san_dns[0], "wild.test");
    hm_check(verify_host(&hm_leaf, "wild.test"), 0, "exact match still works");
    hm_set_name(hm_leaf.san_dns[0], "*.");
    hm_check(verify_host(&hm_leaf, "one.wild.test"), -1, "empty suffix");
    hm_set_name(hm_leaf.san_dns[0], "foo.*.test");
    hm_check(verify_host(&hm_leaf, "foo.bar.test"), -1, "mid-label star");
    /* CN fallback cases (no SAN). */
    memset(&hm_leaf, 0, sizeof(hm_leaf));
    hm_set_name(hm_leaf.cn, "*.wild.test");
    hm_check(verify_host(&hm_leaf, "one.wild.test"), 0, "CN wildcard");
    hm_check(verify_host(&hm_leaf, "a.b.wild.test"), -1, "CN wildcard multi");
    hm_set_name(hm_leaf.cn, "wild.test");
    hm_check(verify_host(&hm_leaf, "10.0.2.2"), -1, "CN vs IP host");
    /* IP branch cases. */
    memset(&hm_leaf, 0, sizeof(hm_leaf));
    hm_leaf.has_san = 1; hm_leaf.san_ip_count = 1;
    hm_leaf.san_ip[0][0] = 10; hm_leaf.san_ip[0][1] = 0;
    hm_leaf.san_ip[0][2] = 2; hm_leaf.san_ip[0][3] = 2;
    hm_check(verify_host(&hm_leaf, "10.0.2.2"), 0, "SAN IP match");
    hm_leaf.san_ip_count = 0; hm_leaf.san_dns_count = 1;
    hm_set_name(hm_leaf.san_dns[0], "*.wild.test");
    hm_check(verify_host(&hm_leaf, "10.0.2.2"), -1, "IP host never matches DNS SAN");
    console_printf("hostmatch: %d failures\n", hm_failures);
    return hm_failures == 0 ? 0 : -1;
}
/* Full chain verification. certs[0] is the leaf. Returns 0 or -1.
   -2 is reserved by the caller for certificate failures; this
   function only returns 0/-1 (the caller maps -1 to -2).
   The VALIDATED PATH is a prefix of the presented chain:
   - Anchored mode: the path ends at the FIRST pinned anchor
     cert (index >= 1, CA-flagged, key equal to a pinned
     anchor). Validation stops at the trust anchor (RFC 5280
     path validation): certs after the anchor are not part
     of the path, so their dates, names, and signatures are
     not checked — exactly as if the server had withheld
     them. A chain with no pinned anchor is refused.
   - Store mode: identical, but the path ends at the FIRST
     CA-store member (index >= 1, CA-flagged, key in
     castore.txt). A chain with no store member is refused.
   - TOFU mode: the path ends just before the first cert
     whose key is oversize (key_oversize), because no link
     into such a key can be verified. That is equivalent to
     the server having withheld that cert and all after it,
     which TOFU already accepts — so it grants an attacker
     nothing new: any chain acceptable under truncation is
     also acceptable with the tail simply not sent. A chain
     whose LEAF key is oversize is refused (empty path).
   Inside the path, every rule still holds: dates for every
   path cert, leaf hostname match, every link's issuer ==
   next subject + CA flag + signature verification. A link
   that must actually be verified and cannot be (oversize
   key, bad signature, wrong name, non-CA issuer) refuses.
   The anchor's own signature is never verified: the anchor
   IS the trust root by pinning (its issuer's key is a
   4096-bit root this 2048-bit kernel cannot verify, which
   is why pinning exists at all). */
static int verify_chain(const struct cert_info *certs, int count, const char *host) {
    char now[15];
    rtc_now_str(now);
    int path_len = count;
    if (tls_verify_mode == 1) {
        path_len = -1;
        for (int i = 1; i < count; i++) {
            if (certs[i].ca_flag == 1 && tls_anchor_match(&certs[i])) {
                path_len = i + 1;
                break;
            }
        }
        if (path_len < 0) { return -1; }
    } else if (tls_verify_mode == 2) {
        path_len = -1;
        for (int i = 1; i < count; i++) {
            if (certs[i].ca_flag == 1 && tls_store_match(&certs[i])) {
                path_len = i + 1;
                break;
            }
        }
        if (path_len < 0) { return -1; }
    } else {
        for (int i = 0; i < count; i++) {
            if (certs[i].key_oversize) { path_len = i; break; }
        }
        if (path_len < 1) { return -1; }
    }
    for (int i = 0; i < path_len; i++) {
        /* Belt-and-braces: no oversize key may sit inside
           the validated path (in TOFU mode the path ends
           before the first oversize cert by construction;
           in anchored/store mode a pinned anchor / store
           member is 2048-bit by construction, so an oversize
           cert here means a broken path, not a trailing root). */
        if (certs[i].key_oversize) { return -1; }
        /* Validity dates (lexicographic on canonical strings). */
        if (strcmp(certs[i].not_before, now) > 0) { return -1; }
        if (strcmp(now, certs[i].not_after) > 0) { return -1; }
    }
    if (verify_host(&certs[0], host) != 0) { return -1; }
    for (int i = 0; i + 1 < path_len; i++) {
        /* Issuer name must equal the next cert's subject. */
        if (certs[i].issuer_len != certs[i + 1].subject_len) return -1;
        if (memcmp(certs[i].issuer, certs[i + 1].subject, certs[i].issuer_len) != 0) return -1;
        /* Non-leaf certs used as issuers must be CAs. */
        if (certs[i + 1].ca_flag != 1) return -1;
        if (verify_signature(&certs[i], &certs[i + 1]) != 0) return -1;
    }
    /* Terminal certificate of the VALIDATED PATH (not
       necessarily the last presented cert — see above).
       Anchored mode: the path terminal IS a pinned anchor
       by construction; the checks below restate that gate
       explicitly. TOFU mode trusts the presented path on
       first use: every link's signature must verify
       (checked above), the leaf must match the host, dates
       must hold — and the terminal must either be self-signed
       with a verifying self-signature (the single-cert case,
       rule unchanged) or a real CA (CA:true). Real servers
       that withhold their root end at an intermediate CA;
       servers that SEND their root (Vercel sends GTS Root
       R1) end at the anchor / truncation point instead —
       the same path, the same trust. */
    const struct cert_info *root = &certs[path_len - 1];
    if (tls_verify_mode == 1) {
        if (root->ca_flag != 1) { return -1; }
        if (!tls_anchor_match(root)) { return -1; }
        return 0;
    }
    if (tls_verify_mode == 2) {
        if (root->ca_flag != 1) { return -1; }
        if (!tls_store_match(root)) { return -1; }
        return 0;
    }
    if (root->issuer_len == root->subject_len &&
        memcmp(root->issuer, root->subject, root->issuer_len) == 0) {
        /* Self-signed terminal: old rule, unchanged. */
        if (root->ca_flag == 0) { return -1; }
        if (verify_signature(root, root) != 0) { return -1; }
        return 0;
    }
    /* Intermediate terminal (the real-world case): it must be a
       CA. Its own issuer's signature cannot be checked — the
       root is not presented — which is exactly what TOFU
       means: this chain is trusted on first use. */
    if (root->ca_flag != 1) { return -1; }
    return 0;
}

/* ---------- TOFU leaf fingerprints (Phase 13) ----------
   TOFU without memory is just "accept anything once": a later
   attacker chain for the same host would pass as easily as the
   first. So the first accepted leaf per host is pinned in the
   root-owned system file tofuprints.txt (one line per host:
   "<host> <sha256-of-leaf-DER-hex>"). A later fetch whose
   leaf hash differs is a hard refusal — re-trust is explicit
   (`tofprints clear <host>` as root), never silent. The file
   is a system file (fs/nxtsfs.c): a non-root user who could
   plant a print could pin an attacker's leaf. Without a
   mounted disk there is nothing to pin to, so diskless TOFU
   proceeds without recording (and says so) rather than
   failing every fetch; a mounted disk whose print file
   cannot be read or written fails closed. */
#define TOFU_PRINTS_FILE "tofuprints.txt"
#define TOFU_PRINTS_MAX 16384
static int tofu_line_host_match(const char *line, u32 line_len,
                                const char *host, u32 *hex_off) {
    /* line = "<host> <64 hex>"; host compare is
       case-insensitive, the stored form is as-first-seen. */
    u32 i = 0;
    while (i < line_len && line[i] != ' ') i++;
    if (i == 0 || i + 1 + 64 != line_len) return 0;
    char hbuf[256];
    if (i >= sizeof(hbuf)) return 0;
    for (u32 j = 0; j < i; j++) hbuf[j] = line[j];
    hbuf[i] = 0;
    if (!ascii_equal_nocase(hbuf, host)) return 0;
    *hex_off = i + 1;
    return 1;
}
static int tofu_hex_ok(const u8 *p) {
    for (int i = 0; i < 64; i++) {
        char c = (char)p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}
/* Returns 0 if this leaf may be trusted for host, -1 if it
   must be refused (mismatch, store full, or write failure). */
static int tofu_print_check_and_store(const char *host,
                                      const u8 *leaf_der, u32 leaf_len) {
    if (!fs_mounted()) {
        console_write("tls: no disk, TOFU print not recorded\n");
        return 0;
    }
    u8 hash[32];
    char hex[65];
    sha256_compute(leaf_der, leaf_len, hash);
    sha256_hex(hash, hex);
    static u8 pbuf[TOFU_PRINTS_MAX];
    u32 psize = 0;
    int have_file = fs_exists(TOFU_PRINTS_FILE);
    if (have_file) {
        if (fs_read(TOFU_PRINTS_FILE, pbuf, sizeof(pbuf) - 1, &psize) != 0)
            return -1; /* exists but unreadable: fail closed */
    }
    pbuf[psize] = 0;
    u32 pos = 0;
    while (pos < psize) {
        u32 ls = pos;
        while (pos < psize && pbuf[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < psize) pos++;
        if (ll == 0) continue;
        u32 hx = 0;
        if (!tofu_line_host_match((const char *)pbuf + ls, ll, host, &hx)) {
            /* A line whose host field matches but whose shape
               is wrong is not "no entry": it is corruption,
               and re-pinning over it would be silent re-trust. */
            u32 i = 0;
            while (i < ll && pbuf[ls + i] != ' ') i++;
            char hbuf[256];
            if (i > 0 && i < sizeof(hbuf)) {
                for (u32 j = 0; j < i; j++) hbuf[j] = (char)pbuf[ls + j];
                hbuf[i] = 0;
                if (ascii_equal_nocase(hbuf, host)) return -1;
            }
            continue;
        }
        if (!tofu_hex_ok(pbuf + ls + hx)) return -1;
        if (memcmp(pbuf + ls + hx, hex, 64) == 0) return 0; /* match */
        console_write("tls: TOFU fingerprint mismatch for ");
        console_write(host);
        console_write(", refusing\n");
        return -1;
    }
    /* New host: append. Byte guard, not just a count cap:
       host names can be long, so capacity is what matters. */
    u32 hlen = 0;
    while (host[hlen]) hlen++;
    u32 need = hlen + 1 + 64 + 1;
    if (psize + need > sizeof(pbuf) - 1) {
        console_write("tls: TOFU print store full, refusing new host\n");
        return -1;
    }
    memcpy(pbuf + psize, host, hlen);
    pbuf[psize + hlen] = ' ';
    memcpy(pbuf + psize + hlen + 1, hex, 64);
    pbuf[psize + hlen + 1 + 64] = '\n';
    psize += need;
    if (fs_write(TOFU_PRINTS_FILE, pbuf, psize, 0, 0600) != 0) {
        console_write("tls: TOFU print store write failed, refusing\n");
        return -1;
    }
    return 0;
}
/* Shell helpers: list prints verbatim (0 ok, -1 no file/error),
   clear one host (0 removed, 1 not present, -1 error). */
int tls_tofu_print_list(void) {
    static u8 lbuf[TOFU_PRINTS_MAX];
    u32 lsize = 0;
    if (fs_read(TOFU_PRINTS_FILE, lbuf, sizeof(lbuf) - 1, &lsize) != 0) return -1;
    lbuf[lsize] = 0;
    console_write("TOFU prints:\n");
    console_write((const char *)lbuf);
    return 0;
}
int tls_tofu_print_clear(const char *host) {
    static u8 cbuf[TOFU_PRINTS_MAX];
    u32 csize = 0;
    if (fs_read(TOFU_PRINTS_FILE, cbuf, sizeof(cbuf) - 1, &csize) != 0) return -1;
    static u8 obuf[TOFU_PRINTS_MAX];
    u32 osize = 0;
    int removed = 0;
    u32 pos = 0;
    while (pos < csize) {
        u32 ls = pos;
        while (pos < csize && cbuf[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < csize) pos++;
        /* Remove ANY line for this host, well-formed or not:
           clear must also fix a corrupt line, or the host
           could never be re-trusted after corruption. */
        int is_host = 0;
        u32 sp = 0;
        while (sp < ll && cbuf[ls + sp] != ' ') sp++;
        if (sp > 0 && sp < 256) {
            char hbuf[256];
            for (u32 j = 0; j < sp; j++) hbuf[j] = (char)cbuf[ls + j];
            hbuf[sp] = 0;
            if (ascii_equal_nocase(hbuf, host)) is_host = 1;
        }
        if (ll > 0 && is_host) {
            removed = 1;
            continue;
        }
        if (osize + ll + 1 > sizeof(obuf) - 1) return -1;
        memcpy(obuf + osize, cbuf + ls, ll);
        obuf[osize + ll] = '\n';
        osize += ll + 1;
    }
    if (!removed) return 1;
    if (osize == 0) {
        if (fs_delete(TOFU_PRINTS_FILE) != 0) return -1;
    } else {
        if (fs_write(TOFU_PRINTS_FILE, obuf, osize, 0, 0600) != 0) return -1;
    }
    return 0;
}

/* ---------- CA store management (Phase 13) ----------
   castore.txt format: one 512-hex-char RSA-2048 modulus per
   line (exponent 65537), blank lines and '#' comments
   skipped — the same line shape as tlsanchors.txt, so one
   parser serves both. The update path: `castore update
   <host>` fetches /castore.txt and /castore.txt.sig over
   ANCHORED https (transport pinned to the anchor set), then
   verifies the bundle's 256-byte vendor signature over the
   bundle bytes with the package trust anchors (compiled-in
   vendor key, then pubkeys.txt) before installing.
   Transport alone is NOT trusted: a bundle served by a
   compromised-but-pinned host still needs the vendor
   signature, exactly like a package. Bundles over 65535
   bytes are refused (about 127 roots in hex format); a
   larger production store wants a binary format first. */
static char castore_bundle_buf[65536];
static u8 castore_sig_buf[512];
/* Validate bundle bytes: every non-blank, non-comment line
   must be exactly 512 hex chars, at least one root. Returns
   the root count, or -1. */
static int castore_bundle_validate(const u8 *buf, u32 len) {
    int count = 0;
    u32 pos = 0;
    while (pos < len) {
        u32 ls = pos;
        while (pos < len && buf[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < len) pos++;
        if (ll == 0) continue;
        if (buf[ls] == '#') continue;
        if (!tls_key_line_valid((const char *)buf + ls, ll)) return -1;
        count++;
    }
    return count > 0 ? count : -1;
}
/* Append one key line to the store (0 ok, 1 already present,
   -1 error). The caller (shell) enforces root-only; the file
   itself is a system file, so a non-root create is refused by
   fs anyway. The line is either a 512-hex RSA modulus or an
   "EC256:" P-256 point line; dedupe is case-insensitive and
   only against well-formed lines of the same length. */
int tls_castore_add(const char *line) {
    if (!fs_mounted()) return -1;
    u32 ll = strlen(line);
    if (!tls_key_line_valid(line, ll)) return -1;
    u32 old_size = 0;
    if (fs_exists("castore.txt")) {
        if (fs_read("castore.txt", (u8 *)castore_bundle_buf,
                    sizeof(castore_bundle_buf) - 1, &old_size) != 0)
            return -1;
        /* Dedupe: a key already in the store is not
           appended again (re-running add after a retry must
           not grow the store, and duplicates would waste
           the bundle cap). */
        u32 pos = 0;
        while (pos < old_size) {
            u32 ls = pos;
            while (pos < old_size && castore_bundle_buf[pos] != '\n') pos++;
            u32 el = pos - ls;
            if (pos < old_size) pos++;
            if (el != ll) continue;
            if (!tls_key_line_valid((const char *)castore_bundle_buf + ls, el)) continue;
            int same = 1;
            for (u32 i = 0; i < ll; i++) {
                char a = (char)castore_bundle_buf[ls + i], b = line[i];
                if (a >= 'A' && a <= 'F') a += 32;
                if (b >= 'A' && b <= 'F') b += 32;
                if (a != b) { same = 0; break; }
            }
            if (same) return 1;
        }
    }
    if (old_size + ll + 1 > sizeof(castore_bundle_buf) - 1) return -1;
    memcpy(castore_bundle_buf + old_size, line, ll);
    castore_bundle_buf[old_size + ll] = '\n';
    if (fs_write("castore.txt", (const u8 *)castore_bundle_buf,
                 old_size + ll + 1, 0, 0644) != 0) return -1;
    return 0;
}
/* Signed-bundle update. Returns 0 with *count_out set, -1
   fetch failure, -2 signature failure, -3 malformed bundle,
   -4 install failure (including no disk). */
int tls_castore_update(const char *host, u16 port, u32 *count_out) {
    if (!fs_mounted()) return -4;
    int bl = net_https_get_anchored(host, port, "/castore.txt",
                                    castore_bundle_buf,
                                    sizeof(castore_bundle_buf) - 1);
    if (bl < 0) return -1;
    if (net_fetch_truncated()) return -3; /* bundle larger than
        the buffer: it cannot verify as a whole, so it is
        malformed from the installer's view, never partial. */
    int sl = net_https_get_anchored(host, port, "/castore.txt.sig",
                                    (char *)castore_sig_buf,
                                    sizeof(castore_sig_buf) - 1);
    if (sl != 256) return -2;
    if (pkg_verify_vendor_sig((const u8 *)castore_bundle_buf, (u32)bl,
                              castore_sig_buf) != 0) return -2;
    int n = castore_bundle_validate((const u8 *)castore_bundle_buf, (u32)bl);
    if (n < 0) return -3;
    if (fs_write("castore.txt", (const u8 *)castore_bundle_buf,
                 (u32)bl, 0, 0644) != 0) return -4;
    *count_out = (u32)n;
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
static u16 tls_cipher_suite = 0;
static u8 tls_peer_x[32], tls_peer_y[32]; /* ECDHE server point */
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

/* ---------- TLS 1.3 helpers (web/SSL Phase 2) ---------- */
static u8 tls13_transcript[16384];
static u32 tls13_transcript_len = 0;
static u8 tls13_hs_buf[16384];
static u32 tls13_hs_len = 0;
static u8 tls13_plain[TLS_REC_MAX + 64];
static u8 tls13_c_hs_key[16], tls13_c_hs_iv[12];
static u8 tls13_s_hs_key[16], tls13_s_hs_iv[12];
static u8 tls13_c_ap_key[16], tls13_c_ap_iv[12];
static u8 tls13_s_ap_key[16], tls13_s_ap_iv[12];
static u32 tls13_send_hs_seq = 0, tls13_recv_hs_seq = 0;
static u32 tls13_send_ap_seq = 0, tls13_recv_ap_seq = 0;
static int tls13_server_epoch_ap = 0; /* 0 = hs keys, 1 = ap keys */
static int tls13_client_epoch_ap = 0;
static int tls13_got_encrypted = 0; /* server CCS only before this */
static int tls_negotiated_version = 0; /* 0 none, 1 = TLS 1.2, 2 = TLS 1.3 */
static u8 tls_ecdh_priv[32];
static u8 tls_ecdh_pub_x[32], tls_ecdh_pub_y[32];
static u8 tls_session_id[32];
static u8 tls_sh_ks_x[32], tls_sh_ks_y[32];
static int tls_sh_ks_present = 0;
static int tls_leaf_key_type = 0;
static u8 tls_leaf_ec_x[32], tls_leaf_ec_y[32];
/* SHA-256 of the empty string (FIPS 180-4 vector, also in
   kernel/sha256.h's comment): HKDF's "derived" secret and
   the master secret both hash the empty transcript. */
static const u8 TLS13_EMPTY_HASH[32] = {
    0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
    0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
    0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
    0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55
};
/* HelloRetryRequest magic random (RFC 8446 4.1.3): a
   ServerHello carrying it IS a retry request, which this
   client does not support. */
static const u8 TLS13_HRR_MAGIC[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};
static int tls13_transcript_append(const u8 *data, u32 len) {
    if (tls13_transcript_len + len > sizeof(tls13_transcript)) return -1;
    memcpy(tls13_transcript + tls13_transcript_len, data, len);
    tls13_transcript_len += len;
    return 0;
}
static void tls13_transcript_hash(u8 out[32]) {
    sha256_compute(tls13_transcript, tls13_transcript_len, out);
}
/* HKDF (RFC 5869, SHA-256) built on hmac_sha256. */
static void hkdf_extract(const u8 *salt, const u8 *ikm, u32 ikm_len, u8 out[32]) {
    hmac_sha256(salt, 32, ikm, ikm_len, out);
}
static void hkdf_expand(const u8 *prk, const u8 *info, u32 info_len,
                        u8 *out, u32 out_len) {
    u8 t[32];
    u32 done = 0;
    u8 ctr = 1;
    u8 buf[160];
    while (done < out_len) {
        u32 pos = 0;
        if (done > 0) { memcpy(buf, t, 32); pos = 32; }
        if (pos + info_len + 1 > sizeof(buf)) return;
        memcpy(buf + pos, info, info_len); pos += info_len;
        buf[pos++] = ctr++;
        hmac_sha256(prk, 32, buf, pos, t);
        u32 take = out_len - done < 32 ? out_len - done : 32;
        memcpy(out + done, t, take);
        done += take;
    }
}
/* HKDF-Expand-Label (RFC 8446 7.3): HkdfLabel = len(2) ||
   "tls13 " || label || context_len(1) || context. */
static void hkdf_expand_label(const u8 *secret, const char *label,
                              const u8 *ctx, u32 ctx_len,
                              u8 *out, u32 out_len) {
    u8 info[96];
    u32 llen = 0;
    while (label[llen]) llen++;
    if (2 + 6 + llen + 1 + ctx_len > sizeof(info)) return;
    u32 pos = 0;
    tput16(info, (u16)out_len); pos += 2;
    memcpy(info + pos, "tls13 ", 6); pos += 6;
    memcpy(info + pos, label, llen); pos += llen;
    info[pos++] = (u8)ctx_len;
    if (ctx_len) memcpy(info + pos, ctx, ctx_len);
    pos += ctx_len;
    hkdf_expand(secret, info, pos, out, out_len);
}
/* Derive-Secret(secret, label, transcript_hash). */
static void tls13_derive_secret(const u8 *secret, const char *label,
                                const u8 *thash, u8 out[32]) {
    hkdf_expand_label(secret, label, thash, 32, out, 32);
}
static void tls13_key_iv(const u8 *traffic, u8 key[16], u8 iv[12]) {
    hkdf_expand_label(traffic, "key", 0, 0, key, 16);
    hkdf_expand_label(traffic, "iv", 0, 0, iv, 12);
}
/* Nonce = IV XOR (4 zero bytes || 64-bit BE sequence). */
static void tls13_nonce(const u8 iv[12], u32 seq, u8 nonce[12]) {
    memcpy(nonce, iv, 4);
    for (int i = 0; i < 4; i++) nonce[4 + i] = iv[4 + i];
    nonce[8] = (u8)(iv[8] ^ (seq >> 24));
    nonce[9] = (u8)(iv[9] ^ (seq >> 16));
    nonce[10] = (u8)(iv[10] ^ (seq >> 8));
    nonce[11] = (u8)(iv[11] ^ seq);
}
/* Read one TLS 1.3 record: skips a pre-encryption CCS, then
   decrypts with the current server epoch keys. On success
   *inner_type is the inner content type and the plaintext is
   in tls13_plain (length *plain_len). The outer record type
   is always application_data (0x17) for encrypted records;
   the inner type is the real one (handshake 0x16, alert
   0x15, app data 0x17). Padding after the inner type must
   be all zeros. */
static int tls13_recv_record(u8 *inner_type, u32 *plain_len) {
    u8 hdr[5];
    for (;;) {
        if (tcp_read_exact(hdr, 5, 1000) != 0) return -1;
        u8 type = hdr[0];
        if (hdr[1] != 0x03 || hdr[2] != 0x03) return -1;
        u32 len = tget16(hdr + 3);
        if (len == 0 || len > TLS_REC_MAX) return -1;
        if (type == 20 && !tls13_got_encrypted) {
            /* Middlebox-compat CCS: one byte 0x01, skipped. */
            if (len != 1) return -1;
            u8 ccs;
            if (tcp_read_exact(&ccs, 1, 1000) != 0) return -1;
            if (ccs != 0x01) return -1;
            continue;
        }
        if (type != 23) return -1;
        if (tcp_read_exact(tls13_plain, len, 1000) != 0) return -1;
        if (len < 16) return -1;
        const u8 *key; const u8 *iv; u32 *seqp;
        if (tls13_server_epoch_ap) {
            key = tls13_s_ap_key; iv = tls13_s_ap_iv; seqp = &tls13_recv_ap_seq;
        } else {
            key = tls13_s_hs_key; iv = tls13_s_hs_iv; seqp = &tls13_recv_hs_seq;
        }
        u8 nonce[12];
        tls13_nonce(iv, *seqp, nonce);
        /* Decrypt in place: gcm_decrypt finishes its GHASH
           over the ciphertext before writing any plaintext,
           and each block is read before it is overwritten,
           so the overlap is safe. */
        if (gcm_decrypt(key, nonce, hdr, 5,
                        tls13_plain, len - 16,
                        tls13_plain + len - 16, tls13_plain) != 0) return -1;
        (*seqp)++;
        tls13_got_encrypted = 1;
        u32 n = len - 16;
        while (n > 0 && tls13_plain[n - 1] == 0) n--;
        if (n == 0) return -1;
        u8 it = tls13_plain[n - 1];
        if (it != 0x15 && it != 0x16 && it != 0x17) return -1;
        *inner_type = it;
        *plain_len = n - 1;
        return 0;
    }
}
/* Send one TLS 1.3 record (inner_type + data, no padding). */
static int tls13_send_record(u8 inner_type, const u8 *data, u32 len) {
    static u8 pt[TLS_REC_MAX + 64];
    static u8 ct[TLS_REC_MAX + 64];
    if (len + 1 > sizeof(pt)) return -1;
    memcpy(pt, data, len);
    pt[len] = inner_type;
    u32 pt_len = len + 1;
    const u8 *key; const u8 *iv; u32 *seqp;
    if (tls13_client_epoch_ap) {
        key = tls13_c_ap_key; iv = tls13_c_ap_iv; seqp = &tls13_send_ap_seq;
    } else {
        key = tls13_c_hs_key; iv = tls13_c_hs_iv; seqp = &tls13_send_hs_seq;
    }
    u8 nonce[12];
    tls13_nonce(iv, *seqp, nonce);
    u8 hdr[5];
    hdr[0] = 23; hdr[1] = 0x03; hdr[2] = 0x03;
    tput16(hdr + 3, (u16)(pt_len + 16));
    u8 tag[16];
    gcm_encrypt(key, nonce, hdr, 5, pt, pt_len, ct, tag);
    if (net_tcp_send(hdr, 5) != 0) return -1;
    if (net_tcp_send(ct, pt_len) != 0) return -1;
    if (net_tcp_send(tag, 16) != 0) return -1;
    (*seqp)++;
    return 0;
}
/* Send one handshake message (appends to the transcript). */
static int tls13_send_hs(u8 type, const u8 *body, u32 body_len) {
    static u8 msg[8192 + 4];
    if (body_len + 4 > sizeof(msg)) return -1;
    msg[0] = type;
    tput24(msg + 1, body_len);
    memcpy(msg + 4, body, body_len);
    if (tls13_transcript_append(msg, body_len + 4) != 0) return -1;
    return tls13_send_record(0x16, msg, body_len + 4);
}
/* Read the next complete handshake message into msg_out
   (returns its type, or -1). Same stream-reassembly shape
   as tls_next_hs, but over decrypted TLS 1.3 records: only
   inner handshake records are accepted here. NOTE: the
   stream buffer is deliberately separate from msg_out —
   an earlier draft reused tls13_hs_buf for both, which
   corrupted the stream whenever two messages shared one
   record (the output length overwrote the stream length
   and the remainder bytes were misread as the next
   message). */
static u8 tls13_stream_buf[16384];
static u32 tls13_stream_len = 0;
static int tls13_next_hs(u8 *msg_out, u32 max, u32 *msg_len_out) {
    while (1) {
        if (tls13_stream_len >= 4) {
            u32 body_len = tget24(tls13_stream_buf + 1);
            if (body_len + 4 <= max && tls13_stream_len >= body_len + 4) {
                u8 type = tls13_stream_buf[0];
                memcpy(msg_out, tls13_stream_buf, body_len + 4);
                memmove(tls13_stream_buf, tls13_stream_buf + body_len + 4,
                        tls13_stream_len - (body_len + 4));
                tls13_stream_len -= body_len + 4;
                *msg_len_out = body_len + 4;
                return type;
            }
            if (body_len + 4 > max) return -1;
        }
        u8 itype; u32 plen;
        if (tls13_recv_record(&itype, &plen) != 0) return -1;
        if (itype != 0x16) return -1;
        if (tls13_stream_len + plen > sizeof(tls13_stream_buf)) return -1;
        memcpy(tls13_stream_buf + tls13_stream_len, tls13_plain, plen);
        tls13_stream_len += plen;
    }
}
/* Application-phase handshake plaintext: parse and skip
   NewSessionTicket messages (servers send them routinely
   after Finished); anything else fails closed. Messages
   split across records are buffered until complete. */
static u8 tls13_app_hs_buf[2048];
static u32 tls13_app_hs_len = 0;
static int tls13_app_hs_skip(const u8 *data, u32 len) {
    if (tls13_app_hs_len + len > sizeof(tls13_app_hs_buf)) return -1;
    memcpy(tls13_app_hs_buf + tls13_app_hs_len, data, len);
    tls13_app_hs_len += len;
    while (tls13_app_hs_len >= 4) {
        u32 blen = tget24(tls13_app_hs_buf + 1);
        if (blen + 4 > tls13_app_hs_len) break; /* split: wait */
        if (tls13_app_hs_buf[0] != 4) return -1; /* only tickets */
        memmove(tls13_app_hs_buf, tls13_app_hs_buf + blen + 4,
                tls13_app_hs_len - (blen + 4));
        tls13_app_hs_len -= blen + 4;
    }
    return 0;
}
static int tls13_recv_app(u8 *buf, u32 max) {
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
    while (1) {
        u8 itype; u32 plen;
        if (tls13_recv_record(&itype, &plen) != 0) return -1;
        if (itype == 0x17) {
            if (plen > max) {
                memcpy(buf, tls13_plain, max);
                memcpy(tls_app_spill, tls13_plain + max, plen - max);
                tls_app_spill_len = plen - max;
                tls_app_spill_pos = 0;
                return (int)max;
            }
            memcpy(buf, tls13_plain, plen);
            return (int)plen;
        }
        if (itype == 0x16) {
            if (tls13_app_hs_skip(tls13_plain, plen) != 0) return -1;
            continue;
        }
        return -1; /* alert or unknown inner type */
    }
}

/* ---------- Handshake ---------- */
/* Build and send the combined TLS 1.3 + 1.2 ClientHello.
   Suites offered: 0x1301, 0xC02F, 0xC00A, 0x009C.
   Extensions: SNI, supported_versions [1.3, 1.2],
   supported_groups [secp256r1], signature_algorithms
   [RSA+SHA256, ECDSA+SHA256], key_share [secp256r1],
   ec_point_formats [uncompressed], ALPN [http/1.1].
   The ECDHE keypair is generated here (CSPRNG) and kept in
   tls_ecdh_* for the negotiated path (the 1.3 key_share, or
   the 1.2 ClientKeyExchange). No ChangeCipherSpec is sent
   after ClientHello: CCS is optional in TLS 1.3 compat
   mode, and an early CCS would break strict TLS 1.2
   servers. The full message is appended to BOTH transcripts
   (the legacy one for a 1.2 negotiation, the 1.3 one for
   1.3). Layout note (from the 1.2 hello this replaces):
   each extension length counts only the bytes AFTER its own
   field; an earlier draft omitted ext_length, which made
   openssl s_server reject the hello with "bad extension". */
static int tls_send_combined_hello(const char *host) {
    int ok = 0;
    for (int attempt = 0; attempt < 4 && !ok; attempt++) {
        csprng_generate(tls_ecdh_priv, 32);
        if (p256_pub_from_priv(tls_ecdh_priv, tls_ecdh_pub_x, tls_ecdh_pub_y) == 0) ok = 1;
    }
    if (!ok) return -1;
    csprng_generate(tls_session_id, 32);
    u8 hello[768];
    u32 pos = 0;
    hello[pos++] = 0x03; hello[pos++] = 0x03; /* legacy_version */
    csprng_generate(tls_client_random, 32);
    memcpy(hello + pos, tls_client_random, 32); pos += 32;
    hello[pos++] = 32; /* session id length (middlebox compat) */
    memcpy(hello + pos, tls_session_id, 32); pos += 32;
    tput16(hello + pos, 8); pos += 2; /* cipher suites length */
    tput16(hello + pos, 0x1301); pos += 2; /* TLS 1.3 AES-128-GCM */
    tput16(hello + pos, 0xC02F); pos += 2; /* ECDHE-RSA AES-128-GCM */
    tput16(hello + pos, 0xC00A); pos += 2; /* ECDHE-ECDSA AES-128-GCM */
    tput16(hello + pos, 0x009C); pos += 2; /* RSA AES-128-GCM */
    hello[pos++] = 1; /* compression methods length */
    hello[pos++] = 0; /* null compression */
    u32 ext_len_field = pos;
    pos += 2; /* extensions_length */
    /* SNI. */
    u32 host_len = strlen(host);
    if (host_len > 255) return -1;
    tput16(hello + pos, 0); pos += 2; /* server_name type */
    u32 sni_len_field = pos;
    pos += 2; /* extension data length */
    u32 sni_list_field = pos;
    pos += 2; /* server_name_list length */
    hello[pos++] = 0; /* host_name type */
    tput16(hello + pos, (u16)host_len); pos += 2;
    memcpy(hello + pos, host, host_len); pos += host_len;
    tput16(hello + sni_list_field, (u16)(pos - sni_list_field - 2));
    tput16(hello + sni_len_field, (u16)(pos - sni_len_field - 2));
    /* supported_versions [1.3, 1.2]. */
    tput16(hello + pos, 43); pos += 2;
    tput16(hello + pos, 5); pos += 2;
    hello[pos++] = 4; /* list length */
    tput16(hello + pos, 0x0304); pos += 2;
    tput16(hello + pos, 0x0303); pos += 2;
    /* supported_groups [secp256r1]. */
    tput16(hello + pos, 10); pos += 2;
    tput16(hello + pos, 4); pos += 2;
    tput16(hello + pos, 2); pos += 2;
    tput16(hello + pos, 23); pos += 2;
    /* signature_algorithms [RSA+SHA256, ECDSA+SHA256]. */
    tput16(hello + pos, 13); pos += 2;
    tput16(hello + pos, 6); pos += 2;
    tput16(hello + pos, 4); pos += 2;
    hello[pos++] = 0x04; hello[pos++] = 0x01;
    hello[pos++] = 0x04; hello[pos++] = 0x03;
    /* key_share [secp256r1 + pubkey]. */
    tput16(hello + pos, 51); pos += 2;
    tput16(hello + pos, 71); pos += 2; /* 2 + 2 + 2 + 65 */
    tput16(hello + pos, 69); pos += 2; /* client_shares length */
    tput16(hello + pos, 23); pos += 2;
    tput16(hello + pos, 65); pos += 2;
    hello[pos++] = 0x04; /* uncompressed point */
    memcpy(hello + pos, tls_ecdh_pub_x, 32); pos += 32;
    memcpy(hello + pos, tls_ecdh_pub_y, 32); pos += 32;
    /* ec_point_formats [uncompressed]. */
    tput16(hello + pos, 11); pos += 2;
    tput16(hello + pos, 2); pos += 2;
    hello[pos++] = 1; hello[pos++] = 0;
    /* ALPN [http/1.1]. The server's selection is not parsed;
       the client speaks HTTP/1.1 regardless, so a server
       selecting anything else fails at the HTTP layer. */
    tput16(hello + pos, 16); pos += 2;
    tput16(hello + pos, 11); pos += 2;
    tput16(hello + pos, 9); pos += 2;
    hello[pos++] = 8;
    memcpy(hello + pos, "http/1.1", 8); pos += 8;
    tput16(hello + ext_len_field, (u16)(pos - ext_len_field - 2));
    if (pos + 4 > sizeof(hello)) return -1;
    u8 msg[772];
    msg[0] = 1; /* ClientHello */
    tput24(msg + 1, pos);
    memcpy(msg + 4, hello, pos);
    if (transcript_append(msg, pos + 4) != 0) return -1;
    if (tls13_transcript_append(msg, pos + 4) != 0) return -1;
    return tls_send_record(22, msg, pos + 4);
}
/* Read and parse ServerHello. Returns 0 with the negotiated
   version in *is13 (1 = TLS 1.3, 0 = TLS 1.2) and, for 1.3,
   the server key_share in tls_sh_ks_*. The full message is
   appended to both transcripts. Refuses: wrong message type,
   legacy_version != 0x0303, non-null compression, an
   unknown cipher suite, malformed extensions, a downgrade
   sentinel in the random when negotiating below 1.3, a
   HelloRetryRequest (unsupported), and (1.3) a session-id
   echo mismatch. */
static int tls_read_server_hello(int *is13) {
    u8 *msg = tls_msg_buf;
    u32 msg_len = 0;
    int mtype = tls_next_hs(msg, 8192, &msg_len);
    if (mtype != 2) return -1;
    const u8 *sh = msg + 4;
    u32 sh_len = msg_len - 4;
    if (sh_len < 34) return -1;
    if (sh[0] != 0x03 || sh[1] != 0x03) return -1;
    memcpy(tls_server_random, sh + 2, 32);
    u32 spos = 34;
    if (spos >= sh_len) return -1;
    u32 sid_len = sh[spos++];
    if (spos + sid_len + 2 + 1 > sh_len) return -1;
    const u8 *sid = sh + spos;
    spos += sid_len;
    tls_cipher_suite = tget16(sh + spos);
    spos += 2;
    if (sh[spos] != 0) return -1; /* compression must be null */
    spos++;
    /* Extensions. */
    u16 sv_version = 0;
    tls_sh_ks_present = 0;
    if (spos + 2 <= sh_len) {
        u32 ext_total = tget16(sh + spos);
        spos += 2;
        if (spos + ext_total > sh_len) return -1;
        u32 epos = spos, eend = spos + ext_total;
        while (epos + 4 <= eend) {
            u16 etype = tget16(sh + epos);
            u16 elen = tget16(sh + epos + 2);
            if (epos + 4 + elen > eend) return -1;
            const u8 *ed = sh + epos + 4;
            if (etype == 43 && elen == 2) {
                sv_version = tget16(ed);
            } else if (etype == 51 && elen == 69) {
                /* key_share: group + key length + point. */
                if (tget16(ed) == 23 && tget16(ed + 2) == 65 &&
                    ed[4] == 0x04) {
                    memcpy(tls_sh_ks_x, ed + 5, 32);
                    memcpy(tls_sh_ks_y, ed + 37, 32);
                    tls_sh_ks_present = 1;
                }
            }
            epos += 4 + elen;
        }
        if (epos != eend) return -1;
    } else if (spos != sh_len) {
        return -1;
    }
    if (transcript_append(msg, msg_len) != 0) return -1;
    if (tls13_transcript_append(msg, msg_len) != 0) return -1;
    if (sv_version == 0x0304) {
        if (tls_cipher_suite != 0x1301) return -1;
        if (!tls_sh_ks_present) return -1; /* HRR or broken */
        if (memcmp(tls_server_random, TLS13_HRR_MAGIC, 32) == 0) return -1;
        if (sid_len != 32 || memcmp(sid, tls_session_id, 32) != 0) return -1;
        *is13 = 1;
        return 0;
    }
    if (sv_version != 0) return -1; /* unknown version */
    if (tls_cipher_suite != 0x009C && tls_cipher_suite != 0xC02F &&
        tls_cipher_suite != 0xC00A) return -1;
    /* Downgrade sentinel: a server that negotiated below 1.3
       while we offered 1.3 must not carry DOWNGRD. */
    if (memcmp(tls_server_random + 24, "DOWNGRD", 7) == 0 &&
        (tls_server_random[31] == 0x00 || tls_server_random[31] == 0x01))
        return -1;
    *is13 = 0;
    return 0;
}
/* TLS 1.2 handshake, continued after a parsed ServerHello.
   Returns 0 (handshake done), -1 (protocol/IO failure),
   -2 (certificate failure — never fall through to plaintext). */
static int tls12_handshake_rest(const char *host) {
    /* msg is a static buffer: an 8 KiB stack array would
       leave almost no room on the 16 KiB kernel stack. */
    u8 *msg = tls_msg_buf;
    u32 msg_len = 0;
    int mtype;
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
    const u8 *leaf_der = 0;
    u32 leaf_der_len = 0;
    u32 cpos = 3;
    while (cpos < 3 + total_certs_len) {
        if (cpos + 3 > cm_len) return -2;
        u32 clen = tget24(cm + cpos);
        if (cpos + 3 + clen > cm_len) return -2;
        if (cert_count >= 4) return -2; /* chain too long */
        if (parse_cert(cm + cpos + 3, clen, &certs[cert_count]) != 0) return -2;
        if (cert_count == 0) { leaf_der = cm + cpos + 3; leaf_der_len = clen; }
        cert_count++;
        cpos += 3 + clen;
    }
    if (cert_count == 0) return -2;
    if (verify_chain(certs, cert_count, host) != 0) { return -2; }
    if (tls_verify_mode == 0) {
        if (tofu_print_check_and_store(host, leaf_der, leaf_der_len) != 0) { return -2; }
    }
    tls_leaf_mod = certs[0].modulus;
    tls_leaf_exp = certs[0].exponent;
    tls_leaf_key_type = certs[0].key_type;
    if (certs[0].key_type == 1) {
        memcpy(tls_leaf_ec_x, certs[0].ec_x, 32);
        memcpy(tls_leaf_ec_y, certs[0].ec_y, 32);
    }
    if (transcript_append(msg, msg_len) != 0) return -1;
    /* ECDHE only: ServerKeyExchange, signed over
       client_random || server_random || params. Signature
       algorithm dispatch: 0x0401 = SHA256+RSA (RSA leaf
       only), 0x0403 = SHA256+ECDSA (EC leaf only). A bad
       curve, point, hash algorithm, or signature fails
       closed (-2, never a fallback to RSA key exchange). */
    if (tls_cipher_suite == 0xC02F || tls_cipher_suite == 0xC00A) {
        mtype = tls_next_hs(msg, 8192, &msg_len);
        if (mtype != 12) return -1;
        const u8 *sk = msg + 4;
        u32 sk_len = msg_len - 4;
        /* params = curve_type(1)=3, named_curve(2)=23,
           pubkey_len(1)=65, pubkey(65) = 69 bytes. */
        if (sk_len < 69 + 2 + 2) return -2;
        if (sk[0] != 3 || tget16(sk + 1) != 23) return -2;
        if (sk[3] != 65 || sk[4] != 0x04) return -2;
        u16 ske_alg = tget16(sk + 69);
        u32 sig_len = tget16(sk + 71);
        if (69 + 2 + 2 + sig_len != sk_len) return -2;
        const u8 *sig = sk + 73;
        memcpy(tls_peer_x, sk + 5, 32);
        memcpy(tls_peer_y, sk + 37, 32);
        if (p256_point_valid(tls_peer_x, tls_peer_y) != 0) return -2;
        /* Signed message: client_random + server_random + params. */
        u8 ske_msg[32 + 32 + 69];
        memcpy(ske_msg, tls_client_random, 32);
        memcpy(ske_msg + 32, tls_server_random, 32);
        memcpy(ske_msg + 64, sk, 69);
        if (ske_alg == 0x0401) {
            if (tls_leaf_key_type != 0) return -2;
            int bl2 = bn_bitlen(&tls_leaf_mod);
            u32 k2 = (u32)((bl2 + 7) / 8);
            u8 mod_be[256];
            if (k2 < 62 || k2 > 256) return -2;
            if (bn_to_be(&tls_leaf_mod, mod_be, k2) != 0) return -2;
            if (rsa_verify_sha256(mod_be, k2, tls_leaf_exp,
                                  sig, sig_len, ske_msg, sizeof(ske_msg)) != 0) return -2;
        } else if (ske_alg == 0x0403) {
            if (tls_leaf_key_type != 1) return -2;
            u8 r[32], s[32], h[32];
            if (der_sig_to_rs(sig, sig_len, r, s) != 0) return -2;
            sha256_compute(ske_msg, sizeof(ske_msg), h);
            if (p256_ecdsa_verify(tls_leaf_ec_x, tls_leaf_ec_y, h, r, s) != 0) return -2;
        } else {
            return -2;
        }
        if (transcript_append(msg, msg_len) != 0) return -1;
    }
    /* ServerHelloDone (may share a record with Certificate in
       theory; the stream parser already handles that). */
    mtype = tls_next_hs(msg, 8192, &msg_len);
    if (mtype != 14) { return -1; }
    if (transcript_append(msg, msg_len) != 0) return -1;
    /* ClientKeyExchange + premaster. ECDHE: the premaster is
       the ECDH shared x coordinate (32 bytes, no version
       prefix), computed with the keypair sent in the
       ClientHello key_share (one keypair per handshake);
       RSA: the classic 48-byte versioned premaster. */
    u8 premaster[48];
    u32 premaster_len = 48;
    if (tls_cipher_suite == 0xC02F || tls_cipher_suite == 0xC00A) {
        u8 shared[32];
        if (p256_ecdh(tls_ecdh_priv, tls_peer_x, tls_peer_y, shared) != 0) return -1;
        memset(tls_ecdh_priv, 0, 32);
        memcpy(premaster, shared, 32);
        premaster_len = 32;
        u8 ckx[66];
        ckx[0] = 65;
        ckx[1] = 0x04;
        memcpy(ckx + 2, tls_ecdh_pub_x, 32);
        memcpy(ckx + 34, tls_ecdh_pub_y, 32);
        if (tls_send_hs(16, ckx, 66) != 0) { return -1; }
    } else {
        if (tls_leaf_key_type != 0) return -2; /* RSA key exchange needs an RSA leaf */
        premaster[0] = 0x03; premaster[1] = 0x03;
        csprng_generate(premaster + 2, 46);
        int bl = bn_bitlen(&tls_leaf_mod);
        u32 k = (u32)((bl + 7) / 8);
        if (k < 48 + 11 || k > 256) return -1;
        u8 em[256];
        em[0] = 0x00; em[1] = 0x02;
        for (u32 i = 2; i < k - 48 - 1; i++) {
            u8 r;
            do { csprng_generate(&r, 1); } while (r == 0);
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
    }
    /* Master secret + key block. */
    u8 seed_ms[64];
    memcpy(seed_ms, tls_client_random, 32);
    memcpy(seed_ms + 32, tls_server_random, 32);
    tls_prf(premaster, premaster_len, "master secret", seed_ms, 64, tls_master, 48);
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
/* TLS 1.3 handshake, continued after a parsed ServerHello
   (cipher 0x1301, server key_share present). ECDH with the
   hello-time keypair, then the full RFC 8446 key schedule
   (SHA-256, suite TLS_AES_128_GCM_SHA256), EncryptedExtensions,
   Certificate, CertificateVerify, server Finished (verified
   over the transcript WITHOUT the Finished itself — the
   only message whose verify data is computed before it is
   appended), client Finished, epoch switch to application
   keys. Returns 0, -1, or -2 (certificate failure). */
static int tls13_handshake_rest(const char *host) {
    u8 shared[32];
    if (p256_ecdh(tls_ecdh_priv, tls_sh_ks_x, tls_sh_ks_y, shared) != 0) return -1;
    memset(tls_ecdh_priv, 0, 32);
    /* early_secret = Extract(0, 0); derived; handshake_secret. */
    u8 zeros[32];
    memset(zeros, 0, 32);
    u8 early[32], derived[32], hs_secret[32];
    hkdf_extract(zeros, zeros, 32, early);
    tls13_derive_secret(early, "derived", TLS13_EMPTY_HASH, derived);
    hkdf_extract(derived, shared, 32, hs_secret);
    /* Handshake traffic secrets over Hash(CH..SH). */
    u8 thash[32];
    tls13_transcript_hash(thash);
    u8 c_hs[32], s_hs[32];
    tls13_derive_secret(hs_secret, "c hs traffic", thash, c_hs);
    tls13_derive_secret(hs_secret, "s hs traffic", thash, s_hs);
    tls13_key_iv(s_hs, tls13_s_hs_key, tls13_s_hs_iv);
    tls13_key_iv(c_hs, tls13_c_hs_key, tls13_c_hs_iv);
    tls13_server_epoch_ap = 0;
    tls13_client_epoch_ap = 0;
    tls13_send_hs_seq = 0;
    tls13_recv_hs_seq = 0;
    /* Encrypted handshake messages. */
    int mtype = tls13_next_hs(tls13_hs_buf, 16384, &tls13_hs_len);
    if (mtype != 8) return -1; /* EncryptedExtensions */
    {
        const u8 *ee = tls13_hs_buf + 4;
        u32 ee_len = tls13_hs_len - 4;
        if (ee_len < 2) return -1;
        if (tget16(ee) != ee_len - 2) return -1;
    }
    if (tls13_transcript_append(tls13_hs_buf, tls13_hs_len) != 0) return -1;
    /* Certificate: context length must be 0; each cert is
       DER + extensions (skipped). The leaf DER is kept for
       the TOFU print. */
    mtype = tls13_next_hs(tls13_hs_buf, 16384, &tls13_hs_len);
    if (mtype != 11) return -1;
    {
        const u8 *cm = tls13_hs_buf + 4;
        u32 cm_len = tls13_hs_len - 4;
        if (cm_len < 4) return -2;
        if (cm[0] != 0) return -2; /* certificate_request_context must be empty */
        u32 clist_len = tget24(cm + 1);
        if (4 + clist_len > cm_len) return -2;
        u32 cpos = 4;
        struct cert_info certs[4];
        int cert_count = 0;
        const u8 *leaf_der = 0;
        u32 leaf_der_len = 0;
        while (cpos + 3 <= 4 + clist_len) {
            u32 clen = tget24(cm + cpos);
            if (cpos + 3 + clen > 4 + clist_len) return -2;
            /* Extensions follow each cert: 2-byte length. */
            u32 after = cpos + 3 + clen;
            if (after + 2 > 4 + clist_len) return -2;
            u32 ext_len = tget16(cm + after);
            if (after + 2 + ext_len > 4 + clist_len) return -2;
            if (cert_count >= 4) return -2;
            if (parse_cert(cm + cpos + 3, clen, &certs[cert_count]) != 0) return -2;
            if (cert_count == 0) { leaf_der = cm + cpos + 3; leaf_der_len = clen; }
            cert_count++;
            cpos = after + 2 + ext_len;
        }
        if (cpos != 4 + clist_len || cert_count == 0) return -2;
        if (verify_chain(certs, cert_count, host) != 0) return -2;
        if (tls_verify_mode == 0) {
            if (tofu_print_check_and_store(host, leaf_der, leaf_der_len) != 0) return -2;
        }
        tls_leaf_mod = certs[0].modulus;
        tls_leaf_exp = certs[0].exponent;
        tls_leaf_key_type = certs[0].key_type;
        if (certs[0].key_type == 1) {
            memcpy(tls_leaf_ec_x, certs[0].ec_x, 32);
            memcpy(tls_leaf_ec_y, certs[0].ec_y, 32);
        }
    }
    if (tls13_transcript_append(tls13_hs_buf, tls13_hs_len) != 0) return -1;
    /* CertificateVerify. The signed blob is 64 spaces +
       "TLS 1.3, server CertificateVerify" + 0x00 + transcript
       hash. Signature algorithm must match the leaf key
       type; anything else (incl. RSA-PSS) fails closed. */
    mtype = tls13_next_hs(tls13_hs_buf, 16384, &tls13_hs_len);
    if (mtype != 15) return -1;
    {
        const u8 *cv = tls13_hs_buf + 4;
        u32 cv_len = tls13_hs_len - 4;
        if (cv_len < 4) return -2;
        u16 alg = tget16(cv);
        u16 sig_len = tget16(cv + 2);
        if (4 + sig_len != cv_len) return -2;
        const u8 *sig = cv + 4;
        u8 th[32];
        tls13_transcript_hash(th);
        u8 blob[64 + 33 + 1 + 32];
        memset(blob, 0x20, 64);
        memcpy(blob + 64, "TLS 1.3, server CertificateVerify", 33);
        blob[64 + 33] = 0x00;
        memcpy(blob + 64 + 33 + 1, th, 32);
        if (alg == 0x0401) {
            if (tls_leaf_key_type != 0) return -2;
            int bl = bn_bitlen(&tls_leaf_mod);
            u32 k = (u32)((bl + 7) / 8);
            u8 mod_be[256];
            if (k < 62 || k > 256) return -2;
            if (bn_to_be(&tls_leaf_mod, mod_be, k) != 0) return -2;
            /* rsa_verify_sha256 hashes its input, so pass the
               130-byte blob directly. */
            if (rsa_verify_sha256(mod_be, k, tls_leaf_exp,
                                  sig, sig_len, blob, sizeof(blob)) != 0) return -2;
        } else if (alg == 0x0403) {
            if (tls_leaf_key_type != 1) return -2;
            u8 r[32], s[32], h[32];
            if (der_sig_to_rs(sig, sig_len, r, s) != 0) return -2;
            sha256_compute(blob, sizeof(blob), h);
            if (p256_ecdsa_verify(tls_leaf_ec_x, tls_leaf_ec_y, h, r, s) != 0) return -2;
        } else {
            return -2;
        }
    }
    if (tls13_transcript_append(tls13_hs_buf, tls13_hs_len) != 0) return -1;
    /* Server Finished: verify BEFORE appending it. */
    mtype = tls13_next_hs(tls13_hs_buf, 16384, &tls13_hs_len);
    if (mtype != 20) return -1;
    {
        if (tls13_hs_len != 4 + 32) return -1;
        u8 th[32];
        tls13_transcript_hash(th);
        u8 fin_key[32], expect[32];
        hkdf_expand_label(s_hs, "finished", 0, 0, fin_key, 32);
        hmac_sha256(fin_key, 32, th, 32, expect);
        if (memcmp(tls13_hs_buf + 4, expect, 32) != 0) return -1;
    }
    if (tls13_transcript_append(tls13_hs_buf, tls13_hs_len) != 0) return -1;
    /* Master secret + application traffic secrets. */
    u8 derived2[32], master[32];
    tls13_derive_secret(hs_secret, "derived", TLS13_EMPTY_HASH, derived2);
    hkdf_extract(derived2, zeros, 32, master);
    u8 th2[32];
    tls13_transcript_hash(th2);
    u8 c_ap[32], s_ap[32];
    tls13_derive_secret(master, "c ap traffic", th2, c_ap);
    tls13_derive_secret(master, "s ap traffic", th2, s_ap);
    tls13_key_iv(s_ap, tls13_s_ap_key, tls13_s_ap_iv);
    tls13_key_iv(c_ap, tls13_c_ap_key, tls13_c_ap_iv);
    tls13_server_epoch_ap = 1;
    tls13_client_epoch_ap = 1;
    tls13_send_ap_seq = 0;
    tls13_recv_ap_seq = 0;
    /* Client Finished over Hash(CH..server Finished). */
    {
        u8 fin_key[32], verify[32];
        hkdf_expand_label(c_hs, "finished", 0, 0, fin_key, 32);
        hmac_sha256(fin_key, 32, th2, 32, verify);
        if (tls13_send_hs(20, verify, 32) != 0) return -1;
    }
    return 0;
}
/* Dispatcher: reset all state (1.2 + 1.3), send the combined
   hello, read ServerHello, and continue on the negotiated
   version. Returns 0, -1, or -2 (certificate failure). */
static int tls_handshake(const char *host) {
    tls_hs_len = 0;
    tls_transcript_len = 0;
    tls13_transcript_len = 0;
    tls13_hs_len = 0;
    tls_app_spill_len = 0; tls_app_spill_pos = 0;
    tls_send_seq = 0; tls_recv_seq = 0;
    tls_client_enc = 0; tls_server_enc = 0;
    tls13_send_hs_seq = 0; tls13_recv_hs_seq = 0;
    tls13_send_ap_seq = 0; tls13_recv_ap_seq = 0;
    tls13_stream_len = 0;
    tls13_server_epoch_ap = 0;
    tls13_client_epoch_ap = 0;
    tls13_got_encrypted = 0;
    tls_negotiated_version = 0;
    tls_sh_ks_present = 0;
    if (tls_send_combined_hello(host) != 0) return -1;
    int is13 = 0;
    if (tls_read_server_hello(&is13) != 0) return -1;
    int rc;
    if (is13) {
        rc = tls13_handshake_rest(host);
        if (rc == 0) tls_negotiated_version = 2;
    } else {
        rc = tls12_handshake_rest(host);
        if (rc == 0) tls_negotiated_version = 1;
    }
    return rc;
}

/* ---------- App data + HTTPS ---------- */
static int tls_send_app(const u8 *data, u32 len) {
    if (tls_negotiated_version == 2) return tls13_send_record(23, data, len);
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
    if (tls_negotiated_version == 2) return tls13_recv_app(buf, max);
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
static int https_get_inner(const char *host, u16 port, const char *path, char *buf, u32 max) {
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
    /* Same truncate-and-drain rule as net_http_get (v0.10.0). */
    net_set_fetch_truncated(0);
    u8 tmp[1024];
    u32 total = 0, seen = 0, header_end = 0, content_len = 0xFFFFFFFFu;
    int storing = 1;
    u32 start = timer_ticks;
    while (timer_ticks - start < 1000) {
        int n = tls_recv_app(tmp, sizeof(tmp));
        if (n < 0) break;
        if (n == 0) {
            if (header_end && content_len != 0xFFFFFFFFu &&
                seen >= header_end + content_len) break;
            continue;
        }
        seen += (u32)n;
        if (storing) {
            if (total + (u32)n > max - 1) {
                u32 room = max - 1 - total;
                if (room) { memcpy(buf + total, tmp, room); total += room; buf[total] = 0; }
                storing = 0; net_set_fetch_truncated(1);
            } else {
                memcpy(buf + total, tmp, (u32)n);
                total += (u32)n;
                buf[total] = 0;
            }
        }
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
        if (header_end && content_len != 0xFFFFFFFFu && seen >= header_end + content_len) break;
    }
    if (tls_negotiated_version == 2) {
        /* Best-effort close_notify under the application keys;
           failures are ignored — the TCP close below is the
           real teardown. */
        u8 cn[2] = { 1, 0 };
        (void)tls13_send_record(21, cn, 2);
    }
    net_tcp_close();
    if (!header_end) return -1;
    u32 body_len = total - header_end;
    memmove(buf, buf + header_end, body_len);
    buf[body_len] = 0;
    return (int)body_len;
}
int net_https_get(const char *host, u16 port, const char *path, char *buf, u32 max) {
    tls_verify_mode = 0;
    return https_get_inner(host, port, path, buf, max);
}
int net_https_get_anchored(const char *host, u16 port, const char *path, char *buf, u32 max) {
    tls_verify_mode = 1;
    return https_get_inner(host, port, path, buf, max);
}
int net_https_get_store(const char *host, u16 port, const char *path, char *buf, u32 max) {
    tls_verify_mode = 2;
    return https_get_inner(host, port, path, buf, max);
}
