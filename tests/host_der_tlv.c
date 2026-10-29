/* Host test for the DER TLV length parser used by net/tls.c
   certificate verification (parse_cert / verify_chain).
   der_tlv is static inside net/tls.c and cannot be linked
   standalone (tls.c pulls in the whole kernel), so this file
   carries a VERBATIM COPY of der_tlv. If net/tls.c der_tlv
   changes, update the copy below to match, or this test pins
   stale code. Purpose: pin the length-overflow check — a
   crafted certificate Name length near 2^32 must be rejected,
   never accepted via u32 wraparound (which would hand
   verify_chain a ~4 GiB issuer_len/subject_len for memcmp,
   an out-of-bounds read -> kernel panic from a malicious
   server certificate).
   Build: gcc -o /tmp/host_der_tlv tests/host_der_tlv.c
   (run from ~/workspace/nxtsOS). Exit 0 on PASS. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;

/* ---- VERBATIM COPY of net/tls.c der_tlv (v1.1.3, FIXED) ---- */
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
        if (n > buflen - pos - 2) return -1;
        vl = 0;
        for (u32 i = 0; i < n; i++) vl = (vl << 8) | buf[pos + 2 + i];
        hl = 2 + n;
    }
    if (hl > buflen - pos) return -1;
    if (vl > buflen - pos - hl) return -1;
    *tag = t; *hdr_len = hl; *val_len = vl; *val_pos = pos + hl;
    return 0;
}
/* ---- END COPY ---- */

static int fails = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("PASS %s\n", name); \
    else { printf("FAIL %s\n", name); fails++; } } while (0)

int main(void) {
    static u8 buf[16384];
    u8 tag; u32 hl, vl, vp; int rc;

    /* 1. Short form, exact fit. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x30; buf[1] = 0x03; buf[2] = 'a'; buf[3] = 'b'; buf[4] = 'c';
    rc = der_tlv(buf, 5, 0, &tag, &hl, &vl, &vp);
    CHECK(rc == 0 && tag == 0x30 && hl == 2 && vl == 3 && vp == 2, "short-form");

    /* 2. WRAPPED length: pos=100, len bytes FF FF FF F0.
       pos+hl+vl wraps to 86 <= 2000, so the old code ACCEPTED
       vl=0xFFFFFFF0. Fixed code must reject. */
    memset(buf, 0, sizeof(buf));
    buf[100] = 0x30; buf[101] = 0x84;
    buf[102] = 0xFF; buf[103] = 0xFF; buf[104] = 0xFF; buf[105] = 0xF0;
    rc = der_tlv(buf, 2000, 100, &tag, &hl, &vl, &vp);
    CHECK(rc == -1, "wrapped-length-0xFFFFFFF0-rejected");

    /* 3. Honest long form: vl=256 in a 300-byte buffer. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x30; buf[1] = 0x82; buf[2] = 0x01; buf[3] = 0x00;
    rc = der_tlv(buf, 300, 0, &tag, &hl, &vl, &vp);
    CHECK(rc == 0 && hl == 4 && vl == 256 && vp == 4, "long-form-256");

    /* 4. Honest overlong: vl=5000 > buflen=2000. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x30; buf[1] = 0x82; buf[2] = 0x13; buf[3] = 0x88;
    rc = der_tlv(buf, 2000, 0, &tag, &hl, &vl, &vp);
    CHECK(rc == -1, "overlong-5000-rejected");

    /* 5. Boundary: exact fit, vl = buflen - pos - hl. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x30; buf[1] = 0x08;
    rc = der_tlv(buf, 10, 0, &tag, &hl, &vl, &vp);
    CHECK(rc == 0 && vl == 8, "exact-fit");

    /* 6. Off-by-one over: vl = buflen - pos - hl + 1. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x30; buf[1] = 0x09;
    rc = der_tlv(buf, 10, 0, &tag, &hl, &vl, &vp);
    CHECK(rc == -1, "off-by-one-rejected");

    /* 7. WRAPPED length at TLS 1.3 scale: buflen=16384, pos=500,
       vl=0xFFFFFF00 -> pos+hl+vl wraps to 506 <= 16384. */
    memset(buf, 0, sizeof(buf));
    buf[500] = 0x30; buf[501] = 0x84;
    buf[502] = 0xFF; buf[503] = 0xFF; buf[504] = 0xFF; buf[505] = 0x00;
    rc = der_tlv(buf, 16384, 500, &tag, &hl, &vl, &vp);
    CHECK(rc == -1, "wrapped-length-0xFFFFFF00-rejected");

    /* 8. Indefinite form rejected. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x30; buf[1] = 0x80;
    rc = der_tlv(buf, 100, 0, &tag, &hl, &vl, &vp);
    CHECK(rc == -1, "indefinite-rejected");

    /* 9. Multi-byte tag rejected. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x1F; buf[1] = 0x01;
    rc = der_tlv(buf, 100, 0, &tag, &hl, &vl, &vp);
    CHECK(rc == -1, "multibyte-tag-rejected");

    /* 10. Long form with n=5 rejected. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x30; buf[1] = 0x85;
    rc = der_tlv(buf, 100, 0, &tag, &hl, &vl, &vp);
    CHECK(rc == -1, "longform-n5-rejected");

    /* 11. Max-length honest value: vl = 0xFFFFFFFF must be
       rejected for any real buflen (it cannot fit). */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x30; buf[1] = 0x84;
    buf[2] = 0xFF; buf[3] = 0xFF; buf[4] = 0xFF; buf[5] = 0xFF;
    rc = der_tlv(buf, 16384, 0, &tag, &hl, &vl, &vp);
    CHECK(rc == -1, "max-length-rejected");

    if (fails) { printf("RESULT FAIL (%d failures)\n", fails); return 1; }
    printf("RESULT PASS\n");
    return 0;
}
