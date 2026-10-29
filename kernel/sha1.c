#include "sha1.h"

/* SHA-1 (FIPS 180-1). One-shot over any length: full 64-byte
   blocks are processed straight from the input buffer; only
   the final padding block(s) are built locally. */

static u32 rotl32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_block(u32 h[5], const u8 block[64]) {
    u32 w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((u32)block[i * 4] << 24) | ((u32)block[i * 4 + 1] << 16) |
               ((u32)block[i * 4 + 2] << 8) | (u32)block[i * 4 + 3];
    for (int i = 16; i < 80; i++)
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        u32 f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        u32 tmp = rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl32(b, 30); b = a; a = tmp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void sha1_compute(const u8 *data, u32 len, u8 out[20]) {
    u32 h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    u32 full = len / 64;
    for (u32 i = 0; i < full; i++) sha1_block(h, data + i * 64);
    /* Tail: remaining bytes + 0x80 + zeros + 64-bit BE bit length.
       One block unless the tail already fills 56+ bytes. */
    u8 tail[128];
    u32 rem = len % 64;
    u32 tlen = 0;
    for (u32 i = 0; i < rem; i++) tail[tlen++] = data[full * 64 + i];
    tail[tlen++] = 0x80;
    while (tlen % 64 != 56) tail[tlen++] = 0;
    /* len < 2^29 in every TLS use, so the high word is zero. */
    tail[tlen++] = 0; tail[tlen++] = 0; tail[tlen++] = 0; tail[tlen++] = 0;
    u32 bits_lo = len * 8;
    tail[tlen++] = (u8)(bits_lo >> 24);
    tail[tlen++] = (u8)(bits_lo >> 16);
    tail[tlen++] = (u8)(bits_lo >> 8);
    tail[tlen++] = (u8)(bits_lo);
    sha1_block(h, tail);
    if (tlen > 64) sha1_block(h, tail + 64);
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (u8)(h[i] >> 24);
        out[i * 4 + 1] = (u8)(h[i] >> 16);
        out[i * 4 + 2] = (u8)(h[i] >> 8);
        out[i * 4 + 3] = (u8)(h[i]);
    }
}
