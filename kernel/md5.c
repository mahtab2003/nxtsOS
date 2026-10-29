#include "md5.h"

/* MD5 (RFC 1321). One-shot over any length: full 64-byte blocks
   are processed straight from the input buffer; only the final
   padding block(s) are built locally, so a 16 KiB transcript
   hash needs no large stack buffer. */

static u32 rotl32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

/* Per-round shift amounts. */
static const u8 MD5_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

/* K[i] = floor(abs(sin(i+1)) * 2^32), RFC 1321 table. */
static const u32 MD5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static void md5_block(u32 h[4], const u8 block[64]) {
    u32 m[16];
    for (int i = 0; i < 16; i++)
        m[i] = (u32)block[i * 4] | ((u32)block[i * 4 + 1] << 8) |
               ((u32)block[i * 4 + 2] << 16) | ((u32)block[i * 4 + 3] << 24);
    u32 a = h[0], b = h[1], c = h[2], d = h[3];
    for (int i = 0; i < 64; i++) {
        u32 f;
        int g;
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
        else { f = c ^ (b | ~d); g = (7 * i) % 16; }
        u32 tmp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + MD5_K[i] + m[g], MD5_S[i]);
        a = tmp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
}

void md5_compute(const u8 *data, u32 len, u8 out[16]) {
    u32 h[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    u32 full = len / 64;
    for (u32 i = 0; i < full; i++) md5_block(h, data + i * 64);
    /* Tail: remaining bytes + 0x80 + zeros + 64-bit LE bit length.
       Needs one block unless the tail already fills 56+ bytes,
       in which case the length spills into a second block. */
    u8 tail[128];
    u32 rem = len % 64;
    u32 tlen = 0;
    for (u32 i = 0; i < rem; i++) tail[tlen++] = data[full * 64 + i];
    tail[tlen++] = 0x80;
    while (tlen % 64 != 56) tail[tlen++] = 0;
    u32 bits_lo = len * 8; /* len < 2^29 in every TLS use; no hi word */
    tail[tlen++] = (u8)(bits_lo);
    tail[tlen++] = (u8)(bits_lo >> 8);
    tail[tlen++] = (u8)(bits_lo >> 16);
    tail[tlen++] = (u8)(bits_lo >> 24);
    tail[tlen++] = 0; tail[tlen++] = 0; tail[tlen++] = 0; tail[tlen++] = 0;
    md5_block(h, tail);
    if (tlen > 64) md5_block(h, tail + 64);
    for (int i = 0; i < 4; i++) {
        out[i * 4] = (u8)(h[i]);
        out[i * 4 + 1] = (u8)(h[i] >> 8);
        out[i * 4 + 2] = (u8)(h[i] >> 16);
        out[i * 4 + 3] = (u8)(h[i] >> 24);
    }
}
