#include "sha256.h"

static const u32 K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};
static u32 rotr(u32 x, u32 n) { return (x >> n) | (x << (32 - n)); }

void sha256_compute(const u8 *data, u32 len, u8 out[32]) {
    u32 h[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    /* Process full 64-byte blocks, then the final padded block(s).
       Data is read through a small block buffer so the caller may
       pass any length, including lengths that are not a multiple
       of 64, without the caller doing padding. */
    u32 total_blocks = (len + 9 + 63) / 64;
    for (u32 bi = 0; bi < total_blocks; bi++) {
        u8 block[64];
        for (int i = 0; i < 64; i++) {
            u32 pos = bi * 64u + (u32)i;
            if (pos < len) block[i] = data[pos];
            else if (pos == len) block[i] = 0x80;
            else if (pos >= len + 1 && pos < total_blocks * 64u - 8) block[i] = 0;
            else {
                /* Last 8 bytes: bit length, big-endian. Lengths here
                   are at most 128 KiB, so the high 32 bits are zero. */
                u32 bitpos = pos - (total_blocks * 64u - 8);
                u32 bits = len * 8u;
                block[i] = bitpos < 4 ? 0 : (u8)((bits >> ((7 - bitpos) * 8)) & 0xFF);
            }
        }
        u32 w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((u32)block[i*4] << 24) | ((u32)block[i*4+1] << 16) |
                   ((u32)block[i*4+2] << 8) | (u32)block[i*4+3];
        for (int i = 16; i < 64; i++) {
            u32 s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            u32 s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        u32 a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int i = 0; i < 64; i++) {
            u32 S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            u32 ch = (e & f) ^ ((~e) & g);
            u32 t1 = hh + S1 + ch + K[i] + w[i];
            u32 S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            u32 mj = (a & b) ^ (a & c) ^ (b & c);
            u32 t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        out[i*4] = (u8)((h[i] >> 24) & 0xFF); out[i*4+1] = (u8)((h[i] >> 16) & 0xFF);
        out[i*4+2] = (u8)((h[i] >> 8) & 0xFF); out[i*4+3] = (u8)(h[i] & 0xFF);
    }
}

void sha256_hex(const u8 hash[32], char out[65]) {
    static const char *digits = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i*2] = digits[(hash[i] >> 4) & 0xF];
        out[i*2+1] = digits[hash[i] & 0xF];
    }
    out[64] = 0;
}

int sha256_parse_hex(const char *hex, u8 out[32]) {
    for (int i = 0; i < 64; i++) {
        char c = hex[i];
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return -1;
        if (i % 2 == 0) out[i/2] = (u8)(v << 4);
        else out[i/2] |= (u8)v;
    }
    return 0;
}
