#include "aes.h"

/* GF(2^8) with polynomial x^8 + x^4 + x^3 + x + 1 (0x11b). */
static u8 gf_mul(u8 a, u8 b) {
    u8 p = 0;
    while (b) {
        if (b & 1) p ^= a;
        u8 hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}
static u8 gf_inv(u8 a) {
    if (a == 0) return 0;
    for (u32 x = 1; x < 256; x++)
        if (gf_mul(a, (u8)x) == 1) return (u8)x;
    return 0; /* unreachable */
}
static u8 rotl8(u8 x, int n) { return (u8)((x << n) | (x >> (8 - n))); }
static u8 sbox[256];
static int sbox_ready = 0;
static void sbox_init(void) {
    if (sbox_ready) return;
    for (u32 i = 0; i < 256; i++) {
        u8 inv = gf_inv((u8)i);
        sbox[i] = (u8)(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
    }
    sbox_ready = 1;
}
static u8 rcon(int i) {
    /* 2^(i-1) in GF, i = 1..7 for AES-256. */
    u8 r = 1;
    for (int j = 1; j < i; j++) r = gf_mul(r, 2);
    return r;
}

void aes256_expand(const u8 key[32], u32 rk[60]) {
    sbox_init();
    for (int i = 0; i < 8; i++)
        rk[i] = ((u32)key[i*4] << 24) | ((u32)key[i*4+1] << 16) |
                ((u32)key[i*4+2] << 8) | (u32)key[i*4+3];
    for (int i = 8; i < 60; i++) {
        u32 temp = rk[i-1];
        if (i % 8 == 0) {
            /* RotWord + SubWord + Rcon. */
            u32 rot = (temp << 8) | (temp >> 24);
            u32 sub = ((u32)sbox[(rot >> 24) & 0xFF] << 24) |
                      ((u32)sbox[(rot >> 16) & 0xFF] << 16) |
                      ((u32)sbox[(rot >> 8) & 0xFF] << 8) |
                      (u32)sbox[rot & 0xFF];
            temp = sub ^ ((u32)rcon(i / 8) << 24);
        } else if (i % 8 == 4) {
            temp = ((u32)sbox[(temp >> 24) & 0xFF] << 24) |
                   ((u32)sbox[(temp >> 16) & 0xFF] << 16) |
                   ((u32)sbox[(temp >> 8) & 0xFF] << 8) |
                   (u32)sbox[temp & 0xFF];
        }
        rk[i] = rk[i-8] ^ temp;
    }
}

void aes128_expand(const u8 key[16], u32 rk[44]) {
    sbox_init();
    for (int i = 0; i < 4; i++)
        rk[i] = ((u32)key[i*4] << 24) | ((u32)key[i*4+1] << 16) |
                ((u32)key[i*4+2] << 8) | (u32)key[i*4+3];
    for (int i = 4; i < 44; i++) {
        u32 temp = rk[i-1];
        if (i % 4 == 0) {
            u32 rot = (temp << 8) | (temp >> 24);
            u32 sub = ((u32)sbox[(rot >> 24) & 0xFF] << 24) |
                      ((u32)sbox[(rot >> 16) & 0xFF] << 16) |
                      ((u32)sbox[(rot >> 8) & 0xFF] << 8) |
                      (u32)sbox[rot & 0xFF];
            temp = sub ^ ((u32)rcon(i / 4) << 24);
        }
        rk[i] = rk[i-4] ^ temp;
    }
}

static void aes_encrypt_nr(const u32 *rk, const u8 in[16], u8 out[16], int nr) {
    sbox_init();
    /* State is column-major: state[r][c] = in[r + 4*c]. */
    u8 s[4][4];
    for (int c = 0; c < 4; c++) for (int r = 0; r < 4; r++) s[r][c] = in[r + 4*c];
    /* AddRoundKey, round 0. */
    for (int c = 0; c < 4; c++) {
        u32 w = rk[c];
        for (int r = 0; r < 4; r++) s[r][c] ^= (u8)((w >> (24 - r*8)) & 0xFF);
    }
    for (int round = 1; round <= nr; round++) {
        /* SubBytes. */
        for (int c = 0; c < 4; c++) for (int r = 0; r < 4; r++) s[r][c] = sbox[s[r][c]];
        /* ShiftRows: row r shifts left by r. */
        for (int r = 1; r < 4; r++) {
            u8 tmp[4];
            for (int c = 0; c < 4; c++) tmp[c] = s[r][(c + r) % 4];
            for (int c = 0; c < 4; c++) s[r][c] = tmp[c];
        }
        if (round < nr) {
            /* MixColumns. */
            for (int c = 0; c < 4; c++) {
                u8 a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
                s[0][c] = (u8)(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
                s[1][c] = (u8)(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
                s[2][c] = (u8)(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
                s[3][c] = (u8)(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
            }
        }
        /* AddRoundKey, round `round`. */
        for (int c = 0; c < 4; c++) {
            u32 w = rk[round*4 + c];
            for (int r = 0; r < 4; r++) s[r][c] ^= (u8)((w >> (24 - r*8)) & 0xFF);
        }
    }
    for (int c = 0; c < 4; c++) for (int r = 0; r < 4; r++) out[r + 4*c] = s[r][c];
}

void aes256_encrypt(const u32 rk[60], const u8 in[16], u8 out[16]) {
    aes_encrypt_nr(rk, in, out, 14);
}
void aes128_encrypt(const u32 rk[44], const u8 in[16], u8 out[16]) {
    aes_encrypt_nr(rk, in, out, 10);
}
