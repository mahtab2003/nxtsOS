/* ChaCha20 DRBG (web/SSL Phase 1). See csprng.h for the entropy
   model and its honest limits. Only 32-bit adds, rotates and
   xors: no u64 division anywhere (the kernel has no 32-bit
   libgcc). All state is file-scope: nothing large sits on the
   16 KiB kernel stack (the 4 KiB self-test sample is .bss). */
#include "common.h"
#include "csprng.h"
#include "sha256.h"
#include "console.h"
#include "../drivers/pit.h"

/* ---------- ChaCha20 block (RFC 8439 section 2.1) ---------- */
static u32 rotl32(u32 v, int n) { return (v << n) | (v >> (32 - n)); }
static void qr(u32 *s, int a, int b, int c, int d) {
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);
}
static void chacha_block(const u8 key[32], u32 counter,
                         const u8 nonce[12], u8 out[64]) {
    static const char sigma[16] = "expand 32-byte k";
    u32 st[16], w[16];
    for (int i = 0; i < 4; i++)
        st[i] = (u32)(u8)sigma[i * 4] | ((u32)(u8)sigma[i * 4 + 1] << 8) |
                ((u32)(u8)sigma[i * 4 + 2] << 16) | ((u32)(u8)sigma[i * 4 + 3] << 24);
    for (int i = 0; i < 8; i++)
        st[4 + i] = (u32)key[i * 4] | ((u32)key[i * 4 + 1] << 8) |
                    ((u32)key[i * 4 + 2] << 16) | ((u32)key[i * 4 + 3] << 24);
    st[12] = counter;
    for (int i = 0; i < 3; i++)
        st[13 + i] = (u32)nonce[i * 4] | ((u32)nonce[i * 4 + 1] << 8) |
                     ((u32)nonce[i * 4 + 2] << 16) | ((u32)nonce[i * 4 + 3] << 24);
    for (int i = 0; i < 16; i++) w[i] = st[i];
    for (int r = 0; r < 10; r++) {
        qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
        qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
        u32 v = w[i] + st[i];
        out[i * 4] = (u8)v; out[i * 4 + 1] = (u8)(v >> 8);
        out[i * 4 + 2] = (u8)(v >> 16); out[i * 4 + 3] = (u8)(v >> 24);
    }
}

/* ---------- DRBG state ---------- */
static u8 drbg_key[32];
static u8 drbg_nonce[12];
static u32 drbg_counter = 0;
static int drbg_seeded = 0;
static u32 drbg_bytes_since_reseed = 0;
static u8 pool[32];
static u8 acc[32];
static u32 acc_pos = 0;
static u32 stir_count = 0;
static u32 last_stir = 0;

void csprng_stir(const u8 *data, u32 len) {
    /* Lock-free on purpose: called from IRQ context (keyboard,
       mouse). A torn stir byte is harmless — it only ever adds
       to the accumulator that the next reseed hashes. */
    for (u32 i = 0; i < len; i++) {
        acc[acc_pos] ^= data[i];
        acc_pos = (acc_pos + 1) & 31;
    }
    stir_count++;
}

static void csprng_reseed(void) {
    /* Key, nonce and next pool are three independent SHA-256
       outputs over the same pool + accumulator + stir-count
       input with different full-length domain strings, so a
       fresh key never reuses a nonce/counter pair from an
       earlier epoch. The accumulator is cleared: the same
       event timing is never mixed in twice. */
    u8 in[32 + 32 + 4 + 20];
    u8 digest[32];
    memcpy(in, pool, 32);
    memcpy(in + 32, acc, 32);
    in[64] = (u8)stir_count; in[65] = (u8)(stir_count >> 8);
    in[66] = (u8)(stir_count >> 16); in[67] = (u8)(stir_count >> 24);
    memcpy(in + 68, "nxts-csprng-key-v1", 18);
    sha256_compute(in, 86, digest);
    memcpy(drbg_key, digest, 32);
    memcpy(in + 68, "nxts-csprng-nonce-v1", 20);
    sha256_compute(in, 88, digest);
    memcpy(drbg_nonce, digest, 12);
    memcpy(in + 68, "nxts-csprng-pool-v1", 19);
    sha256_compute(in, 87, digest);
    memcpy(pool, digest, 32);
    memset(acc, 0, sizeof(acc));
    acc_pos = 0;
    last_stir = stir_count;
    drbg_counter = 0;
    drbg_bytes_since_reseed = 0;
    drbg_seeded = 1;
}

static u8 cmos_reg(u8 reg) {
    outb(0x70, (u8)(0x80 | reg));
    io_wait();
    return inb(0x71);
}

void csprng_init(void) {
    /* Boot seed: raw CMOS RTC registers (seconds, minutes,
       hours, day, month, year) plus the PIT tick count. The
       tick count is 0 this early (pit_init just ran, sti not
       yet set) — it is mixed in so the seed path is uniform,
       not because it adds anything at this point. */
    u8 seed[16];
    seed[0] = cmos_reg(0x00);
    seed[1] = cmos_reg(0x02);
    seed[2] = cmos_reg(0x04);
    seed[3] = cmos_reg(0x07);
    seed[4] = cmos_reg(0x08);
    seed[5] = cmos_reg(0x09);
    u32 t = timer_ticks;
    seed[6] = (u8)t; seed[7] = (u8)(t >> 8);
    seed[8] = (u8)(t >> 16); seed[9] = (u8)(t >> 24);
    for (int i = 10; i < 16; i++) seed[i] = 0;
    sha256_compute(seed, sizeof(seed), pool);
    csprng_reseed();
}

void csprng_generate(u8 *out, u32 len) {
    if (len == 0) return;
    /* Reseed when new event timing arrived since the last
       reseed (the common case: the user typed a command, then
       a handshake runs), when unseeded, or every 1 MiB of
       output (far below the 2^32-block counter wrap). Two
       SHA-256 calls per reseed are negligible next to a TLS
       handshake, which already does dozens. */
    if (!drbg_seeded) csprng_init();
    else if (stir_count != last_stir ||
             drbg_bytes_since_reseed >= (1u << 20))
        csprng_reseed();
    u8 block[64];
    u32 done = 0;
    while (done < len) {
        chacha_block(drbg_key, drbg_counter++, drbg_nonce, block);
        u32 take = len - done < 64 ? len - done : 64;
        memcpy(out + done, block, take);
        done += take;
    }
    memset(block, 0, sizeof(block));
    drbg_bytes_since_reseed += len;
}

/* ---------- self-test ---------- */
/* RFC 8439 section 2.3.2: key 00..1f, nonce
   000000000000004a00000000, counter 1. The expected block was
   produced by two independent implementations (a from-spec
   Python ChaCha and the `cryptography` package) and cross-
   checked against the RFC ciphertext for the "Ladies and
   Gentlemen" plaintext (starts 6e2e359a...). */
static const u8 vec_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const u8 vec_nonce[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
    0x00, 0x00, 0x00, 0x00
};
static const u8 vec_block[64] = {
    0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1,
    0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63, 0x1d, 0xed,
    0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c, 0x06, 0xe2,
    0x7e, 0x4f, 0xca, 0xec, 0x9e, 0xf3, 0xcf, 0x78,
    0x8a, 0x3b, 0x0a, 0xa3, 0x72, 0x60, 0x0a, 0x92,
    0xb5, 0x79, 0x74, 0xcd, 0xed, 0x2b, 0x93, 0x34,
    0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34, 0xcd,
    0xea, 0x21, 0x2c, 0x4c, 0xf0, 0x7d, 0x41, 0xb7
};
static u8 csprng_test_buf[4096];

int csprng_selftest(void) {
    u8 block[64];
    chacha_block(vec_key, 1, vec_nonce, block);
    int vec_ok = memcmp(block, vec_block, 64) == 0;
    csprng_generate(csprng_test_buf, sizeof(csprng_test_buf));
    u32 ones = 0;
    for (u32 i = 0; i < sizeof(csprng_test_buf); i++) {
        u8 b = csprng_test_buf[i];
        while (b) { ones += b & 1; b >>= 1; }
    }
    /* Monobit on 32768 bits: mean 16384, sigma ~91. The
       [15000, 18000] window is ~15 sigma wide: it cannot
       flake on a healthy DRBG, and still catches stuck or
       degenerate output (all-zero, single-bit, short cycles
       visible at 4 KiB). This is a sanity check, NOT a
       randomness proof — no such claim is made. */
    int mono_ok = ones >= 15000 && ones <= 18000;
    int zero_ok = 1;
    for (u32 off = 0; off + 64 <= sizeof(csprng_test_buf); off += 64) {
        int allzero = 1;
        for (int j = 0; j < 64; j++) if (csprng_test_buf[off + j]) { allzero = 0; break; }
        if (allzero) { zero_ok = 0; break; }
    }
    int differ_ok = memcmp(csprng_test_buf, csprng_test_buf + 32, 32) != 0;
    console_printf("csprng: vector %s, monobit %u/32768, zero-block %s, differ %s\n",
                   vec_ok ? "OK" : "FAIL", ones,
                   zero_ok ? "OK" : "FAIL", differ_ok ? "OK" : "FAIL");
    return (vec_ok && mono_ok && zero_ok && differ_ok) ? 0 : -1;
}
