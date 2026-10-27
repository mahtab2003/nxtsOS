#include "enc.h"
#include "aes.h"
#include "sha256.h"
#include "console.h"
#include "../drivers/ata.h"
#include "../drivers/keyboard.h"

static int enc_on = 0;
static u32 enc_rk[60];
static const char CHECK_PLAIN[17] = "NXTS-KEY-CHECK!!";

int enc_enabled(void) { return enc_on; }

void enc_sector_crypt(u32 logical_lba, const u8 in[512], u8 out[512]) {
    for (int b = 0; b < 32; b++) {
        u32 counter = logical_lba * 32u + (u32)b;
        u8 iv[16] = {0};
        iv[12] = (u8)((counter >> 24) & 0xFF);
        iv[13] = (u8)((counter >> 16) & 0xFF);
        iv[14] = (u8)((counter >> 8) & 0xFF);
        iv[15] = (u8)(counter & 0xFF);
        u8 ks[16];
        aes256_encrypt(enc_rk, iv, ks);
        for (int i = 0; i < 16; i++) out[b*16 + i] = (u8)(in[b*16 + i] ^ ks[i]);
    }
}

static void derive_key(const char *pass, const u8 salt[16], u32 iterations, u8 key[32]) {
    u8 buf[80];
    u32 i = 0;
    for (int j = 0; j < 16; j++) buf[i++] = salt[j];
    const char *p = pass;
    while (*p && i < sizeof(buf)) buf[i++] = (u8)*p++;
    u8 h[32];
    sha256_compute(buf, i, h);
    /* Total rounds = 10000: the initial hash plus 9999 iterations
       of SHA256(previous hash + salt). tools/mkdisk_enc.py does
       exactly the same, in the same order. */
    for (u32 r = 1; r < iterations; r++) {
        u8 in2[48];
        for (int j = 0; j < 32; j++) in2[j] = h[j];
        for (int j = 0; j < 16; j++) in2[32 + j] = salt[j];
        sha256_compute(in2, 48, h);
    }
    for (int j = 0; j < 32; j++) key[j] = h[j];
}

static int read_line_noecho(char *buf, u32 max) {
    u32 len = 0;
    for (;;) {
        int c = keyboard_getchar();
        if (c < 0) { __asm__ volatile ("hlt"); continue; }
        if (c == '\n') { console_putchar('\n'); buf[len] = 0; return (int)len; }
        if (c == '\b') { if (len > 0) len--; }
        else if (len < max - 1) buf[len++] = (char)c;
    }
}

int enc_unlock(void) {
    if (!ata_present()) return 0;
    /* Read the physical header with the raw ATA path: at this point
       encryption is not yet enabled, so the translated path would
       read the same sector anyway, but raw is explicit and safe. */
    u8 hdr[512];
    if (ata_read_sector_raw(0, hdr) != 0) return 0; /* no readable disk: let fs_mount report it */
    if (memcmp(hdr, "NXTSFS01", 8) == 0) return 0; /* unencrypted disk */
    if (memcmp(hdr, "NXTSENC1", 8) != 0) return 0; /* unknown: let fs_mount report it */
    u32 version = (u32)hdr[8] | ((u32)hdr[9] << 8) | ((u32)hdr[10] << 16) | ((u32)hdr[11] << 24);
    u32 iterations = (u32)hdr[12] | ((u32)hdr[13] << 8) | ((u32)hdr[14] << 16) | ((u32)hdr[15] << 24);
    if (version != 1 || iterations < 1000 || iterations > 100000) {
        console_write("Encrypted disk: unsupported header version or iteration count.\n");
        return -1;
    }
    u8 salt[16];
    for (int i = 0; i < 16; i++) salt[i] = hdr[16 + i];
    console_write("Encrypted disk detected.\n");
    for (int attempt = 1; attempt <= 3; attempt++) {
        console_write("Disk passphrase: ");
        char pass[65];
        read_line_noecho(pass, sizeof(pass));
        if (pass[0] == 0) { console_write("Wrong passphrase.\n"); continue; }
        u8 key[32];
        derive_key(pass, salt, iterations, key);
        u32 rk[60];
        aes256_expand(key, rk);
        u8 cipher[16];
        aes256_encrypt(rk, (const u8 *)CHECK_PLAIN, cipher);
        int ok = memcmp(cipher, hdr + 32, 16) == 0;
        /* Clear the derived key from the stack copy on failure. */
        if (!ok) {
            memset(key, 0, sizeof(key));
            console_write("Wrong passphrase.\n");
            continue;
        }
        for (int i = 0; i < 60; i++) enc_rk[i] = rk[i];
        enc_on = 1;
        console_write("Disk unlocked.\n");
        return 0;
    }
    console_write("Too many failed attempts. System halted.\n");
    for (;;) __asm__ volatile ("hlt");
}
