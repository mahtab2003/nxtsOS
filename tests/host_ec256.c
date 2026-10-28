/* Host test for net/ec256.c (SEC2 vectors). Not a kernel test:
   it compiles the same C file on the host with kernel-signature
   memset/memcpy/memcmp shims, so curve bugs are caught in
   seconds instead of a QEMU boot. Build:
   gcc -fno-builtin -o /tmp/host_ec256 tests/host_ec256.c net/ec256.c
   (run from ~/workspace/nxtsOS). Exit 0 on PASS. */
#include <stdio.h>
#include "../net/ec256.h"

void *memset(void *dst, int val, u32 n) {
    u8 *d = dst;
    for (u32 i = 0; i < n; i++) d[i] = (u8)val;
    return dst;
}
void *memcpy(void *dst, const void *src, u32 n) {
    const u8 *s = src;
    u8 *d = dst;
    for (u32 i = 0; i < n; i++) d[i] = s[i];
    return dst;
}
int memcmp(const void *a, const void *b, u32 n) {
    const u8 *x = a, *y = b;
    for (u32 i = 0; i < n; i++) if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
}
/* Kernel helpers used by common.h consumers but not by ec256. */
u32 strlen(const char *s) { u32 n = 0; while (s[n]) n++; return n; }
int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (u8)*a - (u8)*b;
}
int strncmp(const char *a, const char *b, u32 n) {
    for (u32 i = 0; i < n; i++) {
        if (a[i] != b[i]) return (u8)a[i] - (u8)b[i];
        if (!a[i]) return 0;
    }
    return 0;
}
void *memmove(void *dst, const void *src, u32 n) {
    u8 *d = dst;
    const u8 *s = src;
    if (d < s) { for (u32 i = 0; i < n; i++) d[i] = s[i]; }
    else { for (u32 i = n; i > 0; i--) d[i - 1] = s[i - 1]; }
    return dst;
}
void u32_to_str(u32 v, char *buf, int base) {
    char tmp[32];
    int i = 0;
    if (v == 0) tmp[i++] = '0';
    while (v) { tmp[i++] = "0123456789abcdef"[v % (u32)base]; v /= (u32)base; }
    int j = 0;
    while (i) buf[j++] = tmp[--i];
    buf[j] = 0;
}
void console_write(const char *s) { (void)s; }

static int hex_to_bytes(const char *hex, u8 *out) {
    int n = 0;
    while (hex[2 * n] && hex[2 * n + 1]) {
        u32 hi = hex[2 * n] >= 'a' ? (u32)(hex[2 * n] - 'a' + 10)
               : hex[2 * n] >= 'A' ? (u32)(hex[2 * n] - 'A' + 10)
               : (u32)(hex[2 * n] - '0');
        u32 lo = hex[2 * n + 1] >= 'a' ? (u32)(hex[2 * n + 1] - 'a' + 10)
               : hex[2 * n + 1] >= 'A' ? (u32)(hex[2 * n + 1] - 'A' + 10)
               : (u32)(hex[2 * n + 1] - '0');
        out[n++] = (u8)((hi << 4) | lo);
    }
    return n;
}
static void print_hex(const char *label, const u8 *b, int n) {
    printf("%s", label);
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    int fails = 0;
    u8 priv[32], x[32], y[32], shared[32];
    u8 gx[32], gy[32], two_x[32], two_y[32];
    hex_to_bytes("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", gx);
    hex_to_bytes("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", gy);
    hex_to_bytes("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978", two_x);
    hex_to_bytes("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1", two_y);

    memset(priv, 0, 32); priv[31] = 1;
    if (p256_pub_from_priv(priv, x, y) != 0 || memcmp(x, gx, 32) || memcmp(y, gy, 32)) {
        printf("FAIL 1*G\n"); print_hex(" got x=", x, 32); print_hex(" got y=", y, 32); fails++;
    } else printf("PASS 1*G == G\n");

    memset(priv, 0, 32); priv[31] = 2;
    if (p256_pub_from_priv(priv, x, y) != 0 || memcmp(x, two_x, 32) || memcmp(y, two_y, 32)) {
        printf("FAIL 2*G\n"); print_hex(" got x=", x, 32); print_hex(" got y=", y, 32); fails++;
    } else printf("PASS 2*G == SEC2 vector\n");

    /* ECDH commutativity: 2*G == 1*(2G). */
    memset(priv, 0, 32); priv[31] = 2;
    if (p256_ecdh(priv, gx, gy, shared) != 0 || memcmp(shared, two_x, 32)) {
        printf("FAIL ECDH 2*G\n"); print_hex(" got=", shared, 32); fails++;
    } else printf("PASS ECDH 2*G\n");
    memset(priv, 0, 32); priv[31] = 1;
    if (p256_ecdh(priv, two_x, two_y, shared) != 0 || memcmp(shared, two_x, 32)) {
        printf("FAIL ECDH 1*(2G)\n"); print_hex(" got=", shared, 32); fails++;
    } else printf("PASS ECDH 1*(2G) == 2G\n");

    /* Invalid points must fail closed. */
    memset(priv, 0, 32); priv[31] = 2;
    u8 zero[32]; memset(zero, 0, 32);
    if (p256_ecdh(priv, zero, zero, shared) == 0) { printf("FAIL (0,0) accepted\n"); fails++; }
    else printf("PASS (0,0) refused\n");
    u8 bad_y[32]; memcpy(bad_y, gy, 32); bad_y[31] ^= 1;
    if (p256_ecdh(priv, gx, bad_y, shared) == 0) { printf("FAIL off-curve accepted\n"); fails++; }
    else printf("PASS off-curve refused\n");
    /* Private key 0 and >= n must fail. */
    if (p256_pub_from_priv(zero, x, y) == 0) { printf("FAIL priv 0 refused\n"); fails++; }
    else printf("PASS priv 0 refused\n");

    /* ECDSA P-256/SHA-256 vector (generated with the python
       cryptography lib; lib-verified before hardcoding).
       Public key, hash, (r, s) below; negatives flip one
       input each and must all refuse. */
    {
        u8 qx[32], qy[32], hash[32], r[32], s[32];
        hex_to_bytes("471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714c", qx);
        hex_to_bytes("dd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858", qy);
        hex_to_bytes("6d1980685444f6b1984fa64cd7d3736d92209a56b103bca4d1b034becdafb7d1", hash);
        hex_to_bytes("a6828d5600dcaa7ed92c3bcc658a3ea745389d083040a29fd508a50de809f61f", r);
        hex_to_bytes("0a3c7376b7bb92d8cc971b891c0b761d748c0c8ad2499b24ea153dd43a5cdc28", s);
        if (p256_ecdsa_verify(qx, qy, hash, r, s) != 0) { printf("FAIL ECDSA verify\n"); fails++; }
        else printf("PASS ECDSA verify\n");
        u8 bad[32];
        memcpy(bad, s, 32); bad[31] ^= 1;
        if (p256_ecdsa_verify(qx, qy, hash, r, bad) == 0) { printf("FAIL ECDSA bad-s accepted\n"); fails++; }
        else printf("PASS ECDSA bad-s refused\n");
        memcpy(bad, hash, 32); bad[0] ^= 1;
        if (p256_ecdsa_verify(qx, qy, bad, r, s) == 0) { printf("FAIL ECDSA bad-hash accepted\n"); fails++; }
        else printf("PASS ECDSA bad-hash refused\n");
        memset(bad, 0, 32);
        if (p256_ecdsa_verify(qx, qy, hash, bad, s) == 0) { printf("FAIL ECDSA r=0 accepted\n"); fails++; }
        else printf("PASS ECDSA r=0 refused\n");
        memcpy(bad, qy, 32); bad[31] ^= 1;
        if (p256_ecdsa_verify(qx, bad, hash, r, s) == 0) { printf("FAIL ECDSA off-curve Q accepted\n"); fails++; }
        else printf("PASS ECDSA off-curve Q refused\n");
    }

    printf(fails ? "HOST EC256 FAIL (%d)\n" : "HOST EC256 PASS\n", fails);
    return fails ? 1 : 0;
}
