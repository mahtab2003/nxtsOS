#include "common.h"

u32 strlen(const char *s) {
    u32 n = 0;
    while (s[n]) n++;
    return n;
}

int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int strncmp(const char *a, const char *b, u32 n) {
    for (u32 i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
        if (a[i] == 0) return 0;
    }
    return 0;
}

void *memset(void *dst, int val, u32 n) {
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++) p[i] = (u8)val;
    return dst;
}

int memcmp(const void *a, const void *b, u32 n) {
    const u8 *x = (const u8 *)a, *y = (const u8 *)b;
    for (u32 i = 0; i < n; i++) {
        if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    }
    return 0;
}

void *memcpy(void *dst, const void *src, u32 n) {
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (u32 i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

void u32_to_str(u32 v, char *buf, int base) {
    /* Only bases 10 and 16 are used. Both are handled without a runtime
       division call, so the kernel links without libgcc (no 32-bit libgcc
       on the host): base 16 via shifts, base 10 via constant division,
       which GCC turns into reciprocal multiplication. */
    static const char digits[] = "0123456789ABCDEF";
    char tmp[32];
    int i = 0;
    if (v == 0) { buf[0] = '0'; buf[1] = 0; return; }
    if (base == 16) {
        while (v > 0) { tmp[i++] = digits[v & 0xFu]; v >>= 4; }
    } else {
        while (v > 0) { tmp[i++] = digits[v % 10u]; v /= 10u; }
    }
    int j = 0;
    while (i > 0) buf[j++] = tmp[--i];
    buf[j] = 0;
}
