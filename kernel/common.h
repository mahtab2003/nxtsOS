#ifndef NXTS_COMMON_H
#define NXTS_COMMON_H

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef int            s32;
/* u64: multiplication/addition/subtraction only. 64-bit
   division/modulo would need libgcc (__udivdi3), which the
   freestanding kernel does not link — bignum code avoids it
   (binary long division). Never divide a u64 here. */
typedef unsigned long long u64;

static inline void outb(u16 port, u8 val) {
    __asm__ volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}
static inline u8 inb(u16 port) {
    u8 ret;
    __asm__ volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
static inline void outw(u16 port, u16 val) {
    __asm__ volatile ("outw %0, %1" : : "a"(val), "Nd"(port));
}
static inline u16 inw(u16 port) {
    u16 ret;
    __asm__ volatile ("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
static inline void outl(u16 port, u32 val) {
    __asm__ volatile ("outl %0, %1" : : "a"(val), "Nd"(port));
}
static inline u32 inl(u16 port) {
    u32 ret;
    __asm__ volatile ("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
static inline void io_wait(void) { outb(0x80, 0); }

u32  strlen(const char *s);
int  strcmp(const char *a, const char *b);
int  memcmp(const void *a, const void *b, u32 n);
int  strncmp(const char *a, const char *b, u32 n);
void *memset(void *dst, int val, u32 n);
void *memcpy(void *dst, const void *src, u32 n);
void *memmove(void *dst, const void *src, u32 n);
void  u32_to_str(u32 v, char *buf, int base);
void  console_write(const char *s);
void  console_printf(const char *fmt, ...);

#endif
