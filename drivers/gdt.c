#include "gdt.h"
#include "../kernel/common.h"

struct gdt_entry {
    u16 limit_lo, base_lo;
    u8  base_mid, access, granularity, base_hi;
} __attribute__((packed));
struct gdt_ptr {
    u16 limit;
    u32 base;
} __attribute__((packed));

static struct gdt_entry gdt[3];
struct gdt_ptr gdt_ptr;
extern void gdt_flush(void);

static void gdt_set(int i, u32 base, u32 limit, u8 access, u8 gran) {
    gdt[i].base_lo = (u16)(base & 0xFFFF);
    gdt[i].base_mid = (u8)((base >> 16) & 0xFF);
    gdt[i].base_hi = (u8)((base >> 24) & 0xFF);
    gdt[i].limit_lo = (u16)(limit & 0xFFFF);
    gdt[i].granularity = (u8)((limit >> 16) & 0x0F) | (gran & 0xF0);
    gdt[i].access = access;
}

void gdt_init(void) {
    gdt_set(0, 0, 0, 0, 0);
    gdt_set(1, 0, 0xFFFFFFFFu, 0x9A, 0xC0); /* code, ring 0 */
    gdt_set(2, 0, 0xFFFFFFFFu, 0x92, 0xC0); /* data, ring 0 */
    gdt_ptr.limit = (u16)(sizeof(gdt) - 1);
    gdt_ptr.base = (u32)&gdt;
    gdt_flush();
}
