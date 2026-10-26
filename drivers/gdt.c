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
struct tss_entry {
    u32 prev_tss, esp0, ss0, esp1, ss1, esp2, ss2, cr3, eip, eflags;
    u32 eax, ecx, edx, ebx, esp, ebp, esi, edi;
    u32 es, cs, ss, ds, fs, gs, ldt, trap, iomap_base;
} __attribute__((packed));

static struct gdt_entry gdt[6];
struct gdt_ptr gdt_ptr;
static struct tss_entry tss;
extern void gdt_flush(void);

static void gdt_set(int i, u32 base, u32 limit, u8 access, u8 gran) {
    gdt[i].base_lo = (u16)(base & 0xFFFF);
    gdt[i].base_mid = (u8)((base >> 16) & 0xFF);
    gdt[i].base_hi = (u8)((base >> 24) & 0xFF);
    gdt[i].limit_lo = (u16)(limit & 0xFFFF);
    gdt[i].granularity = (u8)((limit >> 16) & 0x0F) | (gran & 0xF0);
    gdt[i].access = access;
}

void tss_set_esp0(u32 esp0) { tss.esp0 = esp0; }

void gdt_init(void) {
    gdt_set(0, 0, 0, 0, 0);
    gdt_set(1, 0, 0xFFFFFFFFu, 0x9A, 0xC0); /* kernel code, ring 0 -> 0x08 */
    gdt_set(2, 0, 0xFFFFFFFFu, 0x92, 0xC0); /* kernel data, ring 0 -> 0x10 */
    gdt_set(3, 0, 0xFFFFFFFFu, 0xFA, 0xC0); /* user code, ring 3 -> 0x18 (0x1B) */
    gdt_set(4, 0, 0xFFFFFFFFu, 0xF2, 0xC0); /* user data, ring 3 -> 0x20 (0x23) */
    memset(&tss, 0, sizeof(tss));
    tss.ss0 = 0x10;
    tss.iomap_base = sizeof(tss);
    gdt_set(5, (u32)&tss, sizeof(tss) - 1, 0x89, 0x00); /* TSS -> 0x28 */
    gdt_ptr.limit = (u16)(sizeof(gdt) - 1);
    gdt_ptr.base = (u32)&gdt;
    gdt_flush();
}
