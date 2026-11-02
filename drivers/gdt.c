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

static struct gdt_entry gdt[7];
struct gdt_ptr gdt_ptr;
static struct tss_entry tss;
/* SMP (redesign 4): the AP needs its own TSS, because a ring-3 ->
   ring-0 transition loads SS:ESP from the CURRENT task register's
   TSS — with one TSS, the BSP and AP would overwrite each
   other's esp0 on every switch and syscalls would land on the
   wrong kernel stack. Entry 6 -> selector 0x30, loaded by the
   AP in ap_main (ltr). */
static struct tss_entry tss_ap;
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
void tss_set_esp0_ap(u32 esp0) { tss_ap.esp0 = esp0; }

void gdt_ptr_values(u16 *limit_out, u32 *base_out) {
    if (limit_out) *limit_out = gdt_ptr.limit;
    if (base_out) *base_out = gdt_ptr.base;
}

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
    memset(&tss_ap, 0, sizeof(tss_ap));
    tss_ap.ss0 = 0x10;
    tss_ap.iomap_base = sizeof(tss_ap);
    gdt_set(6, (u32)&tss_ap, sizeof(tss_ap) - 1, 0x89, 0x00); /* AP TSS -> 0x30 */
    gdt_ptr.limit = (u16)(sizeof(gdt) - 1);
    gdt_ptr.base = (u32)&gdt;
    gdt_flush();
}
