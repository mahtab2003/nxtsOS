#ifndef NXTS_GDT_H
#define NXTS_GDT_H
#include "../kernel/common.h"
/* Install nxtsOS's own GDT and reload all segment registers, plus load
   the TSS (selector 0x28) so ring-3 -> ring-0 transitions switch to a
   kernel stack. Must run before idt_init/sti: GRUB's GDT uses different
   selectors (code 0x10, data 0x18), and using 0x08/0x10 against GRUB's
   GDT triple-faults on the first interrupt (v0.1.0 QEMU bug).
   Layout: 0x08 kernel code, 0x10 kernel data, 0x18 user code,
   0x20 user data, 0x28 TSS. */
void gdt_init(void);
void tss_set_esp0(u32 esp0);
#endif
