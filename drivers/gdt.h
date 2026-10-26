#ifndef NXTS_GDT_H
#define NXTS_GDT_H
/* Install nxtsOS's own GDT (null, code 0x08, data 0x10) and reload all
   segment registers. Must run before idt_init/sti: GRUB's GDT uses
   different selectors (code 0x10, data 0x18), and using 0x08/0x10 against
   GRUB's GDT triple-faults on the first interrupt (v0.1.0 QEMU bug). */
void gdt_init(void);
#endif
