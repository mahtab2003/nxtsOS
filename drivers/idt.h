#ifndef NXTS_IDT_H
#define NXTS_IDT_H
#include "../kernel/common.h"
struct regs {
    u32 ds, edi, esi, ebp, esp, ebx, edx, ecx, eax;
    u32 int_no, err_code;
    u32 eip, cs, eflags, useresp, ss;
};
void idt_init(void);
void isr_handler(struct regs *r);
void irq_handler(struct regs *r);
#endif
