#include "idt.h"
#include "pic.h"
#include "pit.h"
#include "keyboard.h"
#include "../kernel/panic.h"
#include "../kernel/proc.h"

struct idt_entry {
    u16 base_lo, sel;
    u8  zero, flags;
    u16 base_hi;
} __attribute__((packed));
struct idt_ptr {
    u16 limit;
    u32 base;
} __attribute__((packed));

static struct idt_entry idt[256];
static struct idt_ptr idtp;

extern void isr0(void);  extern void isr1(void);  extern void isr2(void);
extern void isr3(void);  extern void isr4(void);  extern void isr5(void);
extern void isr6(void);  extern void isr7(void);  extern void isr8(void);
extern void isr9(void);  extern void isr10(void); extern void isr11(void);
extern void isr12(void); extern void isr13(void); extern void isr14(void);
extern void isr15(void); extern void isr16(void); extern void isr17(void);
extern void isr18(void); extern void isr19(void); extern void isr20(void);
extern void isr21(void); extern void isr22(void); extern void isr23(void);
extern void isr24(void); extern void isr25(void); extern void isr26(void);
extern void isr27(void); extern void isr28(void); extern void isr29(void);
extern void isr30(void); extern void isr31(void);
extern void irq0(void);  extern void irq1(void);  extern void irq2(void);
extern void irq3(void);  extern void irq4(void);  extern void irq5(void);
extern void irq6(void);  extern void irq7(void);  extern void irq8(void);
extern void irq9(void);  extern void irq10(void); extern void irq11(void);
extern void irq12(void); extern void irq13(void); extern void irq14(void);
extern void irq15(void);
extern void syscall_stub(void);

static void idt_set_gate(u8 num, u32 base, u16 sel, u8 flags) {
    idt[num].base_lo = (u16)(base & 0xFFFF);
    idt[num].base_hi = (u16)((base >> 16) & 0xFFFF);
    idt[num].sel = sel;
    idt[num].zero = 0;
    idt[num].flags = flags;
}

void idt_init(void) {
    idtp.limit = (u16)(sizeof(idt) - 1);
    idtp.base = (u32)&idt;
    memset(&idt, 0, sizeof(idt));
    void (*isrs[32])(void) = { isr0, isr1, isr2, isr3, isr4, isr5, isr6, isr7,
        isr8, isr9, isr10, isr11, isr12, isr13, isr14, isr15, isr16, isr17,
        isr18, isr19, isr20, isr21, isr22, isr23, isr24, isr25, isr26, isr27,
        isr28, isr29, isr30, isr31 };
    void (*irqs[16])(void) = { irq0, irq1, irq2, irq3, irq4, irq5, irq6, irq7,
        irq8, irq9, irq10, irq11, irq12, irq13, irq14, irq15 };
    for (int i = 0; i < 32; i++) idt_set_gate((u8)i, (u32)isrs[i], 0x08, 0x8E);
    for (int i = 0; i < 16; i++) idt_set_gate((u8)(32 + i), (u32)irqs[i], 0x08, 0x8E);
    /* Syscall gate, DPL 3 so user mode can call int 0x80. */
    idt_set_gate(0x80, (u32)syscall_stub, 0x08, 0xEE);
    __asm__ volatile ("lidt %0" : : "m"(idtp));
}

void isr_handler(struct regs *r) {
    if (r->int_no < 32) {
        console_printf("\nEXCEPTION %u err=0x%x eip=0x%x\n",
                       r->int_no, r->err_code, r->eip);
        if (r->int_no == 14) {
            u32 cr2;
            __asm__ volatile ("mov %%cr2, %0" : "=r"(cr2));
            console_printf("PAGE FAULT at 0x%x\n", cr2);
        }
        panic("unhandled CPU exception");
    }
}

void irq_handler(struct regs *r) {
    if (r->int_no == 0) {
        timer_tick();
        pic_send_eoi(0);
        /* EOI first, then preempt: the switch abandons this IRQ frame,
           so the PIC must already be told the IRQ is done. */
        timer_maybe_preempt(r);
    } else if (r->int_no == 1) {
        keyboard_irq_handler();
        pic_send_eoi(1);
    } else {
        pic_send_eoi((u8)r->int_no);
    }
}
