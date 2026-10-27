#include "pic.h"
#define PIC1_CMD 0x20
#define PIC1_DATA 0x21
#define PIC2_CMD 0xA0
#define PIC2_DATA 0xA1

void pic_init(void) {
    outb(PIC1_CMD, 0x11); io_wait();
    outb(PIC2_CMD, 0x11); io_wait();
    outb(PIC1_DATA, 0x20); io_wait(); /* IRQ 0-7  -> vectors 32-39 */
    outb(PIC2_DATA, 0x28); io_wait(); /* IRQ 8-15 -> vectors 40-47 */
    outb(PIC1_DATA, 0x04); io_wait();
    outb(PIC2_DATA, 0x02); io_wait();
    outb(PIC1_DATA, 0x01); io_wait();
    outb(PIC2_DATA, 0x01); io_wait();
    /* Unmask IRQ0 (timer) and IRQ1 (keyboard) on master, plus IRQ2
       (slave cascade, needed for IRQ12 mouse); unmask IRQ12 on slave,
       mask all other slave IRQs. */
    outb(PIC1_DATA, 0xF8);
    outb(PIC2_DATA, 0xEF);
}

void pic_send_eoi(u8 irq) {
    if (irq >= 8) outb(PIC2_CMD, 0x20);
    outb(PIC1_CMD, 0x20);
}
