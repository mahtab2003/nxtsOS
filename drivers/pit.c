#include "pit.h"
volatile u32 timer_ticks = 0;

void pit_init(void) {
    u32 divisor = 1193180 / 100; /* 100 Hz */
    outb(0x43, 0x36);
    outb(0x40, (u8)(divisor & 0xFF));
    outb(0x40, (u8)((divisor >> 8) & 0xFF));
}

void timer_tick(void) { timer_ticks++; }
