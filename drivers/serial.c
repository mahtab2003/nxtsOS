#include "serial.h"
#define COM1 0x3F8

void serial_init(void) {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x03); /* divisor 3 -> 38400 baud */
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03); /* 8 bits, no parity, 1 stop bit */
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

void serial_putchar(char ch) {
    while ((inb(COM1 + 5) & 0x20) == 0) { }
    outb(COM1, (u8)ch);
}

void serial_write(const char *s) { while (*s) serial_putchar(*s++); }
