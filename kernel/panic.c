#include "common.h"
#include "panic.h"

void panic(const char *msg) {
    console_printf("\nKERNEL PANIC: %s\nSystem halted.\n", msg);
    __asm__ volatile ("cli");
    for (;;) __asm__ volatile ("hlt");
}
