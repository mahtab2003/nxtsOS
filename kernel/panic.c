#include "common.h"
#include "panic.h"
#include "console.h"

void panic(const char *msg) {
    /* A panic during a desktop session must still reach the screen:
       the desktop suppresses framebuffer console output (Bug C fix),
       so clear the suppression and repaint the text console first. */
    console_set_fb_suppressed(0);
    console_redraw_text();
    console_printf("\nKERNEL PANIC: %s\nSystem halted.\n", msg);
    __asm__ volatile ("cli");
    for (;;) __asm__ volatile ("hlt");
}
