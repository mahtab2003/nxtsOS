#include "common.h"
#include "console.h"
#include "shell.h"
#include "../mm/pmm.h"
#include "../drivers/pit.h"
#include "../drivers/keyboard.h"

static void cmd_mem(void) {
    console_printf("Memory: total %u frames (%u KiB), free %u frames (%u KiB), "
                   "used %u frames (%u KiB)\n",
                   pmm_total_frames(), pmm_total_frames() * 4,
                   pmm_free_frames(), pmm_free_frames() * 4,
                   pmm_used_frames(), pmm_used_frames() * 4);
}

static void execute(char *line) {
    if (line[0] == 0) return;
    if (strcmp(line, "help") == 0) {
        console_write("Commands: help, mem, ticks, clear, reboot\n");
    } else if (strcmp(line, "mem") == 0) {
        cmd_mem();
    } else if (strcmp(line, "ticks") == 0) {
        console_printf("Timer ticks: %u (%u seconds at 100 Hz)\n",
                       timer_ticks, timer_ticks / 100);
    } else if (strcmp(line, "clear") == 0) {
        console_clear();
    } else if (strcmp(line, "reboot") == 0) {
        console_write("Rebooting...\n");
        outb(0x64, 0xFE);
        for (;;) __asm__ volatile ("hlt");
    } else {
        console_printf("Unknown command: %s (type help)\n", line);
    }
}

void shell_run(void) {
    char line[128];
    u32 len = 0;
    console_write("\nWelcome to nxtsOS. Type help.\n");
    console_write("nxts> ");
    for (;;) {
        int c = keyboard_getchar();
        if (c < 0) { __asm__ volatile ("hlt"); continue; }
        if (c == '\n') {
            line[len] = 0;
            console_putchar('\n');
            execute(line);
            len = 0;
            console_write("nxts> ");
        } else if (c == '\b') {
            if (len > 0) { len--; console_putchar('\b'); }
        } else if (len < sizeof(line) - 1) {
            line[len++] = (char)c;
            console_putchar((char)c);
        }
    }
}
