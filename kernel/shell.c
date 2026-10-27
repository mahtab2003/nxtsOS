#include "common.h"
#include "console.h"
#include "shell.h"
#include "../mm/pmm.h"
#include "../drivers/pit.h"
#include "../drivers/keyboard.h"
#include "../fs/vfs.h"

static void cmd_mem(void) {
    console_printf("Memory: total %u frames (%u KiB), free %u frames (%u KiB), "
                   "used %u frames (%u KiB)\n",
                   pmm_total_frames(), pmm_total_frames() * 4,
                   pmm_free_frames(), pmm_free_frames() * 4,
                   pmm_used_frames(), pmm_used_frames() * 4);
}

/* Split line into at most 4 whitespace-separated tokens; tokens point
   into the line buffer and are NUL-terminated in place. Returns the
   token count. The remainder of the line after the second token (for
   the `write` command's text) is returned via *rest. */
static int tokenize(char *line, char *tok[], char **rest) {
    int n = 0;
    *rest = 0;
    char *p = line;
    while (*p && n < 4) {
        while (*p == ' ') p++;
        if (*p == 0) break;
        tok[n++] = p;
        while (*p && *p != ' ') p++;
        if (*p == ' ') {
            *p = 0; p++;
            if (n == 2) { /* after command + filename: rest is the text */
                while (*p == ' ') p++;
                *rest = p;
                break;
            }
        }
    }
    return n;
}

static void execute(char *line) {
    char *tok[4];
    char *rest = 0;
    int n = tokenize(line, tok, &rest);
    if (n == 0) return;
    if (strcmp(tok[0], "help") == 0) {
        console_write("Commands: help, mem, ticks, clear, reboot, fs, ls, cat <file>, write <file> <text>, rm <file>\n");
    } else if (strcmp(tok[0], "mem") == 0) {
        cmd_mem();
    } else if (strcmp(tok[0], "ticks") == 0) {
        console_printf("Timer ticks: %u (%u seconds at 100 Hz)\n",
                       timer_ticks, timer_ticks / 100);
    } else if (strcmp(tok[0], "clear") == 0) {
        console_clear();
    } else if (strcmp(tok[0], "reboot") == 0) {
        console_write("Rebooting...\n");
        outb(0x64, 0xFE);
        for (;;) __asm__ volatile ("hlt");
    } else if (strcmp(tok[0], "fs") == 0) {
        fs_status();
    } else if (strcmp(tok[0], "ls") == 0) {
        if (!fs_mounted()) { console_write("No filesystem mounted\n"); return; }
        fs_list();
    } else if (strcmp(tok[0], "cat") == 0) {
        if (n < 2) { console_write("Usage: cat <file>\n"); return; }
        u8 buf[1024];
        u32 size = 0;
        if (fs_read(tok[1], buf, sizeof(buf) - 1, &size) != 0) {
            console_printf("cat: cannot read %s\n", tok[1]);
            return;
        }
        buf[size] = 0;
        console_write((const char *)buf);
        console_write("\n");
    } else if (strcmp(tok[0], "write") == 0) {
        if (n < 2 || !rest || rest[0] == 0) {
            console_write("Usage: write <file> <text>\n"); return;
        }
        if (fs_write(tok[1], (const u8 *)rest, strlen(rest), 0, 0644) != 0) {
            console_printf("write: cannot write %s (invalid name, no space, or no filesystem)\n", tok[1]);
            return;
        }
        console_printf("Wrote %s\n", tok[1]);
    } else if (strcmp(tok[0], "rm") == 0) {
        if (n < 2) { console_write("Usage: rm <file>\n"); return; }
        if (fs_delete(tok[1]) != 0) {
            console_printf("rm: cannot delete %s\n", tok[1]);
            return;
        }
        console_printf("Deleted %s\n", tok[1]);
    } else {
        console_printf("Unknown command: %s (type help)\n", tok[0]);
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
