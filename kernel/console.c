#include "common.h"
#include "../drivers/serial.h"

#define VGA_BASE ((volatile u16 *)0xB8000)
#define COLS 80
#define ROWS 25

static u16 cursor_row = 0, cursor_col = 0;
static u8 colour = 0x07; /* light grey on black */

static void update_cursor(void) {
    u16 pos = (u16)(cursor_row * COLS + cursor_col);
    outb(0x3D4, 0x0F); outb(0x3D5, (u8)(pos & 0xFF));
    outb(0x3D4, 0x0E); outb(0x3D5, (u8)((pos >> 8) & 0xFF));
}

static void scroll(void) {
    for (u16 r = 0; r < ROWS - 1; r++)
        for (u16 c = 0; c < COLS; c++)
            VGA_BASE[r * COLS + c] = VGA_BASE[(r + 1) * COLS + c];
    for (u16 c = 0; c < COLS; c++)
        VGA_BASE[(ROWS - 1) * COLS + c] = (u16)((u16)colour << 8 | ' ');
    cursor_row = ROWS - 1;
}

void console_init(void) {
    for (u16 i = 0; i < COLS * ROWS; i++)
        VGA_BASE[i] = (u16)((u16)colour << 8 | ' ');
    cursor_row = 0; cursor_col = 0;
    update_cursor();
}

void console_clear(void) { console_init(); }

void console_putchar(char ch) {
    serial_putchar(ch);
    if (ch == '\n') { cursor_col = 0; cursor_row++; }
    else if (ch == '\r') { cursor_col = 0; }
    else if (ch == '\b') {
        if (cursor_col > 0) {
            cursor_col--;
            VGA_BASE[cursor_row * COLS + cursor_col] = (u16)((u16)colour << 8 | ' ');
        }
    } else {
        VGA_BASE[cursor_row * COLS + cursor_col] = (u16)((u16)colour << 8 | (u8)ch);
        cursor_col++;
        if (cursor_col >= COLS) { cursor_col = 0; cursor_row++; }
    }
    if (cursor_row >= ROWS) scroll();
    update_cursor();
}

void console_write(const char *s) {
    while (*s) console_putchar(*s++);
}

/* Minimal printf: %s %d %u %x %c %% */
void console_printf(const char *fmt, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    char buf[32];
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') { console_putchar(*p); continue; }
        p++;
        if (*p == 's') console_write(__builtin_va_arg(ap, const char *));
        else if (*p == 'c') console_putchar((char)__builtin_va_arg(ap, int));
        else if (*p == 'd') {
            s32 v = __builtin_va_arg(ap, s32);
            if (v < 0) { console_putchar('-'); v = -v; }
            u32_to_str((u32)v, buf, 10); console_write(buf);
        } else if (*p == 'u') {
            u32_to_str(__builtin_va_arg(ap, u32), buf, 10); console_write(buf);
        } else if (*p == 'x') {
            u32_to_str(__builtin_va_arg(ap, u32), buf, 16); console_write(buf);
        } else if (*p == '%') console_putchar('%');
        else { console_putchar('%'); console_putchar(*p); }
    }
    __builtin_va_end(ap);
}
