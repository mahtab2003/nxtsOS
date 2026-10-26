#include "common.h"
#include "../drivers/serial.h"
#include "fb.h"

#define VGA_BASE ((volatile u16 *)0xB8000)
#define COLS 80
#define ROWS 25

static u16 cursor_row = 0, cursor_col = 0;
static u8 colour = 0x07; /* light grey on black */
static char text_buf[ROWS][COLS];
static int fb_mode = 0; /* 0 = VGA text, 1 = framebuffer text */

static void update_cursor(void) {
    if (fb_mode) return; /* framebuffer cursor is drawn by redraw() */
    u16 pos = (u16)(cursor_row * COLS + cursor_col);
    outb(0x3D4, 0x0F); outb(0x3D5, (u8)(pos & 0xFF));
    outb(0x3D4, 0x0E); outb(0x3D5, (u8)((pos >> 8) & 0xFF));
}

static void render_vga(void) {
    for (u16 r = 0; r < ROWS; r++)
        for (u16 c = 0; c < COLS; c++)
            VGA_BASE[r * COLS + c] = (u16)((u16)colour << 8 | (u8)text_buf[r][c]);
    update_cursor();
}

static void render_fb(void) {
    if (!fb_ready()) return;
    fb_clear(0x000000);
    for (u16 r = 0; r < ROWS; r++)
        for (u16 c = 0; c < COLS; c++)
            fb_draw_char((s32)c * 8, (s32)r * 16, text_buf[r][c], 0x00FFFFFF, 0x00000000);
    /* Cursor: invert the character cell under the cursor. */
    if (cursor_row < ROWS && cursor_col < COLS) {
        char ch = text_buf[cursor_row][cursor_col];
        fb_draw_char((s32)cursor_col * 8, (s32)cursor_row * 16, ch, 0x00000000, 0x00FFFFFF);
    }
}

void console_init(void) {
    for (u16 r = 0; r < ROWS; r++)
        for (u16 c = 0; c < COLS; c++) text_buf[r][c] = ' ';
    cursor_row = 0; cursor_col = 0; fb_mode = 0;
    render_vga();
}

/* Switch the visible console to the framebuffer, redrawing the
   buffered text. Called after fb_init, so early boot logs (buffered
   in RAM, and sent to serial all along) appear on screen in
   graphics mode too. Returns 0 if switched, -1 if no framebuffer. */
int console_switch_to_fb(void) {
    if (!fb_ready()) return -1;
    fb_mode = 1;
    render_fb();
    return 0;
}

/* Switch back to the buffered text console after a GUI session.
   If fb_mode was on, redraw the text buffer to the framebuffer;
   if the system is in VGA mode, this is a no-op redraw. */
void console_redraw_text(void) {
    if (fb_mode) render_fb();
    else render_vga();
}

void console_clear(void) {
    for (u16 r = 0; r < ROWS; r++)
        for (u16 c = 0; c < COLS; c++) text_buf[r][c] = ' ';
    cursor_row = 0; cursor_col = 0;
    console_redraw_text();
}

static void scroll(void) {
    for (u16 r = 0; r < ROWS - 1; r++)
        for (u16 c = 0; c < COLS; c++) text_buf[r][c] = text_buf[r + 1][c];
    for (u16 c = 0; c < COLS; c++) text_buf[ROWS - 1][c] = ' ';
    cursor_row = ROWS - 1;
}

void console_putchar(char ch) {
    serial_putchar(ch);
    u16 old_row = cursor_row, old_col = cursor_col;
    if (ch == '\n') { cursor_col = 0; cursor_row++; }
    else if (ch == '\r') { cursor_col = 0; }
    else if (ch == '\b') {
        if (cursor_col > 0) { cursor_col--; text_buf[cursor_row][cursor_col] = ' '; }
    } else {
        text_buf[cursor_row][cursor_col] = ch;
        cursor_col++;
        if (cursor_col >= COLS) { cursor_col = 0; cursor_row++; }
    }
    int scrolled = 0;
    if (cursor_row >= ROWS) { scroll(); scrolled = 1; }
    if (fb_mode) {
        if (scrolled) { render_fb(); return; }
        /* Erase the old cursor cell (normal colours), then draw the
           new cursor cell inverted. Only two glyphs per character,
           so a busy log stays fast. */
        if (old_row < ROWS && old_col < COLS)
            fb_draw_char((s32)old_col * 8, (s32)old_row * 16, text_buf[old_row][old_col], 0x00FFFFFF, 0x00000000);
        if (cursor_row < ROWS && cursor_col < COLS)
            fb_draw_char((s32)cursor_col * 8, (s32)cursor_row * 16, text_buf[cursor_row][cursor_col], 0x00000000, 0x00FFFFFF);
    } else {
        render_vga();
    }
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
