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
static int fb_suppressed = 0; /* desktop active: no fb console draws */
/* Scrollback (Work D list view): lines that scrolled off the 25-row
   screen are kept in a 100-line ring (8,000 B, file-scope static —
   never on the 16 KiB kernel stack). sb_view counts how many lines
   back from live the screen currently shows; 0 = live. */
#define SB_LINES 100
static char sb_lines[SB_LINES][COLS];
static int sb_head = 0; /* next ring slot to write */
static int sb_count = 0; /* lines stored, <= SB_LINES */
static int sb_view = 0; /* lines back from live, 0 = live */

void console_set_fb_suppressed(int v) { fb_suppressed = v ? 1 : 0; }

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
    /* Text console in graphics mode is also a scene: present it
       whole, so the shell never shows a half-rendered screen. */
    fb_present();
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
   if the system is in VGA mode, this is a no-op redraw. Always
   shows live (a history view does not survive a scene switch). */
void console_redraw_text(void) {
    sb_view = 0;
    if (fb_mode) render_fb();
    else render_vga();
}

void console_clear(void) {
    for (u16 r = 0; r < ROWS; r++)
        for (u16 c = 0; c < COLS; c++) text_buf[r][c] = ' ';
    cursor_row = 0; cursor_col = 0;
    /* View returns to live; the ring itself survives a clear, as in
       a real terminal (scrollback is history, not screen). */
    sb_view = 0;
    console_redraw_text();
}

static void scroll(void) {
    /* Save the line scrolling off into the scrollback ring first. */
    for (int c = 0; c < COLS; c++) sb_lines[sb_head][c] = text_buf[0][c];
    sb_head = (sb_head + 1) % SB_LINES;
    if (sb_count < SB_LINES) sb_count++;
    for (u16 r = 0; r < ROWS - 1; r++)
        for (u16 c = 0; c < COLS; c++) text_buf[r][c] = text_buf[r + 1][c];
    for (u16 c = 0; c < COLS; c++) text_buf[ROWS - 1][c] = ' ';
    cursor_row = ROWS - 1;
}

/* Draw the current view window: the 25 rows ending sb_view lines
   back from live. Ring lines come first (oldest), then the live
   screen rows. The cursor is drawn only in live view — it belongs
   to the live prompt, not to history. */
static void render_view(void) {
    if (!fb_ready()) return;
    fb_clear(0x000000);
    int total = sb_count + ROWS;
    int top = total - ROWS - sb_view;
    for (int r = 0; r < ROWS; r++) {
        int li = top + r;
        const char *line;
        if (li < sb_count) {
            int idx = sb_head - sb_count + li;
            if (idx < 0) idx += SB_LINES;
            line = sb_lines[idx];
        } else {
            line = text_buf[li - sb_count];
        }
        for (int c = 0; c < COLS; c++)
            fb_draw_char((s32)c * 8, (s32)r * 16, line[c], 0x00FFFFFF, 0x00000000);
    }
    if (sb_view == 0 && cursor_row < ROWS && cursor_col < COLS) {
        char ch = text_buf[cursor_row][cursor_col];
        fb_draw_char((s32)cursor_col * 8, (s32)cursor_row * 16, ch, 0x00000000, 0x00FFFFFF);
    }
    fb_present();
}

/* PgUp: one 25-line page older, clamped to the ring. PgDn: one page
   newer, clamped to live. Framebuffer-text mode only: VGA text has
   no back buffer to render history into. */
void console_scroll_up(void) {
    if (!fb_mode || fb_suppressed) return;
    if (sb_view < sb_count) {
        sb_view += ROWS;
        if (sb_view > sb_count) sb_view = sb_count;
        render_view();
    }
}
void console_scroll_down(void) {
    if (!fb_mode || fb_suppressed) return;
    if (sb_view > 0) {
        sb_view -= ROWS;
        if (sb_view < 0) sb_view = 0;
        render_view();
    }
}

void console_putchar(char ch) {
    serial_putchar(ch);
    /* Any new output returns the view to live: history viewing ends
       the moment something prints. A full repaint follows below, so
       the stale history window cannot linger under new output. */
    int was_viewing = (sb_view != 0);
    if (was_viewing) sb_view = 0;
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
    if (fb_mode && !fb_suppressed) {
        if (scrolled || was_viewing) { render_fb(); return; }
        /* Erase the old cursor cell (normal colours), then draw the
           new cursor cell inverted. Only two glyphs per character,
           so a busy log stays fast. */
        if (old_row < ROWS && old_col < COLS)
            fb_draw_char((s32)old_col * 8, (s32)old_row * 16, text_buf[old_row][old_col], 0x00FFFFFF, 0x00000000);
        if (cursor_row < ROWS && cursor_col < COLS)
            fb_draw_char((s32)cursor_col * 8, (s32)cursor_row * 16, text_buf[cursor_row][cursor_col], 0x00000000, 0x00FFFFFF);
        /* Back-buffered mode: the two cells above land in the
           shadow buffer only. Present them, or typed input and
           the cursor never reach the screen (v1.1.0 real-device
           bug: shell echo invisible in framebuffer text mode —
           the pre-compositor direct-draw code needed no present,
           this fast path was never updated for the back buffer).
           No-op in direct mode (no back buffer). */
        if (old_row < ROWS && old_col < COLS)
            fb_present_rect((s32)old_col * 8, (s32)old_row * 16, 8, 16);
        if (cursor_row < ROWS && cursor_col < COLS)
            fb_present_rect((s32)cursor_col * 8, (s32)cursor_row * 16, 8, 16);
    } else {
        render_vga();
    }
}

void console_write(const char *s) {
    while (*s) console_putchar(*s++);
}

void console_set_cursor(u32 row, u32 col) {
    if (row >= ROWS) row = ROWS - 1;
    if (col >= COLS) col = COLS - 1;
    cursor_row = (u16)row;
    cursor_col = (u16)col;
}
void console_put_at(u32 row, u32 col, char ch) {
    if (row >= ROWS || col >= COLS) return;
    text_buf[row][col] = ch;
}
void console_present(void) {
    if (fb_mode) {
        if (!fb_suppressed) render_fb();
    } else {
        render_vga();
    }
}
u32 console_rows(void) { return ROWS; }
u32 console_cols(void) { return COLS; }

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
