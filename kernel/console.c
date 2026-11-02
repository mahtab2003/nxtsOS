#include "common.h"
#include "../drivers/serial.h"
#include "spinlock.h"
#include "smp.h"
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

/* Output capture (shell pipelines/redirection, parity run step 9):
   while cap_active, console_putchar buffers instead of printing
   to screen AND serial, so redirected output never leaks into
   the serial log (a redirected secret must not land in the log).
   The buffer is 4096 bytes; when it fills, the shell's flush
   callback (registered by the shell before begin) drains it to
   the capture file. The callback runs inside console_putchar,
   so cap_flushing discards any print attempted during a flush
   instead of recursing. All statics are file-scope, never on
   the 16 KiB kernel stack. */
#define CAP_BUF 4096
static char cap_buf[CAP_BUF];
static u32 cap_len = 0;
static int cap_active = 0, cap_flushing = 0, cap_trunc = 0;
static void (*cap_flush_cb)(void) = 0;

/* Forward: console_putchar/write are defined below; the dmesg
   printer needs them. */
void console_putchar(char ch);
void console_write(const char *s);
/* dmesg ring: completed lines only, oldest first on print. */
#define DMESG_LINES 64
static char dmesg_lines[DMESG_LINES][81];
static int dmesg_head = 0, dmesg_count = 0;
static char dmesg_cur[81];
static int dmesg_cur_len = 0;
static int dmesg_suppress = 0;
static void dmesg_push_line(void) {
    int slot = dmesg_head;
    int i = 0;
    while (i < dmesg_cur_len && i < 80) { dmesg_lines[slot][i] = dmesg_cur[i]; i++; }
    dmesg_lines[slot][i] = 0;
    dmesg_head = (dmesg_head + 1) % DMESG_LINES;
    if (dmesg_count < DMESG_LINES) dmesg_count++;
    dmesg_cur_len = 0;
}
void console_dmesg_print(u32 max_lines) {
    int n = dmesg_count;
    if (max_lines > 0 && (int)max_lines < n) n = (int)max_lines;
    int start = dmesg_head - dmesg_count + (dmesg_count - n);
    dmesg_suppress = 1;
    for (int k = 0; k < n; k++) {
        int slot = (start + k) % DMESG_LINES;
        if (slot < 0) slot += DMESG_LINES;
        console_write(dmesg_lines[slot]);
        console_putchar('\n');
    }
    dmesg_suppress = 0;
}
void console_dmesg_clear(void) {
    dmesg_head = 0; dmesg_count = 0; dmesg_cur_len = 0;
}

void console_capture_set_flush(void (*cb)(void)) { cap_flush_cb = cb; }
void console_capture_begin(void) { cap_len = 0; cap_active = 1; cap_trunc = 0; }
u32 console_capture_take(char *out) {
    u32 n = cap_len;
    for (u32 i = 0; i < n; i++) out[i] = cap_buf[i];
    cap_len = 0;
    return n;
}
void console_capture_end(void) { cap_active = 0; }
int console_capture_truncated(void) { return cap_trunc; }
void console_capture_set_truncated(void) { cap_trunc = 1; }

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

/* SMP (redesign 4): console output is shared state (cursor,
   text buffer, scrollback, dmesg ring), and two CPUs printing
   at once would interleave characters and corrupt the cursor.
   Every character goes through console_lock. The lock is
   owner-recursive: the capture-flush callback runs INSIDE
   console_putchar and may itself print (a filesystem warning
   while draining), and a plain spinlock would deadlock on that
   re-entry. The owner is the CPU index (smp_cpu_index); only
   the owning CPU can re-enter, and only it can release. Panic
   mode bypasses the lock entirely (see console_set_panic_mode):
   a fault inside console_putchar itself must still reach the
   screen instead of spinning on a lock its own CPU holds. */
static spinlock_t console_lock = SPINLOCK_INIT;
static int console_lock_owner = -1; /* -1 free, else CPU index */
static u32 console_lock_depth = 0;
static int console_panic_mode = 0;
void console_set_panic_mode(void) { console_panic_mode = 1; }

static void console_putchar_locked(char ch);

/* Line-level locking: console_write/console_printf hold the lock
   for their whole call, so one CPU's line can never interleave
   character-by-character with another CPU's line (seen in SMP
   testing: an AP "job finished" line garbled into a BSP "wait"
   line). console_putchar alone still locks per character — a
   user program's print syscall is a character stream, and only
   the shell's own line calls need atomicity. The token is the
   saved flags, except the two sentinels (never real EFLAGS):
   PANIC (no lock taken) and NESTED (same-CPU re-entry). */
#define CONSOLE_TOK_PANIC 0xFFFFFFFFu
#define CONSOLE_TOK_NESTED 0xFFFFFFFEu
static u32 console_line_begin(void) {
    if (console_panic_mode) return CONSOLE_TOK_PANIC;
    int cpu = smp_cpu_index();
    if (console_lock_owner == cpu) { console_lock_depth++; return CONSOLE_TOK_NESTED; }
    u32 f = spin_lock_irqsave(&console_lock);
    console_lock_owner = cpu;
    console_lock_depth = 1;
    return f;
}
static void console_line_end(u32 tok) {
    if (tok == CONSOLE_TOK_PANIC) return;
    if (tok == CONSOLE_TOK_NESTED) { console_lock_depth--; return; }
    console_lock_depth = 0;
    console_lock_owner = -1; /* released before the lock word: a
        spinner that sees the word free must see owner free too */
    spin_unlock_irqrestore(&console_lock, tok);
}

void console_putchar(char ch) {
    u32 tok = console_line_begin();
    console_putchar_locked(ch);
    console_line_end(tok);
}

static void console_putchar_locked(char ch) {
    /* Capture branch FIRST, before the serial mirror: while a
       pipeline stage or redirect is capturing, output goes to
       the capture buffer only — never to screen or serial. */
    if (cap_active) {
        if (cap_flushing) return; /* print during a flush: drop, never recurse */
        if (cap_len < CAP_BUF) { cap_buf[cap_len++] = ch; return; }
        if (cap_flush_cb) {
            cap_flushing = 1; cap_flush_cb(); cap_flushing = 0;
            if (cap_len < CAP_BUF) { cap_buf[cap_len++] = ch; return; }
        }
        cap_trunc = 1; /* full and undrainable: drop, warn at end */
        return;
    }
    serial_putchar(ch);
    /* dmesg ring: completed lines only, never captured output,
       never dmesg's own printing. */
    if (!dmesg_suppress) {
        if (ch == '\n') dmesg_push_line();
        else if (ch != '\r' && dmesg_cur_len < 80) dmesg_cur[dmesg_cur_len++] = ch;
    }
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
    u32 tok = console_line_begin();
    while (*s) console_putchar(*s++);
    console_line_end(tok);
}

void console_set_cursor(u32 row, u32 col) {
    if (row >= ROWS) row = ROWS - 1;
    if (col >= COLS) col = COLS - 1;
    cursor_row = (u16)row;
    cursor_col = (u16)col;
}
u32 console_cursor_row(void) { return cursor_row; }
u32 console_cursor_col(void) { return cursor_col; }
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
    u32 tok = console_line_begin();
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
    console_line_end(tok);
}
