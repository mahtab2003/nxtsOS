#ifndef NXTS_CONSOLE_H
#define NXTS_CONSOLE_H
#include "common.h"
void console_init(void);
void console_clear(void);
void console_putchar(char ch);
/* Panic path: once set, console_putchar skips the SMP spinlock,
   so a fault inside console output itself can still print
   instead of deadlocking. Set by panic() and by the exception
   handler before it prints. Never cleared. */
void console_set_panic_mode(void);
void console_write(const char *s);
void console_printf(const char *fmt, ...);
int  console_switch_to_fb(void);
void console_redraw_text(void);
/* While set, console output goes to serial + the text buffer only
   and never touches the framebuffer (desktop sessions: shell text
   must not scribble over the wallpaper). Cleared on desktop exit;
   panic() clears it too, so a panic is always visible. */
void console_set_fb_suppressed(int v);
/* Scrollback paging (PgUp/PgDn in the shell): one 25-line page per
   press, clamped. Framebuffer-text mode only; no-op in VGA mode. */
void console_scroll_up(void);
void console_scroll_down(void);
/* Full-screen editor APIs (kernel/editor.c): buffer-only, never
   serial. The editor owns the screen while it runs, so it must
   not use console_write/console_putchar (every call would spam
   the serial log with a full redraw per keystroke and corrupt
   the editor's own text_buf rows). */
void console_set_cursor(u32 row, u32 col); /* clamped to 25x80 */
u32 console_cursor_row(void); /* additive getters for the shell redraw path */
u32 console_cursor_col(void);
void console_put_at(u32 row, u32 col, char ch); /* text_buf only, no draw */
void console_present(void); /* render text_buf (fb unless suppressed, else VGA) */
u32  console_rows(void); /* 25 */
u32  console_cols(void); /* 80 */
/* Output capture (shell pipelines/redirection): while active,
   console_putchar buffers instead of printing to screen/serial,
   so redirected output never leaks into the serial log. The
   shell drains the buffer to the capture file. */
void console_capture_set_flush(void (*cb)(void));
void console_capture_begin(void);
u32  console_capture_take(char *out); /* copies buffered bytes, empties buffer */
void console_capture_end(void);
int  console_capture_truncated(void);
void console_capture_set_truncated(void);
/* Kernel log ring (Linux-comparability run, for `dmesg`): the last
   64 completed console lines (80 chars each, file-scope statics).
   Captured output (pipelines/redirection) is NOT logged, and
   dmesg's own printing is suppressed from the ring, so the log
   never logs itself. Lines longer than 80 chars are stored
   truncated at 80 (the screen width), never wrapped. */
void console_dmesg_print(u32 max_lines);
void console_dmesg_clear(void);
#endif
