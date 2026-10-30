#ifndef NXTS_CONSOLE_H
#define NXTS_CONSOLE_H
#include "common.h"
void console_init(void);
void console_clear(void);
void console_putchar(char ch);
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
void console_put_at(u32 row, u32 col, char ch); /* text_buf only, no draw */
void console_present(void); /* render text_buf (fb unless suppressed, else VGA) */
u32  console_rows(void); /* 25 */
u32  console_cols(void); /* 80 */
#endif
