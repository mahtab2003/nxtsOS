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
#endif
