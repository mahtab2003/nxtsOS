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
#endif
