#ifndef NXTS_KEYBOARD_H
#define NXTS_KEYBOARD_H
#include "../kernel/common.h"
void keyboard_init(void);
void keyboard_irq_handler(void);
/* Returns -1 if no key waiting, 0..255 for an ASCII/control char,
   or a KEY_* special code for a delivered extended key (PgUp/PgDn,
   arrows, Home/End, Delete). Ctrl tracking: either Ctrl key sets
   a flag; a letter typed with Ctrl down is delivered as its
   control code (a->1 ... z->26), so the editor sees ^O=15,
   ^X=24, ^W=23, ^K=11, ^U=21, ^G=7. */
int  keyboard_getchar(void);
#define KEY_PGUP 0x101
#define KEY_PGDN 0x102
#define KEY_UP   0x103
#define KEY_DOWN 0x104
#define KEY_LEFT 0x105
#define KEY_RIGHT 0x106
#define KEY_HOME 0x107
#define KEY_END  0x108
#define KEY_DEL  0x109
void keyboard_inject_char(char c); /* test-only: push an ASCII char into the buffer */
void keyboard_flush(void); /* discard buffered keys (login/lock/logout) */
void keyboard_poll(void); /* pick up a pending byte without an IRQ */
u32  keyboard_init_drained(void); /* bytes drained at startup (v0.7.3) */
u32  keyboard_startup_drained(void); /* init + post-mouse drain */
u32  keyboard_drain_controller(void); /* drain now, return count */
u8   keyboard_controller_status(void);
u8   keyboard_last_scancode(void);
#endif
