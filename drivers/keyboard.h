#ifndef NXTS_KEYBOARD_H
#define NXTS_KEYBOARD_H
#include "../kernel/common.h"
void keyboard_init(void);
void keyboard_irq_handler(void);
int  keyboard_getchar(void); /* -1 if no key waiting */
void keyboard_flush(void); /* discard buffered keys (login/lock/logout) */
#endif
