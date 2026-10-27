#ifndef NXTS_SERIAL_H
#define NXTS_SERIAL_H
#include "../kernel/common.h"
void serial_init(void);
void serial_putchar(char ch);
void serial_write(const char *s);
#endif
