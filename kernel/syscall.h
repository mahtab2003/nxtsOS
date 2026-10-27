#ifndef NXTS_SYSCALL_H
#define NXTS_SYSCALL_H
#include "common.h"
#include "../drivers/idt.h"
#define SYS_PRINT  1
#define SYS_YIELD  2
#define SYS_EXIT   3
#define SYS_GETPID 4
#define SYS_TICKS  5
#define SYS_GETUID 6
#define SYS_READ_FILE 7
#define SYS_WRITE_FILE 8
#define SYS_GUI_OPEN 9
#define SYS_GUI_RECT 10
#define SYS_GUI_TEXT 11
#define SYS_GUI_EVENT 12
#define SYS_GUI_CLOSE 13
void syscall_handler(struct regs *r);
#endif
