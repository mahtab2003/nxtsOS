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
/* Deep-core phase D2: file descriptors, pipes, brk, flock. */
#define SYS_OPEN  14
#define SYS_READ  15
#define SYS_WRITE 16
#define SYS_CLOSE 17
#define SYS_LSEEK 18
#define SYS_PIPE  19
#define SYS_BRK   20
#define SYS_FLOCK 21
/* Redesign 5 demand-paging syscall (NEW number; 14-28 unchanged).
   ebx = page-aligned address, ecx = page count (1..16),
   edx = flags (bit 0 = swappable intent only). */
#define SYS_VMA_ADD 29
/* §15.2 socket syscalls (NEW numbers; 14-21 unchanged). */
#define SYS_SOCKET 22
#define SYS_BIND 23
#define SYS_LISTEN 24
#define SYS_ACCEPT 25
#define SYS_CONNECT 26
#define SYS_SENDTO 27
#define SYS_RECVFROM 28
void syscall_handler(struct regs *r);
#endif
