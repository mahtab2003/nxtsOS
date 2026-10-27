#ifndef NXTS_PROC_H
#define NXTS_PROC_H
#include "common.h"
#include "../drivers/idt.h"

#define PROC_READY   0
#define PROC_RUNNING 1
#define PROC_EXITED  2
#define MAX_PROCS    4

struct proc {
    u32 pid;
    u32 uid;
    int state;
    u32 pd;
    u32 kernel_stack_top;
    u32 code_pages;
    u32 eip, esp, eflags;
    u32 edi, esi, ebp, ebx, edx, ecx, eax;
};

extern struct proc *current_proc;
extern struct proc procs[MAX_PROCS];
extern int proc_count;

void proc_init(void);
int  proc_exec_file(const char *name, u32 uid); /* run an ELF to completion */
void proc_save_from_regs(struct proc *p, struct regs *r);
void scheduler_run(void);
void timer_maybe_preempt(struct regs *r);
void sched_switch_asm(void);
void switch_to_user_asm(void);

#endif
