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
/* Background jobs (v0.4.1): an ELF started with runbg stays READY and is
   resumed from the shell's idle loop, so the prompt returns immediately
   and the program runs concurrently with shell input. */
#define MAX_BG 4
int  proc_bg_start(const char *name, u32 uid); /* 0 ok, -1 fail; prints start */
void proc_bg_tick(void);   /* run each READY job once (yield/preempt returns) */
int  proc_bg_list(void);   /* prints jobs, returns count */
int  proc_bg_kill(u32 pid, u32 uid); /* 0 ok, -1 no such job / no permission */
int  proc_bg_kill_for_uid(u32 uid);  /* logout cleanup, returns count killed */
int  proc_bg_count(void);
int  proc_bg_exists(u32 pid); /* 1 if a background job with this pid is still alive */
void proc_save_from_regs(struct proc *p, struct regs *r);
void scheduler_run(void);
void timer_maybe_preempt(struct regs *r);
void sched_switch_asm(void);
void switch_to_user_asm(void);

#endif
