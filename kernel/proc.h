#ifndef NXTS_PROC_H
#define NXTS_PROC_H
#include "common.h"
#include "../drivers/idt.h"

#define PROC_READY   0
#define PROC_RUNNING 1
#define PROC_EXITED  2
#define PROC_STOPPED 3 /* background job stopped by SIGSTOP; tick skips it */
#define PROC_BLOCKED 4 /* waiting on a pipe/FIFO/lock; tick skips it,
                          the pending op below is retried on wakeup */

#define MAX_PROCS    4

/* Deep-core phase D2: per-process file descriptors. 16 per
   proc, in the proc struct (zeroed by elf_create_proc's
   memset, freed by fd_close_all at every teardown site). */
#define PROC_MAX_FD 16
#define PFD_FILE 0
#define PFD_PIPE 1
#define PFD_SOCK 2 /* §15.2: socket-table index in `sock` */
struct proc_fd {
    int used;
    int kind; /* PFD_FILE, PFD_PIPE, or PFD_SOCK */
    char name[32]; /* file name (file fds) or FIFO name (pipe fds) */
    u32 offset; /* file fds */
    u32 flags; /* open flags (low 2 bits = access mode) */
    void *ring; /* pipe fds: kernel/pipe ring */
    u32 pipe_end; /* pipe fds: 0 read, 1 write */
    int lock; /* flock held via this fd: 0 none, 1 SH, 2 EX */
    int sock; /* socket fds: socket-table index, else -1 */
};

/* Deep-core phase D2: a blocked syscall, retried by the tick /
   exec loop before user code resumes (see docs §14.12). */
#define PEND_NONE 0
#define PEND_READ 1
#define PEND_WRITE 2
#define PEND_OPEN_FIFO 3
#define PEND_FLOCK 4
struct proc_pend {
    int op;
    int fd;
    u32 buf; /* user buffer address */
    u32 len;
    u32 flags; /* open flags / flock op */
    char name[32];
    void *ring;
};

/* Redesign 5 (CORE_CLI.md section 15.4): one demand-paging
   VMA (see mm/vma.h). Flags: bit 0 = swappable (intent
   only — no swap area exists, so nothing is ever paged
   out). The list lives in the proc struct (never on a
   stack) and is zeroed by elf_create_proc's memset. */
#define PROC_MAX_VMA 8
#define VMA_SWAPPABLE 1
struct proc_vma {
    u32 start;
    u32 pages;
    u32 flags;
    int used;
};

struct proc {
    u32 pid;
    u32 uid;
    int state;
    u32 pd;
    u32 kernel_stack_top;
    u32 code_pages;
    u32 eip, esp, eflags;
    u32 edi, esi, ebp, ebx, edx, ecx, eax;
    /* Redesign 5: capability mask inherited from the session
       at spawn (kernel/caps.h), and demand-paging state. */
    u32 caps;
    struct proc_vma vmas[PROC_MAX_VMA];
    u32 vma_faults;
    u32 vma_pages;
    /* Deep-core phase: SYS_EXIT code (ebx & 0xFF, see syscall.c).
       Zeroed by elf_create_proc's memset; boot blob procs never
       report it. */
    u32 exit_code;
    /* Deep-core phase D2: fds, pending blocked op, brk heap. */
    struct proc_fd fds[PROC_MAX_FD];
    struct proc_pend pend;
    u32 heap_base; /* 0 until first brk */
    u32 heap_end;
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
/* Deep-core phase: exit-status reap table. When a background job
   exits, proc_bg_tick copies pid/name/uid/code here (4 entries,
   oldest overwritten) and frees the job slot at once, so jobs,
   counts, and iterators are unchanged. wait/fg consume an entry
   (each code reported exactly once). 0 ok, -1 none/permission. */
int  proc_reap_take(u32 pid, u32 uid, u32 *code_out);
/* Deep-core phase: minimal signals for background jobs only
   (foreground delivery has no sender while the shell is blocked
   in proc_exec_file — see docs/CORE_CLI.md §14.10 item 3).
   Signals: 1 HUP, 2 INT, 9 KILL, 15 TERM, 18 CONT, 19 STOP.
   Delivery happens at the next proc_bg_tick boundary: TERM/
   HUP/INT/KILL remove the job, STOP parks it (PROC_STOPPED),
   CONT resumes it. 0 ok, -1 no job/permission, -2 bad signal. */
int  proc_bg_signal(u32 pid, u32 uid, int sig);
/* Deep-core phase D2: live-proc registry for pipe/lock wakeup
   scans (boot procs + bg jobs + the foreground exec proc).
   Returns the count; out holds up to max pointers. */
int  proc_live_list(struct proc **out, int max);
/* Linux-comparability run: job priorities (nice -20..19, default 0).
   Negative nice (higher priority) runs a job twice per tick; positive
   nice runs it less often (10..19: every 2nd tick). The field is
   part of the job table, never on the kernel stack. */
int  proc_bg_start_nice(const char *name, u32 uid, int nice);
int  proc_bg_set_nice(u32 pid, u32 uid, int nice); /* 0 ok, -1 no job/permission, -2 negative nice needs root */
int  proc_bg_get_nice(u32 pid, int *nice_out, u32 *runs_out);
int  proc_bg_info(int n, char *name_out, u32 *pid_out, u32 *uid_out, int *nice_out, u32 *runs_out);
/* nth used job in slot order (0 ok, -1 none): the Monitor window's
   jobs list reads through this, so the desktop and shell `jobs`
   show the same table; name_out holds 31 chars + NUL. */
int  proc_bg_at(int n, char *name_out, u32 *pid_out, u32 *uid_out);
void proc_save_from_regs(struct proc *p, struct regs *r);
void scheduler_run(void);
void timer_maybe_preempt(struct regs *r);
void sched_switch_asm(void);
void switch_to_user_asm(void);
/* SMP (redesign 4): per-CPU scheduler state for the AP. The AP
   runs user jobs through its own switch globals (switch.S),
   its own current_proc, and its own preemption quantum — the
   BSP's globals are never touched from the AP. */
void switch_to_user_asm_ap(void);
void sched_switch_asm_ap(void);
struct proc *proc_current_for_cpu(void); /* syscall context: BSP or AP proc */
void sched_switch_current(void); /* sched_switch_asm or _ap, by CPU */
void ap_sched_tick(void); /* AP loop: deliver signals + run cpu==1 jobs */
void ap_timer_tick(struct regs *r); /* LAPIC timer on AP: count + preempt */
void timer_maybe_preempt_ap(struct regs *r);
void proc_ap_stats(u32 *runs_out, u32 *done_out);
/* CPU affinity (a job field, redesign 4): 0 = BSP, 1 = AP.
   New jobs start on CPU 0. A move requested while the job is
   RUNNING is pended and applied at its next READY transition. */
/* Redesign 5: publish the session capability mask that new
   processes inherit; read a background job's own mask and
   its vruntime accounting (for `sched -v`). */
void proc_set_session_caps(u32 caps);
int proc_bg_caps(u32 pid, u32 *caps_out);
int proc_bg_vruntime(u32 pid, u32 *vruntime_out, u32 *weight_out, u32 *runs_out);
int proc_bg_cpu(u32 pid, int *cpu_out, int *pending_out);
int proc_bg_set_cpu(u32 pid, u32 uid, int cpu); /* 0 ok, -1 no job/permission, -2 no AP, -3 bad cpu */

#endif
