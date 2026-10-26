#include "proc.h"
#include "elf.h"
#include "console.h"
#include "../mm/vmm.h"
#include "../drivers/gdt.h"
#include "../drivers/pit.h"
#include "../mm/pmm.h"

extern const u8 user_prog_blob[];
extern const u8 user_prog_blob_end[];

struct proc *current_proc = 0;
struct proc procs[MAX_PROCS];
int proc_count = 0;

/* Switch globals, read by switch.S. */
u32 sw_pd, sw_eip, sw_esp, sw_eflags, sw_kernel_stack_top;
u32 sw_edi, sw_esi, sw_ebp, sw_ebx, sw_edx, sw_ecx, sw_eax;
u32 sched_esp, sched_ebp, sched_ebx, sched_esi, sched_edi;

static u8 kernel_stacks[MAX_PROCS][8192];

void proc_save_from_regs(struct proc *p, struct regs *r) {
    p->eip = r->eip; p->esp = r->useresp; p->eflags = r->eflags;
    p->edi = r->edi; p->esi = r->esi; p->ebp = r->ebp;
    p->ebx = r->ebx; p->edx = r->edx; p->ecx = r->ecx; p->eax = r->eax;
}

static void run_process(struct proc *p) {
    sw_pd = p->pd; sw_eip = p->eip; sw_esp = p->esp; sw_eflags = p->eflags;
    sw_kernel_stack_top = p->kernel_stack_top;
    sw_edi = p->edi; sw_esi = p->esi; sw_ebp = p->ebp;
    sw_ebx = p->ebx; sw_edx = p->edx; sw_ecx = p->ecx; sw_eax = p->eax;
    tss_set_esp0(p->kernel_stack_top);
    p->state = PROC_RUNNING;
    current_proc = p;
    switch_to_user_asm();
    /* Reached only via sched_switch_asm (yield, exit, or timer preempt).
       Interrupt entry cleared IF and the stack switch never restores it,
       so without this the scheduler — and the shell after it — would run
       with interrupts off and never see another timer/keyboard IRQ. */
    current_proc = 0;
    __asm__ volatile ("sti");
}

static u8 exec_kernel_stack[8192];

int proc_exec_file(const char *name, u32 uid) {
    /* Run a single ELF program to completion, in the shell's context.
       Yield/preemption return here with state READY, so loop until
       the program exits; then free its address space. */
    static struct proc exec_proc;
    if (elf_create_proc(name, uid, &exec_proc) != 0) return -1;
    exec_proc.pid = 3;
    exec_proc.kernel_stack_top = (u32)&exec_kernel_stack[8192];
    console_printf("Running %s (pid %u, uid %u)...\n", name, exec_proc.pid, uid);
    do {
        run_process(&exec_proc);
    } while (exec_proc.state == PROC_READY);
    vmm_destroy_pd(exec_proc.pd);
    exec_proc.pd = 0;
    console_printf("Program %s finished\n", name);
    return 0;
}

void proc_init(void) {
    u32 blob_size = (u32)(user_prog_blob_end - user_prog_blob);
    console_printf("User program blob: %u bytes\n", blob_size);
    for (int i = 0; i < 2; i++) {
        struct proc *p = &procs[proc_count];
        p->pid = (u32)(proc_count + 1);
        p->uid = 0;
        p->state = PROC_READY;
        p->pd = vmm_create_pd();
        p->code_pages = vmm_map_user(p->pd, user_prog_blob, blob_size);
        p->kernel_stack_top = (u32)&kernel_stacks[proc_count][8192];
        p->eip = USER_BASE; p->esp = USER_STACK_TOP; p->eflags = 0x202;
        p->edi = p->esi = p->ebp = p->ebx = p->edx = p->ecx = p->eax = 0;
        console_printf("Process %u created: pd=0x%x code_pages=%u\n",
                       p->pid, p->pd, p->code_pages);
        proc_count++;
    }
}

void scheduler_run(void) {
    int remaining;
    do {
        remaining = 0;
        for (int i = 0; i < proc_count; i++) {
            if (procs[i].state == PROC_READY) {
                remaining++;
                run_process(&procs[i]);
            } else if (procs[i].state == PROC_RUNNING) {
                remaining++;
            }
        }
    } while (remaining > 0);
    /* Teardown (fixes the v0.2.0 leak): free each exited process's
       user frames, page tables, and page directory. */
    for (int i = 0; i < proc_count; i++) {
        if (procs[i].state == PROC_EXITED) {
            vmm_destroy_pd(procs[i].pd);
            procs[i].pd = 0;
        }
    }
    console_printf("All user processes finished. PMM used=%u frames\n",
                   pmm_used_frames());
}

void timer_maybe_preempt(struct regs *r) {
    static u32 last_preempt = 0;
    if (current_proc == 0) return;
    if (r->cs != 0x1B) return; /* only preempt code running in user mode */
    if (timer_ticks - last_preempt < 10) return; /* 100 ms quantum */
    last_preempt = timer_ticks;
    proc_save_from_regs(current_proc, r);
    current_proc->state = PROC_READY;
    sched_switch_asm(); /* noreturn */
}
