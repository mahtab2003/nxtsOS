#include "syscall.h"
#include "proc.h"
#include "console.h"
#include "../mm/vmm.h"
#include "../drivers/pit.h"

/* Validate a user print pointer before the kernel reads it: it must lie
   in the process's mapped code/data pages or its stack page, and the
   string must terminate within 256 bytes. Anything else returns -1
   instead of faulting the kernel. Yield/exit never return here. */
static int valid_print_ptr(struct proc *p, u32 ptr, const char **out, u32 *len) {
    u32 code_end = USER_BASE + p->code_pages * 4096;
    int in_code = (ptr >= USER_BASE && ptr < code_end);
    int in_stack = (ptr >= USER_STACK_PAGE && ptr < USER_STACK_TOP);
    if (!in_code && !in_stack) return 0;
    const char *s = (const char *)ptr;
    for (u32 i = 0; i < 256; i++) {
        if (s[i] == 0) { *out = s; *len = i; return 1; }
    }
    return 0;
}

void syscall_handler(struct regs *r) {
    u32 num = r->eax;
    if (num == SYS_PRINT) {
        if (current_proc == 0) { r->eax = (u32)-1; return; }
        const char *s = 0; u32 len = 0;
        if (!valid_print_ptr(current_proc, r->ebx, &s, &len)) {
            r->eax = (u32)-1; return;
        }
        /* Print via console_putchar so it reaches VGA and the serial log. */
        for (u32 i = 0; i < len; i++) console_putchar(s[i]);
        r->eax = 0;
    } else if (num == SYS_YIELD) {
        if (current_proc == 0) return;
        proc_save_from_regs(current_proc, r);
        current_proc->state = PROC_READY;
        sched_switch_asm(); /* noreturn */
    } else if (num == SYS_EXIT) {
        if (current_proc == 0) return;
        current_proc->state = PROC_EXITED;
        sched_switch_asm(); /* noreturn */
    } else if (num == SYS_GETPID) {
        r->eax = current_proc ? current_proc->pid : 0;
    } else if (num == SYS_TICKS) {
        r->eax = timer_ticks;
    } else {
        r->eax = (u32)-1;
    }
}
