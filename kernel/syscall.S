/* int 0x80 syscall stub. Yield/exit handlers never return here: they
   call sched_switch_asm, which rets straight to the scheduler. All
   other syscalls return normally through the iret below, with the
   result the handler wrote into regs->eax (restored by popa). */
.global syscall_stub
.extern syscall_handler
syscall_stub:
    pushl $0
    pushl $0x80
    jmp syscall_common
syscall_common:
    pusha
    mov %ds, %ax
    push %eax
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    /* §15.2: the syscall gate (0xEE) is an interrupt gate, so
       it clears IF on entry — syscalls used to run with
       interrupts off. That was invisible while every syscall
       returned at once, but socket syscalls wait on timer
       ticks (connect/send/close timeouts), and with IF=0
       ticks never advance: a close drained forever. So
       re-enable interrupts here. This is safe: the timer
       ISR only preempts user-mode code (cs == 0x1B, see
       timer_maybe_preempt), and a syscall runs with kernel
       cs, so the ISR just counts ticks and returns — no
       preemption out of a half-finished syscall, and no
       re-entrancy into the socket layer (no ISR calls it).
       iret at the end restores the caller's flags anyway. */
    sti
    push %esp
    call syscall_handler
    add $4, %esp
    pop %eax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    popa
    add $8, %esp
    iret
.section .note.GNU-stack,"",@progbits
