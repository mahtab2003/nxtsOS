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
