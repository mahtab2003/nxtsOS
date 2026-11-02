/* Phase 3 context switching.
   switch_to_user_asm: called from run_process() (C). It saves the
   scheduler's callee-saved registers and stack pointer, loads the
   process page directory, switches to the process kernel stack, pushes
   an iret frame (user SS/ESP/EFLAGS/CS/EIP), loads the process's saved
   user registers, and irets into ring 3. Interrupts stay off until the
   iret frame's EFLAGS (IF=1) takes effect in user mode.
   sched_switch_asm: called from a syscall/timer handler that has
   already saved the user context into the process struct. It restores
   the scheduler registers saved by switch_to_user_asm and rets to
   run_process(), bypassing the interrupt stub's iret entirely. The
   abandoned interrupt frame sits on the process kernel stack and is
   overwritten the next time that process is run. */
.global switch_to_user_asm
.global sched_switch_asm
.extern sw_pd, sw_eip, sw_esp, sw_eflags, sw_kernel_stack_top
.extern sw_edi, sw_esi, sw_ebp, sw_ebx, sw_edx, sw_ecx, sw_eax
.extern sched_esp, sched_ebp, sched_ebx, sched_esi, sched_edi
/* SMP (redesign 4): the AP runs user jobs through its OWN switch
   state. Sharing the BSP switch globals between CPUs would
   corrupt both switches the moment the BSP and AP ran jobs at
   once, so the AP entry points below are byte-identical copies
   against ap_ globals (see kernel/proc.c). */
.global switch_to_user_asm_ap
.global sched_switch_asm_ap
.extern ap_sw_pd, ap_sw_eip, ap_sw_esp, ap_sw_eflags, ap_sw_kernel_stack_top
.extern ap_sw_edi, ap_sw_esi, ap_sw_ebp, ap_sw_ebx, ap_sw_edx, ap_sw_ecx, ap_sw_eax
.extern ap_sched_esp, ap_sched_ebp, ap_sched_ebx, ap_sched_esi, ap_sched_edi

switch_to_user_asm:
    mov %ebx, sched_ebx
    mov %esi, sched_esi
    mov %edi, sched_edi
    mov %ebp, sched_ebp
    mov %esp, sched_esp
    cli
    mov sw_pd, %eax
    mov %eax, %cr3
    mov sw_kernel_stack_top, %esp
    pushl $0x23
    pushl sw_esp
    pushl sw_eflags
    pushl $0x1B
    pushl sw_eip
    mov $0x23, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov sw_edi, %edi
    mov sw_ebp, %ebp
    mov sw_ebx, %ebx
    mov sw_edx, %edx
    mov sw_ecx, %ecx
    mov sw_esi, %esi
    mov sw_eax, %eax
    iret

sched_switch_asm:
    mov sched_ebx, %ebx
    mov sched_esi, %esi
    mov sched_edi, %edi
    mov sched_ebp, %ebp
    mov sched_esp, %esp
    ret

switch_to_user_asm_ap:
    mov %ebx, ap_sched_ebx
    mov %esi, ap_sched_esi
    mov %edi, ap_sched_edi
    mov %ebp, ap_sched_ebp
    mov %esp, ap_sched_esp
    cli
    mov ap_sw_pd, %eax
    mov %eax, %cr3
    mov ap_sw_kernel_stack_top, %esp
    pushl $0x23
    pushl ap_sw_esp
    pushl ap_sw_eflags
    pushl $0x1B
    pushl ap_sw_eip
    mov $0x23, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov ap_sw_edi, %edi
    mov ap_sw_ebp, %ebp
    mov ap_sw_ebx, %ebx
    mov ap_sw_edx, %edx
    mov ap_sw_ecx, %ecx
    mov ap_sw_esi, %esi
    mov ap_sw_eax, %eax
    iret

sched_switch_asm_ap:
    mov ap_sched_ebx, %ebx
    mov ap_sched_esi, %esi
    mov ap_sched_edi, %edi
    mov ap_sched_ebp, %ebp
    mov ap_sched_esp, %esp
    ret
.section .note.GNU-stack,"",@progbits
