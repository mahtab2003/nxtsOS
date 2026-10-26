/* User program entry: call main, then exit via syscall 3. */
.global _start
_start:
    call main
    mov $3, %eax
    int $0x80
1:  jmp 1b
.section .note.GNU-stack,"",@progbits
