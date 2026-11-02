/* User program entry: call main, then exit via syscall 3.
   Deep-core phase: main's return value is preserved in ebx,
   which SYS_EXIT reads as the exit code (0-255). */
.global _start
_start:
    call main
    mov %eax, %ebx
    mov $3, %eax
    int $0x80
1:  jmp 1b
.section .note.GNU-stack,"",@progbits
