/* nxtsOS boot entry: Multiboot 1 header, stack setup, call kmain. */
.set ALIGN,    1<<0
.set MEMINFO,  1<<1
.set FLAGS,    ALIGN | MEMINFO
.set MAGIC,    0x1BADB002
.set CHECKSUM, -(MAGIC + FLAGS)

.section .multiboot, "a"
.align 4
.long MAGIC
.long FLAGS
.long CHECKSUM

.section .bss
.align 16
stack_bottom:
.skip 16384
stack_top:

.section .text
.global _start
.type _start, @function
_start:
    mov $stack_top, %esp
    /* kmain(magic, multiboot_info): push info, then magic, so magic is arg 1. */
    push %ebx
    push %eax
    call kmain
    cli
1:  hlt
    jmp 1b
.size _start, . - _start
.section .note.GNU-stack,"",@progbits
