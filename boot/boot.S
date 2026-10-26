/* nxtsOS boot entry: Multiboot 1 header, stack setup, call kmain. */
.set ALIGN,    1<<0
.set MEMINFO,  1<<1
.set VIDEO,    1<<2
.set FLAGS,    ALIGN | MEMINFO | VIDEO
.set MAGIC,    0x1BADB002
.set CHECKSUM, -(MAGIC + FLAGS)

.section .multiboot, "a"
.align 4
.long MAGIC
.long FLAGS
.long CHECKSUM
/* Video mode request (flags bit 2 set): linear framebuffer, 800x600x32.
   The five address fields are present as zeros so the video fields
   land at offset 32, where GRUB reads them — without them, GRUB
   reads boot code as the mode type and refuses to boot (seen in
   testing: "unsupported graphical mode type 2045232924").
   If GRUB cannot set this mode, it boots in text mode and the
   framebuffer info flag is clear — the kernel then runs text-only
   and the GUI is unavailable, rather than panicking. */
.long 0
.long 0
.long 0
.long 0
.long 0
.long 0
.long 800
.long 600
.long 32

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
