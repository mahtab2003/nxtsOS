/* Load nxtsOS's GDT and reload CS/DS/SS. */
.global gdt_flush
.extern gdt_ptr
gdt_flush:
    lgdt gdt_ptr
    ljmp $0x08, $reload_cs
reload_cs:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    ret
.section .note.GNU-stack,"",@progbits
