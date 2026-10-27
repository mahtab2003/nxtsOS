/* Load nxtsOS's GDT, reload CS/DS/SS, and load the task register. */
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
    mov $0x28, %ax
    ltr %ax
    ret
.section .note.GNU-stack,"",@progbits
