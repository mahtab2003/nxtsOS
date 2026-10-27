ENTRY(_start)
SECTIONS {
    . = 1M;
    __kernel_start = .;
    .multiboot : { *(.multiboot) }
    .text : { *(.text) }
    .rodata : { *(.rodata) }
    .user_blob : { *(.user_blob) }
    .data : { *(.data) }
    .bss : {
        *(COMMON)
        *(.bss)
    }
    __kernel_end = .;
    /DISCARD/ : {
        *(.note.gnu.build-id)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note.GNU-stack)
    }
}
