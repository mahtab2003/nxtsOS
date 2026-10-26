/* Embedded user program binary, built first by scripts/build.sh. */
.section .user_blob, "a"
.global user_prog_blob
.global user_prog_blob_end
user_prog_blob:
    .incbin "build/user_prog.bin"
user_prog_blob_end:
.section .note.GNU-stack,"",@progbits
