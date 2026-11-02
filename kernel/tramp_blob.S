/* Embedded AP trampoline binary, built first by scripts/build.sh
   (same pattern as user_blob.S). */
.section .tramp_blob, "a"
.global tramp_blob
.global tramp_blob_end
tramp_blob:
    .incbin "build/trampoline.bin"
tramp_blob_end:
.section .note.GNU-stack,"",@progbits
