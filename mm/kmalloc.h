/* Kernel heap allocator (deep-core phase, §14.10 item 1).
   No kmalloc existed: every kernel buffer was a file-scope
   static, which is also why the 16 KiB stack rule is load-
   bearing. The heap is a static .bss arena (128 KiB), so it
   is identity-mapped and needs no PMM frame management and
   no page-table work. First-fit free list with split and
   coalescing; 8-byte alignment. Never panics: OOM returns
   0. Uniprocessor only (no locks — the kernel has no SMP
   locking yet, see §14.7). */
#ifndef NXTS_KMALLOC_H
#define NXTS_KMALLOC_H
#include "../kernel/common.h"

void kmalloc_init(void);
void *kmalloc(u32 size); /* 0 on size 0 or OOM */
void kfree(void *ptr);   /* ignores 0 and out-of-heap pointers */
void kmalloc_stats(u32 *used_out, u32 *free_out, u32 *blocks_out);
int  kmalloc_selftest(void); /* 0 PASS; alloc/free/coalesce/align */

#endif
