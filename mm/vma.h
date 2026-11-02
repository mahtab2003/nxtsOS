#ifndef NXTS_VMA_H
#define NXTS_VMA_H
#include "../kernel/common.h"
#include "../kernel/proc.h"
/* Demand paging (CORE_CLI.md section 15.4, redesign 5): a
   per-process VMA list. A VMA is a reserved user address range
   whose pages are NOT mapped upfront: the first access to a
   page inside a VMA faults, the fault handler maps a fresh
   zero page there, and the faulting instruction resumes. A
   fault outside every VMA is not handled here (the caller
   terminates the faulting process; it never silently
   succeeds). VMAs live in struct proc (proc.h), never on any
   stack, and are freed implicitly when vmm_destroy_pd frees
   the process address space (the records themselves are
   zeroed by elf_create_proc's memset at the next reuse).
   Swap interaction: VMA_SWAPPABLE only records intent. No
   swap area is configured (see blk_swap_status), so no page
   is ever written out; a swappable VMA behaves exactly like
   a normal one until a backing area exists. */
int vma_add(struct proc *p, u32 addr, u32 pages, u32 flags); /* 0 ok, -1 bad */
int vma_find(struct proc *p, u32 addr); /* index, or -1 */
int vma_overlaps(struct proc *p, u32 start, u32 end); /* 1 if any VMA intersects */
int vma_contains_range(struct proc *p, u32 ptr, u32 len); /* 1 if fully inside one VMA */
/* Fault service: map a zero page for `addr` if it lies in a
   VMA of `p`. Returns 1 when mapped (caller resumes the
   faulting instruction), 0 otherwise (no VMA, or no free
   frame: the caller must fail the process, never retry in
   a loop). Small locals only; no lock is held on entry, and
   the PMM lock is taken only inside pmm_alloc_frame, so the
   lock order (bg_lock -> kmalloc_lock -> pmm_lock) is never
   inverted and no lock is held across a switch or sleep. */
int vma_handle_fault(struct proc *p, u32 addr);
void vma_stats(u32 *faults_out, u32 *pages_out);
#endif
