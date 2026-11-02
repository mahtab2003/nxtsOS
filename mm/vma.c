#include "vma.h"
#include "vmm.h"
#include "pmm.h"

static u32 vma_faults_total = 0;
static u32 vma_pages_total = 0;

void vma_stats(u32 *faults_out, u32 *pages_out) {
    if (faults_out) *faults_out = vma_faults_total;
    if (pages_out) *pages_out = vma_pages_total;
}

int vma_find(struct proc *p, u32 addr) {
    if (!p) return -1;
    for (int i = 0; i < PROC_MAX_VMA; i++) {
        if (!p->vmas[i].used) continue;
        u32 s = p->vmas[i].start;
        u32 e = s + p->vmas[i].pages * 4096u;
        if (addr >= s && addr < e) return i;
    }
    return -1;
}

int vma_overlaps(struct proc *p, u32 start, u32 end) {
    if (!p || end <= start) return 0;
    for (int i = 0; i < PROC_MAX_VMA; i++) {
        if (!p->vmas[i].used) continue;
        u32 s = p->vmas[i].start;
        u32 e = s + p->vmas[i].pages * 4096u;
        if (start < e && s < end) return 1;
    }
    return 0;
}

int vma_contains_range(struct proc *p, u32 ptr, u32 len) {
    if (!p || len == 0) return 0;
    if (ptr + len < ptr) return 0; /* overflow guard */
    int i = vma_find(p, ptr);
    if (i < 0) return 0;
    u32 s = p->vmas[i].start;
    u32 e = s + p->vmas[i].pages * 4096u;
    return (ptr >= s && ptr + len <= e) ? 1 : 0;
}

int vma_add(struct proc *p, u32 addr, u32 pages, u32 flags) {
    if (!p) return -1;
    if (addr & 4095u) return -1; /* page-aligned only */
    if (pages < 1 || pages > 16) return -1;
    if (flags & ~VMA_SWAPPABLE) return -1; /* unknown flag bits refused */
    /* The VMA must live in user space below the stack page and
       above the shared kernel region: it may not cover kernel
       pages, the ELF image, the brk heap, or the stack page.
       Overflow-safe: pages <= 16, addr < USER_STACK_PAGE. */
    if (addr < KERNEL_MAP_END) return -1;
    u32 end = addr + pages * 4096u;
    if (end <= addr || end > USER_STACK_PAGE) return -1;
    u32 code_end = USER_BASE + p->code_pages * 4096u;
    if (addr < code_end && USER_BASE < end) return -1;
    if (p->heap_base != 0 && p->heap_end > p->heap_base &&
        addr < p->heap_end && p->heap_base < end) return -1;
    if (addr < USER_STACK_TOP && USER_STACK_PAGE < end) return -1;
    if (vma_overlaps(p, addr, end)) return -1;
    for (int i = 0; i < PROC_MAX_VMA; i++) {
        if (p->vmas[i].used) continue;
        p->vmas[i].used = 1;
        p->vmas[i].start = addr;
        p->vmas[i].pages = pages;
        p->vmas[i].flags = flags;
        return 0;
    }
    return -1; /* VMA table full */
}

int vma_handle_fault(struct proc *p, u32 addr) {
    if (!p) return 0;
    u32 page = addr & ~4095u;
    if (vma_find(p, page) < 0) return 0;
    /* A present page cannot fault here: every user page is
       RW and there are no protection keys or NX faults for
       RW pages, so a fault on an in-VMA page always means
       "not yet mapped". Nothing ever unmaps a VMA page
       mid-run (only teardown frees the whole PD). */
    u32 frame = pmm_alloc_frame();
    if (frame == 0) return 0; /* OOM: fail the process, never panic */
    memset((u8 *)frame, 0, 4096);
    vmm_map_page(p->pd, page, frame, PAGE_RW | PAGE_USER);
    __asm__ volatile ("invlpg (%0)" : : "r"(page) : "memory");
    p->vma_faults++;
    p->vma_pages++;
    vma_faults_total++;
    vma_pages_total++;
    return 1;
}
