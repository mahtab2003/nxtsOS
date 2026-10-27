#include "vmm.h"
#include "pmm.h"
#include "../kernel/panic.h"

static u32 kernel_pd = 0;

static void *phys_to_virt(u32 phys) {
    /* Page-directory/table frames are allocated early and low, so they
       live inside the identity-mapped region. Anything else is a bug
       in this phase, and failing loudly beats silently corrupting. */
    if (phys >= KERNEL_MAP_END) panic("vmm: page table frame outside identity map");
    return (void *)phys;
}

void vmm_map_page(u32 pd_phys, u32 virt, u32 phys, u32 flags) {
    u32 *pd = (u32 *)phys_to_virt(pd_phys);
    u32 pd_idx = virt >> 22;
    u32 pt_idx = (virt >> 12) & 0x3FF;
    if ((pd[pd_idx] & PAGE_PRESENT) == 0) {
        u32 pt = pmm_alloc_frame();
        if (pt == 0) panic("vmm: out of frames for page table");
        memset(phys_to_virt(pt), 0, 4096);
        pd[pd_idx] = pt | PAGE_PRESENT | PAGE_RW | (flags & PAGE_USER);
    }
    u32 *pt = (u32 *)phys_to_virt(pd[pd_idx] & ~0xFFFu);
    pt[pt_idx] = (phys & ~0xFFFu) | flags | PAGE_PRESENT;
}

void vmm_enable_paging(u32 pd_phys) {
    __asm__ volatile (
        "mov %0, %%eax\n\t"
        "mov %%eax, %%cr3\n\t"
        "mov %%cr0, %%eax\n\t"
        "orl $0x80000000, %%eax\n\t"
        "mov %%eax, %%cr0\n\t"
        : : "r"(pd_phys) : "eax");
}

void vmm_init(void) {
    kernel_pd = pmm_alloc_frame();
    if (kernel_pd == 0) panic("vmm: out of frames for page directory");
    memset(phys_to_virt(kernel_pd), 0, 4096);
    /* Identity-map 0-32 MB, supervisor, read/write, except page 0
       (left unmapped so a null dereference faults instead of reading). */
    for (u32 addr = 0x1000; addr < KERNEL_MAP_END; addr += 4096)
        vmm_map_page(kernel_pd, addr, addr, PAGE_RW);
    vmm_enable_paging(kernel_pd);
}

u32 vmm_kernel_pd(void) { return kernel_pd; }

void vmm_destroy_pd(u32 pd_phys) {
    if (pd_phys == 0 || pd_phys == kernel_pd) return;
    /* Switch back to the kernel PD first: the PD being freed must not
       be the active one when its frames are returned to the PMM. */
    vmm_enable_paging(kernel_pd);
    u32 *pd = (u32 *)phys_to_virt(pd_phys);
    /* PD entries 0-7 are the shared kernel region, and entry 256 is
       the shared framebuffer (see vmm_create_pd) — both belong to
       the kernel PD and must never be freed here. Only the other
       entries (user space) are freed. */
    for (int i = 8; i < 1024; i++) {
        if (i == 256) continue;
        if ((pd[i] & PAGE_PRESENT) == 0) continue;
        u32 pt_phys = pd[i] & ~0xFFFu;
        u32 *pt = (u32 *)phys_to_virt(pt_phys);
        for (int j = 0; j < 1024; j++) {
            if (pt[j] & PAGE_PRESENT) pmm_free_frame(pt[j] & ~0xFFFu);
        }
        pmm_free_frame(pt_phys);
    }
    pmm_free_frame(pd_phys);
}

u32 vmm_create_pd(void) {
    u32 pd = pmm_alloc_frame();
    if (pd == 0) panic("vmm: out of frames for process page directory");
    memset(phys_to_virt(pd), 0, 4096);
    u32 *kpd = (u32 *)phys_to_virt(kernel_pd);
    u32 *npd = (u32 *)phys_to_virt(pd);
    /* Kernel region (PD entries 0-7, covering 0-32 MB) is shared. */
    for (int i = 0; i < 8; i++) npd[i] = kpd[i];
    /* Framebuffer (PD entry 256, 0x40000000, supervisor pages) is
       also shared, so kernel code running in syscall context (ring
       0, with a user PD active) can draw to it — e.g. a user
       program's print syscall goes through console_putchar, which
       in graphics mode writes to the framebuffer. Without this,
       the first user print in graphics mode page-faulted, because
       FB_VIRT was unmapped in user PDs. User code itself (ring 3)
       still cannot access these supervisor pages directly. */
    npd[256] = kpd[256];
    return pd;
}

u32 vmm_map_user(u32 pd_phys, const u8 *blob, u32 blob_size) {
    u32 code_pages = (blob_size + 4095) / 4096 + 1; /* +1 zero page for BSS */
    for (u32 i = 0; i < code_pages; i++) {
        u32 frame = pmm_alloc_frame();
        if (frame == 0) panic("vmm: out of frames for user code");
        u8 *dst = (u8 *)phys_to_virt(frame);
        memset(dst, 0, 4096);
        u32 off = i * 4096;
        if (off < blob_size) {
            u32 chunk = blob_size - off;
            if (chunk > 4096) chunk = 4096;
            memcpy(dst, blob + off, chunk);
        }
        vmm_map_page(pd_phys, USER_BASE + i * 4096, frame, PAGE_RW | PAGE_USER);
    }
    u32 stack_frame = pmm_alloc_frame();
    if (stack_frame == 0) panic("vmm: out of frames for user stack");
    memset(phys_to_virt(stack_frame), 0, 4096);
    vmm_map_page(pd_phys, USER_STACK_PAGE, stack_frame, PAGE_RW | PAGE_USER);
    return code_pages;
}
