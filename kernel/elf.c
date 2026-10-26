#include "elf.h"
#include "console.h"
#include "../fs/vfs.h"
#include "../mm/pmm.h"
#include "../mm/vmm.h"

#define ELF_MAX_SIZE 65536
#define ELF_MAX_SEGMENT 262144
#define ELF_MAX_TOTAL 262144
static u8 elf_buf[ELF_MAX_SIZE];

struct elfhdr {
    u8 ident[16];
    u16 type, machine;
    u32 version, entry, phoff, shoff, flags;
    u16 ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
} __attribute__((packed));
struct phdr {
    u32 type, offset, vaddr, paddr, filesz, memsz, flags, align;
} __attribute__((packed));

static u32 rd16(const u8 *p) { return (u32)p[0] | ((u32)p[1] << 8); }
static u32 rd32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

int elf_create_proc(const char *name, u32 uid, struct proc *p) {
    memset(p, 0, sizeof(*p));
    u32 size = 0;
    if (fs_read_as(name, elf_buf, sizeof(elf_buf), &size, uid) != 0) return -1;
    if (size < sizeof(struct elfhdr)) return -1;
    struct elfhdr *eh = (struct elfhdr *)elf_buf;
    if (eh->ident[0] != 0x7F || eh->ident[1] != 'E' || eh->ident[2] != 'L' || eh->ident[3] != 'F') return -1;
    if (eh->ident[4] != 1 || eh->ident[5] != 1 || eh->ident[6] != 1) return -1; /* 32-bit, LE, v1 */
    if (rd16((u8 *)&eh->type) != 2) return -1; /* ET_EXEC only */
    if (rd16((u8 *)&eh->machine) != 3) return -1; /* i386 */
    u32 entry = rd32((u8 *)&eh->entry);
    u32 phoff = rd32((u8 *)&eh->phoff);
    u32 phentsize = rd16((u8 *)&eh->phentsize);
    u32 phnum = rd16((u8 *)&eh->phnum);
    if (phentsize != sizeof(struct phdr)) return -1;
    if (phnum == 0 || phnum > 32) return -1;
    if (phoff >= size) return -1;
    if (phnum > (size - phoff) / sizeof(struct phdr)) return -1;

    u32 pd = vmm_create_pd();
    if (pd == 0) return -1;
    u32 total_mem = 0;
    u32 max_code_end = USER_BASE;
    int entry_found = 0;
    for (u32 i = 0; i < phnum; i++) {
        struct phdr *ph = (struct phdr *)(elf_buf + phoff + i * sizeof(struct phdr));
        if (rd32((u8 *)&ph->type) != 1) continue; /* PT_LOAD only */
        u32 offset = rd32((u8 *)&ph->offset);
        u32 vaddr = rd32((u8 *)&ph->vaddr);
        u32 filesz = rd32((u8 *)&ph->filesz);
        u32 memsz = rd32((u8 *)&ph->memsz);
        if (filesz > memsz) goto fail;
        if (memsz > ELF_MAX_SEGMENT) goto fail;
        if (total_mem > ELF_MAX_TOTAL - memsz) goto fail;
        total_mem += memsz;
        if (offset > size || filesz > size - offset) goto fail;
        if (vaddr < USER_BASE) goto fail;
        if (memsz > 0 && vaddr > USER_STACK_PAGE - memsz) goto fail;
        u32 seg_end = vaddr + memsz;
        if (seg_end > max_code_end) max_code_end = seg_end;
        if (entry >= vaddr && entry < seg_end) entry_found = 1;
        u32 page_start = vaddr & ~4095u;
        u32 page_end = (seg_end + 4095u) & ~4095u;
        for (u32 page = page_start; page < page_end; page += 4096) {
            u32 frame = pmm_alloc_frame();
            if (frame == 0) goto fail;
            u8 *dst = (u8 *)(u32)frame; /* frames are in the identity-mapped region */
            memset(dst, 0, 4096);
            for (u32 j = 0; j < 4096; j++) {
                u32 virt = page + j;
                if (virt >= vaddr && virt < vaddr + filesz)
                    dst[j] = elf_buf[offset + (virt - vaddr)];
            }
            vmm_map_page(pd, page, frame, PAGE_RW | PAGE_USER);
        }
    }
    if (!entry_found || total_mem == 0) goto fail;
    /* Stack page, as in vmm_map_user. */
    {
        u32 frame = pmm_alloc_frame();
        if (frame == 0) goto fail;
        memset((u8 *)(u32)frame, 0, 4096);
        vmm_map_page(pd, USER_STACK_PAGE, frame, PAGE_RW | PAGE_USER);
    }
    p->pd = pd;
    p->eip = entry; p->esp = USER_STACK_TOP; p->eflags = 0x202;
    p->code_pages = (max_code_end - USER_BASE + 4095u) / 4096u;
    p->uid = uid;
    p->state = PROC_READY;
    return 0;
fail:
    vmm_destroy_pd(pd);
    p->pd = 0;
    return -1;
}
