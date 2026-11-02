#include "pmm.h"
#include "../kernel/spinlock.h"

/* Bitmap: 1 bit per 4 KiB frame, sized for 512 MiB (131072 frames). */
#define MAX_FRAMES 131072
#define BITMAP_WORDS (MAX_FRAMES / 32)
static u32 bitmap[BITMAP_WORDS];
static u32 total_frames = 0, free_frames = 0;
/* SMP (redesign 4): the frame bitmap is shared by both CPUs, so
   alloc/free run under pmm_lock. Lock order: bg_lock ->
   kmalloc_lock -> pmm_lock (see kernel/spinlock.h). The lock is
   never held across a print, a sleep, or a scheduler switch —
   alloc/free are short, straight-line bitmap scans. */
static spinlock_t pmm_lock = SPINLOCK_INIT;

struct mmap_entry {
    u32 size;
    u32 addr_lo, addr_hi;
    u32 len_lo, len_hi;
    u32 type;
} __attribute__((packed));

static void set_frame(u32 frame, int used) {
    if (frame >= MAX_FRAMES) return;
    if (used) bitmap[frame / 32] |= (1u << (frame % 32));
    else bitmap[frame / 32] &= ~(1u << (frame % 32));
}
static int frame_used(u32 frame) {
    if (frame >= MAX_FRAMES) return 1;
    return (bitmap[frame / 32] >> (frame % 32)) & 1u;
}

void pmm_init(u32 mmap_addr, u32 mmap_len, u32 kstart, u32 kend) {
    for (u32 i = 0; i < BITMAP_WORDS; i++) bitmap[i] = 0xFFFFFFFFu;
    total_frames = 0; free_frames = 0;
    u32 p = mmap_addr;
    u32 end = mmap_addr + mmap_len;
    while (p < end) {
        struct mmap_entry *e = (struct mmap_entry *)p;
        if (e->type == 1) { /* available RAM */
            u32 start = e->addr_lo;
            u32 len = e->len_lo;
            u32 a = (start + 4095u) & ~4095u;
            u32 b = (start + len) & ~4095u;
            for (u32 addr = a; addr < b && addr < 512u * 1024u * 1024u; addr += 4096) {
                u32 f = addr / 4096;
                if (f >= MAX_FRAMES) break;
                if (frame_used(f)) { set_frame(f, 0); free_frames++; }
                if (f + 1 > total_frames) total_frames = f + 1;
            }
        }
        p += e->size + 4;
    }
    /* Reserve the first 1 MiB and the kernel image itself. */
    for (u32 addr = 0; addr < kend; addr += 4096) {
        u32 f = addr / 4096;
        if (f < MAX_FRAMES && !frame_used(f)) { set_frame(f, 1); free_frames--; }
    }
    (void)kstart;
}

u32 pmm_alloc_frame(void) {
    u32 f = spin_lock_irqsave(&pmm_lock);
    for (u32 fr = 0; fr < total_frames; fr++) {
        if (!frame_used(fr)) {
            set_frame(fr, 1); free_frames--;
            spin_unlock_irqrestore(&pmm_lock, f);
            return fr * 4096;
        }
    }
    spin_unlock_irqrestore(&pmm_lock, f);
    return 0;
}

void pmm_free_frame(u32 addr) {
    u32 f = spin_lock_irqsave(&pmm_lock);
    u32 fr = addr / 4096;
    if (fr < MAX_FRAMES && frame_used(fr)) { set_frame(fr, 0); free_frames++; }
    spin_unlock_irqrestore(&pmm_lock, f);
}

u32 pmm_total_frames(void) {
    u32 f = spin_lock_irqsave(&pmm_lock);
    u32 v = total_frames;
    spin_unlock_irqrestore(&pmm_lock, f);
    return v;
}
u32 pmm_free_frames(void) {
    u32 f = spin_lock_irqsave(&pmm_lock);
    u32 v = free_frames;
    spin_unlock_irqrestore(&pmm_lock, f);
    return v;
}
u32 pmm_used_frames(void) {
    u32 f = spin_lock_irqsave(&pmm_lock);
    u32 v = total_frames - free_frames;
    spin_unlock_irqrestore(&pmm_lock, f);
    return v;
}
