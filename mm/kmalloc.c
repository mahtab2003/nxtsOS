#include "kmalloc.h"
#include "../kernel/spinlock.h"

/* SMP (redesign 4): the heap arena is shared by both CPUs
   (syscalls from AP jobs can kmalloc through the socket layer),
   so every arena walk runs under kmalloc_lock. The arena never
   calls the PMM (it is a static array), so this lock never
   nests inside pmm_lock — but it may nest OUTSIDE it if a
   future caller allocates frames while holding it; the lock
   order bg_lock -> kmalloc_lock -> pmm_lock (spinlock.h) keeps
   that safe. Never held across a print or a switch. */
static spinlock_t kmalloc_lock = SPINLOCK_INIT;

#define KHEAP_SIZE (128u * 1024u)
#define KHEAP_ALIGN 8u

/* Static arena: the sanctioned large-buffer shape in this
   kernel (never the 16 KiB stack). 8-byte aligned base AND a
   16-byte header, so every payload is 8-byte aligned (a plain
   u8 array has alignment 1 and a 12-byte header misaligns
   payloads by 4 — the boot self-test caught exactly this). */
static u8 kheap[KHEAP_SIZE] __attribute__((aligned(8)));

struct kblock {
    u32 size; /* payload bytes, excluding this header */
    u32 free; /* 1 free, 0 used */
    struct kblock *next;
    u32 pad; /* header is 16 bytes, a multiple of 8 */
};

static struct kblock *khead = 0;
static int kinit_done = 0;

static u32 align_up(u32 v, u32 a) { return (v + a - 1u) & ~(a - 1u); }

void kmalloc_init(void) {
    if (kinit_done) return;
    khead = (struct kblock *)kheap;
    khead->size = KHEAP_SIZE - (u32)sizeof(struct kblock);
    khead->free = 1;
    khead->next = 0;
    kinit_done = 1;
}

void *kmalloc(u32 size) {
    if (!kinit_done || size == 0) return 0;
    u32 fl = spin_lock_irqsave(&kmalloc_lock);
    u32 need = align_up(size, KHEAP_ALIGN);
    struct kblock *b = khead;
    while (b) {
        if (b->free && b->size >= need) {
            /* Split when the remainder fits another block. */
            if (b->size >= need + (u32)sizeof(struct kblock) + KHEAP_ALIGN) {
                struct kblock *nb = (struct kblock *)((u8 *)b + sizeof(struct kblock) + need);
                nb->size = b->size - need - (u32)sizeof(struct kblock);
                nb->free = 1;
                nb->next = b->next;
                b->size = need;
                b->next = nb;
            }
            b->free = 0;
            void *ret = (void *)((u8 *)b + sizeof(struct kblock));
            spin_unlock_irqrestore(&kmalloc_lock, fl);
            return ret;
        }
        b = b->next;
    }
    spin_unlock_irqrestore(&kmalloc_lock, fl);
    return 0; /* OOM: never panic */
}

void kfree(void *ptr) {
    if (!kinit_done || ptr == 0) return;
    u8 *p = (u8 *)ptr;
    if (p < kheap + sizeof(struct kblock) || p >= kheap + KHEAP_SIZE) return;
    struct kblock *b = (struct kblock *)(p - sizeof(struct kblock));
    /* Header must be plausible: inside the arena, aligned. */
    if (((u8 *)b < kheap) || ((u8 *)b >= kheap + KHEAP_SIZE)) return;
    if ((((u32)b) & (KHEAP_ALIGN - 1u)) != 0) return;
    u32 fl = spin_lock_irqsave(&kmalloc_lock);
    if (b->free) { spin_unlock_irqrestore(&kmalloc_lock, fl); return; } /* double free: ignore */
    b->free = 1;
    /* Coalesce with the next block, then with the previous one. */
    if (b->next && b->next->free) {
        b->size += (u32)sizeof(struct kblock) + b->next->size;
        b->next = b->next->next;
    }
    struct kblock *prev = 0, *cur = khead;
    while (cur && cur != b) { prev = cur; cur = cur->next; }
    if (prev && prev->free) {
        prev->size += (u32)sizeof(struct kblock) + b->size;
        prev->next = b->next;
    }
    spin_unlock_irqrestore(&kmalloc_lock, fl);
}

void kmalloc_stats(u32 *used_out, u32 *free_out, u32 *blocks_out) {
    u32 fl = spin_lock_irqsave(&kmalloc_lock);
    u32 used = 0, fre = 0, n = 0;
    struct kblock *b = khead;
    while (b) {
        n++;
        if (b->free) fre += b->size;
        else used += b->size;
        b = b->next;
    }
    spin_unlock_irqrestore(&kmalloc_lock, fl);
    if (used_out) *used_out = used;
    if (free_out) *free_out = fre;
    if (blocks_out) *blocks_out = n;
}

int kmalloc_selftest(void) {
    kmalloc_init();
    /* Alignment: every allocation is 8-byte aligned. */
    void *a = kmalloc(1);
    void *b = kmalloc(100);
    void *c = kmalloc(4096);
    if (!a || !b || !c) return -1;
    if ((((u32)a) & 7u) || (((u32)b) & 7u) || (((u32)c) & 7u)) return -2;
    /* Write every byte: the arena is really mapped. */
    for (u32 i = 0; i < 1; i++) ((u8 *)a)[i] = 0xA5;
    for (u32 i = 0; i < 100; i++) ((u8 *)b)[i] = (u8)i;
    for (u32 i = 0; i < 4096; i++) ((u8 *)c)[i] = (u8)(i & 0xFF);
    for (u32 i = 0; i < 100; i++) if (((u8 *)b)[i] != (u8)i) return -3;
    /* Free middle, realloc: split reuse. */
    kfree(b);
    void *d = kmalloc(64);
    if (!d) return -4;
    /* Free all: coalescing must restore one block. */
    kfree(a); kfree(d); kfree(c);
    u32 used, fre, n;
    kmalloc_stats(&used, &fre, &n);
    if (used != 0 || n != 1) return -5;
    /* OOM: larger than the arena fails, never panics. */
    if (kmalloc(KHEAP_SIZE) != 0) return -6;
    /* Zero-size and double-free are safe no-ops. */
    if (kmalloc(0) != 0) return -7;
    void *e = kmalloc(32);
    if (!e) return -8;
    kfree(e); kfree(e);
    kmalloc_stats(&used, &fre, &n);
    if (used != 0 || n != 1) return -9;
    return 0;
}
