#ifndef NXTS_SPINLOCK_H
#define NXTS_SPINLOCK_H
#include "common.h"

/* SMP spinlocks (redesign 4, CORE_CLI.md section 15.3).
   xchg-based: the lock word is 0 free / 1 held, and the atomic
   exchange is the whole protocol (no separate test-and-set race).
   Holders always run with interrupts disabled (irqsave), so an
   interrupt handler can never preempt a holder on the same CPU
   and spin on a lock that CPU already holds.
 *
 * WHERE A SPINLOCK MAY *NOT* BE TAKEN (violations deadlock or
 * corrupt, by construction — not by convention):
 *  - Never in an IRQ/exception handler. Handlers run with
 *    interrupts off and must only set flags (see the LAPIC
 *    shootdown handler, which sets a flag and returns).
 *  - Never across a sleep, a scheduler switch, a hlt-wait, or a
 *    console read. Holders must make forward progress, because
 *    the other CPU spins (it does not block).
 *  - Never nested against the lock order below. irqsave/
 *    irqrestore nesting is safe for the SAME lock only via the
 *    saved-flags discipline: an inner acquire saves IF=0 (the
 *    outer acquire already cleared it) and its restore keeps IF
 *    clear, so the outer restore is the one that re-enables.
 *  - Never while holding another lock that ranks HIGHER in the
 *    order below (a cycle would deadlock the moment both CPUs
 *    take the pair in opposite order).
 *
 * LOCK ORDER (outer -> inner, never reversed):
 *    bg_lock (job table + reap table)
 *      -> kmalloc_lock (kernel heap arena)
 *      -> pmm_lock (frame bitmap)
 * Console output uses its own owner-recursive lock in console.c
 * and is never taken while holding bg/pmm/kmalloc locks: all
 * job-table prints happen AFTER the lock is released, from
 * copied info. The one nesting that exists is console ->
 * (capture flush -> fs -> pmm), which is safe because the PMM
 * never acquires the console lock (panics bypass it).
 *
 * Kernel stacks are 16 KiB per CPU: no lock is ever taken with
 * a large object on the stack, and no lock holder calls code
 * that allocates a large stack frame. */
typedef struct { volatile u32 locked; } spinlock_t;
#define SPINLOCK_INIT { 0 }

/* Acquire: save EFLAGS, disable interrupts, then spin on xchg
   until the exchange returns 0 (we took it). Returns the saved
   flags for the matching restore. `pause` in the spin loop is
   the polite form on SMP (less bus contention than a bare loop). */
static inline u32 spin_lock_irqsave(spinlock_t *l) {
    u32 flags;
    __asm__ volatile ("pushfl\n\tpopl %0\n\tcli"
                      : "=r"(flags) :: "memory");
    for (;;) {
        u32 one = 1;
        __asm__ volatile ("xchg %0, %1"
                          : "+r"(one) : "m"(l->locked) : "memory");
        if (one == 0) break;
        __asm__ volatile ("pause");
    }
    return flags;
}

/* Release: full barrier, clear the word, then restore IF from
   the saved flags (sti only if interrupts were enabled when
   the matching acquire ran). */
static inline void spin_unlock_irqrestore(spinlock_t *l, u32 flags) {
    __asm__ volatile ("" ::: "memory");
    l->locked = 0;
    __asm__ volatile ("" ::: "memory");
    if (flags & 0x200u) __asm__ volatile ("sti");
}

#endif
