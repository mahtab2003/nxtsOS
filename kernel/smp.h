#ifndef NXTS_SMP_H
#define NXTS_SMP_H
#include "common.h"
#include "../drivers/idt.h"

/* SMP (redesign 4, CORE_CLI.md section 15.3). At most 2 CPUs are
   supported in this phase (BSP + one AP): the trampoline, the
   per-CPU stacks/TSS/switch state, and the shootdown path are
   all built for exactly one AP. A machine with more CPUs boots
   the first AP and leaves the rest parked — never reported as
   running. The kernel NEVER reports an AP as running unless it
   has signalled readiness (ap_state == 2, see smp_ap_online). */

/* BSP entry: parse the MADT, map + enable the LAPIC, calibrate
   the LAPIC timer, copy the trampoline to 0x8000, run the
   INIT-SIPI sequence, and wait for the AP's readiness signal.
   On any failure it prints the reason and leaves the kernel
   uniprocessor-by-construction (all smp_* accessors stay safe). */
void smp_init(void);
int smp_cpu_count(void);      /* 1 or 2 (2 only if the AP signalled) */
int smp_ap_online(void);      /* 1 iff the AP reached its idle loop */
int smp_ap_state(void);       /* 0 absent, 1 booting, 2 idle loop */
u32 smp_lapic_base(void);     /* 0 if no LAPIC/MADT */
int smp_cpu_index(void);      /* LAPIC ID -> 0 (BSP) or 1 (AP); 0 if unknown */
/* TLB shootdown: invalidate `virt` on the AP via IPI vector 240
   and wait for its ack. Returns 1 if acked, 0 if no AP / timeout.
   The caller must already have invalidated its own TLB entry. */
int smp_tlb_shootdown(u32 virt);
void smp_shootdown_stats(u32 *sent_out, u32 *acked_out);
u32 smp_ap_timer_per_10ms(void); /* calibrated LAPIC ticks per 10 ms, 0 if uncalibrated */

/* AP entry (called from the trampoline, never returns). */
void ap_main(void);
/* LAPIC IRQ handler for vectors 240 (shootdown), 241 (timer),
   255 (spurious). Called from the lapic stubs in drivers/isr.S. */
void lapic_irq_handler(struct regs *r);

/* TLB-shootdown proof state, shared with the page-fault handler
   (drivers/idt.c). The probe read is a single fixed instruction
   (mov (%eax), %ebx = 8B 18, 2 bytes) in smp.c's AP loop; the
   fault handler only skips it when every check matches (probe
   active, fault address == test page, kernel CS, exact bytes),
   and otherwise panics exactly as before. */
#define SMP_TLB_TEST_VIRT 0x03000000u
extern volatile int smp_tlb_probe_active;
extern volatile int smp_tlb_probe_faulted;

/* Kernel-side SMP proofs (driven by the shell `smp` command).
   All refuse honestly (-1) when no AP is online. */
int smp_locktest(u32 n, u32 *counter_out); /* 0 ok, -1 no AP, -2 timeout */
int smp_pmmtest(u32 *free_before_out, u32 *free_after_out, int *disjoint_out);
struct smp_tlb_result {
    u32 stale_before, stale_after;
    int ack;    /* shootdown IPI acked by the AP */
    int fault;  /* AP faulted on the page after shootdown */
};
int smp_tlb_proof(struct smp_tlb_result *res);
/* 0 = shootdown proven (stale reads grew after unmap, fault after
   shootdown, IPI acked); 1 = not proven (see res fields);
   -1 = no AP; -2 = setup failure (no frame / AP never probed). */

#endif
