#include "smp.h"
#include "console.h"
#include "spinlock.h"
#include "proc.h"
#include "../mm/vmm.h"
#include "../mm/pmm.h"
#include "../drivers/gdt.h"
#include "../drivers/idt.h"
#include "../drivers/pit.h"
#include "tramp_offsets.h"

extern const u8 tramp_blob[];
extern const u8 tramp_blob_end[];

#define TRAMP_ADDR 0x8000u
#define LAPIC_ID 0x20u
#define LAPIC_SVR 0xF0u
#define LAPIC_LVT_TIMER 0x320u
#define LAPIC_LVT_LINT0 0x350u
#define LAPIC_EOI 0xB0u
#define LAPIC_ICR_LO 0x300u
#define LAPIC_ICR_HI 0x310u
#define LAPIC_TIMER_INIT 0x380u
#define LAPIC_TIMER_CUR 0x390u
#define LAPIC_TIMER_DIV 0x3E0u
#define LAPIC_VEC_SHOOTDOWN 240u
#define LAPIC_VEC_TIMER 241u
#define LAPIC_VEC_SPURIOUS 255u

/* ---- state (all file-scope statics, never on a stack) ---- */
static u32 lapic_base = 0;
static u32 bsp_lapic_id = 0;
/* 0xFFFFFFFF = no AP id known. This MUST NOT be 0: on a UP boot
   the BSP id is 0, and a 0-valued ap_lapic_id would make
   smp_cpu_index() misidentify the BSP as the AP (seen live:
   UP boot hung in scheduler_run — syscalls resolved to the
   NULL AP proc and switches went to the AP scheduler state). */
static u32 ap_lapic_id = 0xFFFFFFFFu;
static int ap_present = 0; /* MADT listed a second CPU */
static volatile int ap_state_v = 0; /* 0 absent, 1 booting, 2 idle */
static int ap_online_v = 0;
static u32 ap_ticks_per_10ms = 0;
static u32 shootdowns_sent = 0, shootdowns_acked = 0;
/* Per-CPU kernel stack for the AP (16 KiB, like the BSP stack in
   boot.S — never shared, never on another CPU's stack). */
static u8 ap_stack[16384] __attribute__((aligned(16)));
static const u16 ap_tr_sel = 0x30; /* second TSS, drivers/gdt.c */

/* TLB shootdown handshake + probe state. */
static volatile u32 shootdown_addr = 0;
static volatile u32 shootdown_ack = 0;
volatile int smp_tlb_probe_active = 0;
volatile int smp_tlb_probe_faulted = 0;
static volatile u32 ap_probe_reads = 0;
static volatile int ap_probe_done = 0;
static volatile int ap_tlb_mode = 0; /* 1 = AP is probing the test page */

/* AP work items (driven by the shell `smp` test commands). */
#define AP_WORK_NONE 0
#define AP_WORK_LOCKTEST 1
#define AP_WORK_PMMTEST 2
static volatile int ap_work_cmd = AP_WORK_NONE;
static volatile int ap_work_done = 0;
static volatile u32 ap_work_n = 0;
static spinlock_t test_lock = SPINLOCK_INIT;
static volatile u32 locktest_counter = 0;
static u32 ap_pmm_addrs[32];
static u32 bsp_pmm_addrs[32];

/* ---- LAPIC access (page mapped into the kernel PD by smp_init) ---- */
static void lapic_write(u32 reg, u32 val) {
    *(volatile u32 *)(lapic_base + reg) = val;
}
static u32 lapic_read(u32 reg) {
    return *(volatile u32 *)(lapic_base + reg);
}
static void lapic_eoi(void) { lapic_write(LAPIC_EOI, 0); }

static void lapic_send_ipi(u32 dest_id, u32 icr_lo) {
    lapic_write(LAPIC_ICR_HI, dest_id << 24);
    lapic_write(LAPIC_ICR_LO, icr_lo);
    /* Bounded delivery-status wait: a stuck ICR must not hang boot. */
    for (volatile int i = 0; i < 100000; i++)
        if ((lapic_read(LAPIC_ICR_LO) & 0x1000u) == 0) break;
}

/* Enable the local APIC: spurious vector 255 + software enable.
   LINT0 is set to ExtINT/unmasked so the PIC (timer/keyboard)
   keeps reaching the BSP in virtual-wire mode — without this,
   enabling the LAPIC would mask PIC delivery on some firmware. */
static void lapic_enable(void) {
    lapic_write(LAPIC_SVR, 0x100u | LAPIC_VEC_SPURIOUS);
    lapic_write(LAPIC_LVT_LINT0, 0x700u);
}

/* AP variant: the BSP alone owns the 8259, so the AP must NOT
   accept ExtINT on LINT0. With 0x700 here, QEMU's virtual-wire
   routing delivered the PIT IRQ0 to the AP as well, and the AP's
   IRQ0 handler ran the BSP preempt path on the AP, corrupting
   the BSP job's saved state (see CORE_CLI.md §15.3). Masked
   LINT0 (0x10000) keeps the AP on LAPIC timer + IPIs only. */
static void lapic_enable_ap(void) {
    lapic_write(LAPIC_SVR, 0x100u | LAPIC_VEC_SPURIOUS);
    lapic_write(LAPIC_LVT_LINT0, 0x10000u);
}

u32 smp_lapic_base(void) { return lapic_base; }
int smp_ap_online(void) { return ap_online_v; }
int smp_ap_state(void) { return ap_state_v; }
int smp_cpu_count(void) { return ap_online_v ? 2 : 1; }
u32 smp_ap_timer_per_10ms(void) { return ap_ticks_per_10ms; }
void smp_shootdown_stats(u32 *sent_out, u32 *acked_out) {
    if (sent_out) *sent_out = shootdowns_sent;
    if (acked_out) *acked_out = shootdowns_acked;
}

int smp_cpu_index(void) {
    if (lapic_base == 0) return 0;
    u32 id = lapic_read(LAPIC_ID) >> 24;
    /* BSP id wins ties: before smp_init sets the real BSP id,
       lapic_base is 0 and we never get here. */
    if (id == bsp_lapic_id) return 0;
    if (ap_lapic_id != 0xFFFFFFFFu && id == ap_lapic_id) return 1;
    return 0;
}

/* ---- MADT parsing (own ACPI window; acpi.c's helpers are static).
   The window sits at 32 MiB + 1 MiB (PD index 8, second page in
   the same page table acpi.c uses for its own window). */
#define SMP_WIN 0x02100000u
static u32 smp_win_page = 0xFFFFFFFFu;
static u8 smp_read_byte(u32 phys) {
    if (phys >= 4096 && phys < KERNEL_MAP_END) return *(volatile u8 *)phys;
    u32 page = phys & ~0xFFFu;
    if (page != smp_win_page) {
        vmm_map_page(vmm_kernel_pd(), SMP_WIN, page, PAGE_RW);
        __asm__ volatile ("invlpg (%0)" :: "r"(SMP_WIN) : "memory");
        smp_win_page = page;
    }
    return *(volatile u8 *)(SMP_WIN + (phys & 0xFFFu));
}
static u32 smp_read_u32(u32 phys) {
    u32 v = 0;
    for (int i = 0; i < 4; i++) v |= (u32)smp_read_byte(phys + (u32)i) << (i * 8);
    return v;
}
static int smp_sig(u32 phys, const char *sig4) {
    for (int i = 0; i < 4; i++)
        if (smp_read_byte(phys + (u32)i) != (u8)sig4[i]) return 0;
    return 1;
}
static int smp_sig8(u32 phys, const char *sig8) {
    for (int i = 0; i < 8; i++)
        if (smp_read_byte(phys + (u32)i) != (u8)sig8[i]) return 0;
    return 1;
}
static int smp_checksum(u32 phys, u32 len) {
    u32 sum = 0;
    for (u32 i = 0; i < len; i++) sum += smp_read_byte(phys + i);
    return (sum & 0xFFu) == 0;
}

/* Returns 0 on success (base + enabled APIC IDs filled), -1 on any
   failure (fail-closed: the caller stays uniprocessor). */
static int madt_parse(u32 *base_out, u8 *ids, int max_ids, int *n_out) {
    u32 rsdp = 0;
    u16 ebda_seg = (u16)(smp_read_byte(0x40E) |
                         ((u32)smp_read_byte(0x40F) << 8));
    u32 ebda = (u32)ebda_seg << 4;
    if (ebda >= 0x40000 && ebda < 0xA0000) {
        for (u32 p = ebda; p < ebda + 1024; p += 16)
            if (smp_sig8(p, "RSD PTR ")) { rsdp = p; break; }
    }
    if (!rsdp) {
        for (u32 p = 0xE0000; p < 0x100000; p += 16)
            if (smp_sig8(p, "RSD PTR ")) { rsdp = p; break; }
    }
    if (!rsdp) return -1;
    if (!smp_checksum(rsdp, 20)) return -1;
    u32 rsdt = smp_read_u32(rsdp + 16);
    if (!rsdt || !smp_sig(rsdt, "RSDT")) return -1;
    u32 rsdt_len = smp_read_u32(rsdt + 4);
    if (rsdt_len < 36 || rsdt_len > 65536) return -1;
    if (!smp_checksum(rsdt, rsdt_len)) return -1;
    u32 madt = 0;
    for (u32 e = 36; e + 4 <= rsdt_len; e += 4) {
        u32 tab = smp_read_u32(rsdt + e);
        if (tab && smp_sig(tab, "APIC")) { madt = tab; break; }
    }
    if (!madt) return -1;
    u32 madt_len = smp_read_u32(madt + 4);
    if (madt_len < 44 || madt_len > 65536) return -1;
    if (!smp_checksum(madt, madt_len)) return -1;
    *base_out = smp_read_u32(madt + 36);
    if (*base_out == 0) return -1;
    int n = 0;
    for (u32 off = 44; off + 2 <= madt_len; ) {
        u8 type = smp_read_byte(madt + off);
        u8 elen = smp_read_byte(madt + off + 1);
        if (elen < 2) break;
        if (type == 0 && elen >= 8) {
            u32 flags = smp_read_u32(madt + off + 4);
            if ((flags & 1u) && n < max_ids) ids[n++] = smp_read_byte(madt + off + 3);
        }
        off += elen;
    }
    *n_out = n;
    return n > 0 ? 0 : -1;
}

/* ---- BSP helpers ---- */
static void smp_delay_ticks(u32 n) {
    u32 start = timer_ticks;
    while (timer_ticks - start < n) __asm__ volatile ("hlt");
}

/* Calibrate the LAPIC timer against the PIT: one-shot max count,
   masked (no interrupt — only the current-count register is
   read), 100 ms of PIT ticks, then stop. Returns ticks per
   10 ms, or 0 if nothing counted (AP timer stays off). */
static u32 lapic_calibrate(void) {
    lapic_write(LAPIC_TIMER_DIV, 0x0Bu); /* divide by 1 */
    lapic_write(LAPIC_LVT_TIMER, 0x10000u | LAPIC_VEC_TIMER); /* masked, one-shot */
    lapic_write(LAPIC_TIMER_INIT, 0xFFFFFFFFu);
    smp_delay_ticks(10); /* 100 ms at 100 Hz */
    u32 cur = lapic_read(LAPIC_TIMER_CUR);
    lapic_write(LAPIC_TIMER_INIT, 0);
    lapic_write(LAPIC_LVT_TIMER, 0x10000u);
    u32 delta = 0xFFFFFFFFu - cur;
    if (delta < 1000) return 0;
    return delta / 10;
}

static void tramp_write16(u32 off, u16 v) {
    *(volatile u16 *)(TRAMP_ADDR + off) = v;
}
static void tramp_write32(u32 off, u32 v) {
    *(volatile u32 *)(TRAMP_ADDR + off) = v;
}

void smp_init(void) {
    u8 ids[8];
    int n_ids = 0;
    u32 base = 0;
    if (madt_parse(&base, ids, 8, &n_ids) != 0) {
        console_write("SMP: no MADT, uniprocessor\n");
        return;
    }
    /* Map the LAPIC page BEFORE publishing lapic_base: the PIT
       IRQ handler calls smp_cpu_index() on every tick, and it
       dereferences lapic_base + 0x20 whenever lapic_base is
       nonzero. Publishing first left a window where a tick
       landing between the store and the mapping faulted on the
       unmapped page (seen live 2026-11-02: repo_httpsa good
       boot panicked with PAGE FAULT at 0xFEE00020 from
       smp_cpu_index, before any "SMP:" line). With map-first,
       a tick in the window sees lapic_base == 0 and returns 0
       safely, and after the store the mapping already exists.
       (vmm_map_page itself is safe in the window: any console
       output it triggers also sees lapic_base == 0.) */
    vmm_map_page(vmm_kernel_pd(), base, base, PAGE_RW);
    __asm__ volatile ("invlpg (%0)" :: "r"(base) : "memory");
    lapic_base = base;
    lapic_enable();
    bsp_lapic_id = lapic_read(LAPIC_ID) >> 24;
    if (n_ids <= 1) {
        console_printf("SMP: 1 CPU (LAPIC base 0x%x, BSP id %u), uniprocessor\n",
                       lapic_base, bsp_lapic_id);
        return;
    }
    /* First non-BSP enabled CPU is the AP. Any further CPUs are
       left parked and never reported. */
    ap_lapic_id = 0xFFFFFFFFu;
    for (int i = 0; i < n_ids; i++) {
        if (ids[i] != bsp_lapic_id) { ap_lapic_id = ids[i]; break; }
    }
    if (ap_lapic_id == 0xFFFFFFFFu) {
        console_write("SMP: MADT lists no second CPU, uniprocessor\n");
        return;
    }
    ap_present = 1;
    ap_ticks_per_10ms = lapic_calibrate();
    console_printf("SMP: LAPIC base 0x%x, BSP id %u, AP id %u, LAPIC timer %u ticks/10ms\n",
                   lapic_base, bsp_lapic_id, ap_lapic_id, ap_ticks_per_10ms);
    /* Copy the trampoline to low memory and patch its slots. */
    u32 blob_size = (u32)(tramp_blob_end - tramp_blob);
    memcpy((void *)TRAMP_ADDR, tramp_blob, blob_size);
    u16 gdt_lim = 0; u32 gdt_base = 0;
    gdt_ptr_values(&gdt_lim, &gdt_base);
    u16 idt_lim = 0; u32 idt_base = 0;
    idt_ptr_values(&idt_lim, &idt_base);
    tramp_write16(TRAMP_SLOT_GDT, gdt_lim);
    tramp_write32(TRAMP_SLOT_GDT + 2, gdt_base);
    tramp_write16(TRAMP_SLOT_IDT, idt_lim);
    tramp_write32(TRAMP_SLOT_IDT + 2, idt_base);
    tramp_write32(TRAMP_SLOT_STACK, (u32)&ap_stack[16384]);
    tramp_write32(TRAMP_SLOT_PD, vmm_kernel_pd());
    tramp_write32(TRAMP_SLOT_ENTRY, (u32)ap_main);
    /* INIT-SIPI sequence (Intel MP spec): INIT assert, 10 ms,
       INIT deassert, SIPI, SIPI. */
    ap_state_v = 1;
    lapic_send_ipi(ap_lapic_id, 0x0000C500u); /* INIT assert */
    smp_delay_ticks(2);
    lapic_send_ipi(ap_lapic_id, 0x00008500u); /* INIT deassert */
    smp_delay_ticks(1);
    lapic_send_ipi(ap_lapic_id, 0x00004600u | (TRAMP_ADDR >> 12)); /* SIPI */
    smp_delay_ticks(1);
    lapic_send_ipi(ap_lapic_id, 0x00004600u | (TRAMP_ADDR >> 12)); /* SIPI again */
    u32 start = timer_ticks;
    while (ap_state_v != 2 && timer_ticks - start < 200)
        __asm__ volatile ("hlt");
    if (ap_state_v == 2) {
        ap_online_v = 1;
        console_printf("SMP: AP online (id %u), 2 CPUs\n", ap_lapic_id);
    } else {
        console_printf("SMP: AP failed to start (timeout), continuing uniprocessor\n");
    }
}

/* ---- shootdown ---- */
int smp_tlb_shootdown(u32 virt) {
    if (!ap_online_v) return 0;
    shootdown_ack = 0;
    shootdown_addr = virt;
    __asm__ volatile ("" ::: "memory");
    lapic_send_ipi(ap_lapic_id, 0x00004000u | LAPIC_VEC_SHOOTDOWN);
    shootdowns_sent++;
    u32 start = timer_ticks;
    while (!shootdown_ack && timer_ticks - start < 100)
        __asm__ volatile ("hlt");
    if (shootdown_ack) shootdowns_acked++;
    return shootdown_ack ? 1 : 0;
}

void lapic_irq_handler(struct regs *r) {
    u32 vec = r->int_no;
    if (vec == LAPIC_VEC_TIMER) {
        lapic_eoi();
        ap_timer_tick(r);
    } else if (vec == LAPIC_VEC_SHOOTDOWN) {
        __asm__ volatile ("invlpg (%0)" :: "r"(shootdown_addr) : "memory");
        shootdown_ack = 1;
        lapic_eoi();
    }
    /* 255 spurious: no EOI, nothing to do. */
}

/* ---- AP work dispatch ---- */
static void ap_work_dispatch(void) {
    int cmd = ap_work_cmd;
    if (cmd == AP_WORK_NONE) return;
    if (cmd == AP_WORK_LOCKTEST) {
        for (u32 i = 0; i < ap_work_n; i++) {
            u32 f = spin_lock_irqsave(&test_lock);
            locktest_counter++;
            spin_unlock_irqrestore(&test_lock, f);
        }
    } else if (cmd == AP_WORK_PMMTEST) {
        for (int i = 0; i < 32; i++) ap_pmm_addrs[i] = pmm_alloc_frame();
    }
    ap_work_cmd = AP_WORK_NONE;
    ap_work_done = 1;
}

static void ap_probe_step(void) {
    if (ap_tlb_mode != 1) return;
    if (smp_tlb_probe_faulted) { ap_probe_done = 1; return; }
    /* Fixed 2-byte instruction (mov (%eax), %ebx = 8B 18): the
       fault handler recognises exactly these bytes before it
       skips the instruction, so this must never be rewritten
       as a C dereference (the compiler could pick any form). */
    __asm__ volatile ("movl (%%eax), %%ebx"
                      :: "a"(SMP_TLB_TEST_VIRT) : "ebx", "memory");
    ap_probe_reads++;
}

void ap_main(void) {
    /* Trampoline state: AP stack, kernel PD, real GDT/IDT loaded,
       interrupts off. Enable the local APIC and take the AP TSS
       before anything can interrupt or syscall. AP variant: LINT0
       masked, so the 8259 never interrupts the AP (see above). */
    lapic_enable_ap();
    __asm__ volatile ("ltr %0" :: "m"(ap_tr_sel));
    ap_state_v = 2; /* readiness signal: the BSP may now use the AP */
    if (ap_ticks_per_10ms != 0) {
        lapic_write(LAPIC_TIMER_DIV, 0x0Bu);
        lapic_write(LAPIC_LVT_TIMER, 0x20000u | LAPIC_VEC_TIMER); /* periodic */
        lapic_write(LAPIC_TIMER_INIT, ap_ticks_per_10ms);
    }
    /* If the timer could not be calibrated, the loop below must
       not hlt (nothing would wake it): it spins on pause instead.
       Jobs still run; only the idle power saving is lost. */
    __asm__ volatile ("sti");
    for (;;) {
        ap_work_dispatch();
        ap_probe_step();
        ap_sched_tick();
        if (ap_ticks_per_10ms != 0) __asm__ volatile ("hlt");
        else __asm__ volatile ("pause");
    }
}

/* ---- shell-driven proofs ---- */
static int wait_flag(volatile int *flag, int want, u32 ticks) {
    u32 start = timer_ticks;
    while (*flag != want && timer_ticks - start < ticks)
        __asm__ volatile ("hlt");
    return *flag == want;
}

int smp_locktest(u32 n, u32 *counter_out) {
    if (!ap_online_v) return -1;
    if (ap_work_cmd != AP_WORK_NONE) return -2;
    locktest_counter = 0;
    ap_work_n = n;
    ap_work_done = 0;
    ap_work_cmd = AP_WORK_LOCKTEST;
    for (u32 i = 0; i < n; i++) {
        u32 f = spin_lock_irqsave(&test_lock);
        locktest_counter++;
        spin_unlock_irqrestore(&test_lock, f);
    }
    if (!wait_flag(&ap_work_done, 1, 1000)) return -2;
    if (counter_out) *counter_out = locktest_counter;
    return locktest_counter == 2 * n ? 0 : -3;
}

int smp_pmmtest(u32 *free_before_out, u32 *free_after_out, int *disjoint_out) {
    if (!ap_online_v) return -1;
    if (ap_work_cmd != AP_WORK_NONE) return -2;
    u32 baseline = pmm_free_frames();
    for (int i = 0; i < 32; i++) ap_pmm_addrs[i] = 0;
    ap_work_done = 0;
    ap_work_cmd = AP_WORK_PMMTEST;
    if (!wait_flag(&ap_work_done, 1, 1000)) return -2;
    for (int i = 0; i < 32; i++) bsp_pmm_addrs[i] = pmm_alloc_frame();
    int disjoint = 1;
    for (int i = 0; i < 32 && disjoint; i++) {
        if (ap_pmm_addrs[i] == 0 || bsp_pmm_addrs[i] == 0) { disjoint = 0; break; }
        for (int j = 0; j < 32; j++)
            if (ap_pmm_addrs[i] == bsp_pmm_addrs[j]) { disjoint = 0; break; }
        for (int j = i + 1; j < 32; j++)
            if (bsp_pmm_addrs[i] == bsp_pmm_addrs[j]) { disjoint = 0; break; }
        for (int j = i + 1; j < 32; j++)
            if (ap_pmm_addrs[i] == ap_pmm_addrs[j]) { disjoint = 0; break; }
    }
    /* Free everything (BSP frees the AP's frames too — the PMM
       is CPU-agnostic, only its lock is per-access). */
    for (int i = 0; i < 32; i++) {
        if (ap_pmm_addrs[i]) pmm_free_frame(ap_pmm_addrs[i]);
        if (bsp_pmm_addrs[i]) pmm_free_frame(bsp_pmm_addrs[i]);
    }
    if (free_before_out) *free_before_out = baseline;
    if (free_after_out) *free_after_out = pmm_free_frames();
    if (disjoint_out) *disjoint_out = disjoint;
    if (!disjoint) return -3;
    return pmm_free_frames() == baseline ? 0 : -4;
}

int smp_tlb_proof(struct smp_tlb_result *res) {
    if (!ap_online_v) return -1;
    if (ap_tlb_mode != 0) return -2;
    u32 frame = pmm_alloc_frame();
    if (frame == 0) return -2;
    vmm_map_page(vmm_kernel_pd(), SMP_TLB_TEST_VIRT, frame, PAGE_RW);
    *(volatile u32 *)SMP_TLB_TEST_VIRT = 0x544C4254u;
    ap_probe_reads = 0;
    smp_tlb_probe_faulted = 0;
    ap_probe_done = 0;
    smp_tlb_probe_active = 1;
    ap_tlb_mode = 1;
    /* Wait until the AP has the translation cached (>= 50 reads). */
    {
        u32 start = timer_ticks;
        while (ap_probe_reads < 50 && timer_ticks - start < 500)
            __asm__ volatile ("hlt");
        if (ap_probe_reads < 50) goto fail_setup;
    }
    /* Unmap on the BSP only (own TLB invalidated, AP's left stale). */
    vmm_unmap_page(vmm_kernel_pd(), SMP_TLB_TEST_VIRT);
    __asm__ volatile ("invlpg (%0)" :: "r"(SMP_TLB_TEST_VIRT) : "memory");
    res->stale_before = ap_probe_reads;
    smp_delay_ticks(30); /* ~300 ms: the AP keeps reading via its stale TLB */
    res->stale_after = ap_probe_reads;
    res->ack = smp_tlb_shootdown(SMP_TLB_TEST_VIRT);
    {
        u32 start = timer_ticks;
        while (!ap_probe_done && timer_ticks - start < 500)
            __asm__ volatile ("hlt");
    }
    res->fault = smp_tlb_probe_faulted;
    ap_tlb_mode = 0;
    smp_tlb_probe_active = 0;
    pmm_free_frame(frame);
    if (res->stale_after > res->stale_before && res->fault && res->ack) return 0;
    return 1;
fail_setup:
    ap_tlb_mode = 0;
    smp_tlb_probe_active = 0;
    vmm_unmap_page(vmm_kernel_pd(), SMP_TLB_TEST_VIRT);
    __asm__ volatile ("invlpg (%0)" :: "r"(SMP_TLB_TEST_VIRT) : "memory");
    pmm_free_frame(frame);
    return -2;
}
