#include "proc.h"
#include "caps.h"
#include "fd.h"
#include "../drivers/keyboard.h"
#include "elf.h"
#include "console.h"
#include "spinlock.h"
#include "smp.h"
#include "../mm/vmm.h"
#include "../drivers/gdt.h"
#include "../drivers/pit.h"
#include "../mm/pmm.h"
#include "../drivers/serial.h"

extern const u8 user_prog_blob[];
extern const u8 user_prog_blob_end[];

struct proc *current_proc = 0;
struct proc procs[MAX_PROCS];
int proc_count = 0;

/* Deep-core phase D2: live-proc registry for pipe/lock
   wakeup scans (fd.c). Boot procs + bg jobs + the foreground
   exec proc; unregistered at every teardown site. */
static struct proc *live_procs[16];
static int live_count = 0;
static void live_add(struct proc *p) {
    for (int i = 0; i < live_count; i++)
        if (live_procs[i] == p) return;
    if (live_count < 16) live_procs[live_count++] = p;
}
static void live_remove(struct proc *p) {
    for (int i = 0; i < live_count; i++) {
        if (live_procs[i] != p) continue;
        for (int j = i + 1; j < live_count; j++) live_procs[j - 1] = live_procs[j];
        live_count--;
        return;
    }
}
int proc_live_list(struct proc **out, int max) {
    int n = live_count < max ? live_count : max;
    for (int i = 0; i < n; i++) out[i] = live_procs[i];
    return n;
}

/* Switch globals, read by switch.S. */
u32 sw_pd, sw_eip, sw_esp, sw_eflags, sw_kernel_stack_top;
u32 sw_edi, sw_esi, sw_ebp, sw_ebx, sw_edx, sw_ecx, sw_eax;
u32 sched_esp, sched_ebp, sched_ebx, sched_esi, sched_edi;
/* SMP (redesign 4): the AP's own switch globals + current proc.
   The BSP and AP must never share these: both CPUs can be
   inside switch_to_user_asm at once, and shared globals would
   hand each CPU the other's page directory and registers. */
u32 ap_sw_pd, ap_sw_eip, ap_sw_esp, ap_sw_eflags, ap_sw_kernel_stack_top;
u32 ap_sw_edi, ap_sw_esi, ap_sw_ebp, ap_sw_ebx, ap_sw_edx, ap_sw_ecx, ap_sw_eax;
u32 ap_sched_esp, ap_sched_ebp, ap_sched_ebx, ap_sched_esi, ap_sched_edi;
struct proc *current_proc_ap = 0;
static u32 ap_ticks = 0, ap_last_preempt = 0;
static u32 ap_runs_total = 0, ap_done_total = 0;

struct proc *proc_current_for_cpu(void) {
    if (smp_cpu_index() == 1) return current_proc_ap;
    return current_proc;
}
void sched_switch_current(void) {
    if (smp_cpu_index() == 1) sched_switch_asm_ap();
    else sched_switch_asm();
}
void proc_ap_stats(u32 *runs_out, u32 *done_out) {
    if (runs_out) *runs_out = ap_runs_total;
    if (done_out) *done_out = ap_done_total;
}

static u8 kernel_stacks[MAX_PROCS][8192];

void proc_save_from_regs(struct proc *p, struct regs *r) {
    p->eip = r->eip; p->esp = r->useresp; p->eflags = r->eflags;
    p->edi = r->edi; p->esi = r->esi; p->ebp = r->ebp;
    p->ebx = r->ebx; p->edx = r->edx; p->ecx = r->ecx; p->eax = r->eax;
}

static void run_process(struct proc *p) {
    sw_pd = p->pd; sw_eip = p->eip; sw_esp = p->esp; sw_eflags = p->eflags;
    sw_kernel_stack_top = p->kernel_stack_top;
    sw_edi = p->edi; sw_esi = p->esi; sw_ebp = p->ebp;
    sw_ebx = p->ebx; sw_edx = p->edx; sw_ecx = p->ecx; sw_eax = p->eax;
    tss_set_esp0(p->kernel_stack_top);
    p->state = PROC_RUNNING;
    current_proc = p;
    switch_to_user_asm();
    /* Reached only via sched_switch_asm (yield, exit, or timer preempt).
       Interrupt entry cleared IF and the stack switch never restores it,
       so without this the scheduler — and the shell after it — would run
       with interrupts off and never see another timer/keyboard IRQ. */
    current_proc = 0;
    /* CRITICAL: sched_switch_asm restores the scheduler's registers and
       stack but NOT CR3, so without this the scheduler keeps running
       with the just-run process's user page directory. User PDs share
       only PD entries 0-7 (kernel 0-32 MB) and 256 (framebuffer) —
       NOT entry 260 (0x41000000, e1000 MMIO). The first network send
       after a background-job tick therefore page-faulted on the MMIO
       read in net_send (v1.1.2 Virt-Manager report: EXCEPTION 14,
       eip in net_send, PAGE FAULT at 0x41003810). Kernel/scheduler
       code must always run with the kernel PD; user code runs with
       its own PD only between switch_to_user_asm and the next
       sched_switch. One CR3 reload per job tick (TLB flush) is the
       price, and it is negligible here. */
    vmm_enable_paging(vmm_kernel_pd());
    __asm__ volatile ("sti");
}

/* AP twin of run_process (redesign 4): same contract, but the
   AP's switch globals, the AP TSS, and current_proc_ap. The
   kernel-PD restore + sti on return are identical — the AP
   scheduler, like the BSP's, must always run with the kernel
   PD (a user PD lacks nothing the AP needs, but the LAPIC
   page is the only shared MMIO entry, and scheduler code
   must never depend on which user PD happens to be active). */
static void run_process_ap(struct proc *p) {
    ap_sw_pd = p->pd; ap_sw_eip = p->eip; ap_sw_esp = p->esp; ap_sw_eflags = p->eflags;
    ap_sw_kernel_stack_top = p->kernel_stack_top;
    ap_sw_edi = p->edi; ap_sw_esi = p->esi; ap_sw_ebp = p->ebp;
    ap_sw_ebx = p->ebx; ap_sw_edx = p->edx; ap_sw_ecx = p->ecx; ap_sw_eax = p->eax;
    tss_set_esp0_ap(p->kernel_stack_top);
    p->state = PROC_RUNNING;
    current_proc_ap = p;
    switch_to_user_asm_ap();
    current_proc_ap = 0;
    vmm_enable_paging(vmm_kernel_pd());
    __asm__ volatile ("sti");
}

void ap_timer_tick(struct regs *r) {
    ap_ticks++;
    timer_maybe_preempt_ap(r);
}

void timer_maybe_preempt_ap(struct regs *r) {
    if (current_proc_ap == 0) return;
    /* SMP guard (permanent): the AP preempt path runs only on the
       AP; a stray IRQ0 on the BSP must never touch AP job state. */
    if (smp_cpu_index() != 1) return;
    if (r->cs != 0x1B) return; /* only preempt code running in user mode */
    if (ap_ticks - ap_last_preempt < 10) return; /* 100 ms quantum */
    ap_last_preempt = ap_ticks;
    proc_save_from_regs(current_proc_ap, r);
    current_proc_ap->state = PROC_READY;
    sched_switch_asm_ap(); /* noreturn */
}

static u8 exec_kernel_stack[8192];

/* Background jobs. Each slot has its own kernel stack, so a job's
   ring-0 stack is never shared with the shell's exec stack. A job is
   READY when the shell is running; RUNNING only while run_process()
   is inside it. Timer preemption and yield both return to the caller
   (shell idle loop) with state READY, so the shell stays responsive. */
/* Redesign 5 (CORE_CLI.md section 15.4): vruntime runqueue. Each
   job carries vruntime (scaled virtual time) and a nice weight;
   a tick runs only jobs within SCHED_SLICE of the tick's minimum
   vruntime, so a high-nice job falls behind its fair share and
   skips ticks until the minimum catches up. This replaces the
   old ad-hoc rule (negative nice = 2 runs, nice >= 10 = every
   2nd tick) with the same 100 ms tick underneath. vruntime is
   a u32 (no u64 division anywhere: the increment is a 32-bit
   divide, 1048576 / weight). */
struct bg_job { struct proc p; char name[32]; int used; u8 stack[8192]; int nice; u32 vruntime; u32 weight; u32 runs; u32 pending_sig; int cpu; int pending_cpu; };
static struct bg_job bg_jobs[MAX_BG];
/* SMP (redesign 4): the job table + reap table are shared by
   both CPUs (BSP shell vs AP scheduler loop), so every table
   scan and mutation runs under bg_lock. The lock is NEVER held
   across run_process (a job runs for a whole quantum), across
   a print (prints use copied info, after unlock), or across a
   hlt-wait. Lock order: bg_lock -> pmm_lock (teardown frees
   page directories under bg_lock). */
static spinlock_t bg_lock = SPINLOCK_INIT;

/* Linux CFS weight table (nice -20..19), used verbatim as the
   vruntime scale: increment = 1048576 / weight, so nice 0
   advances 1024 per quantum, nice 10 advances 9532, and
   nice 19 advances 69905. File-scope const, never on a stack. */
static const u32 sched_weights[40] = {
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14954, 11996,
    9548, 7620, 6100, 4904, 3906, 3121, 2501, 1991, 1586, 1277,
    1024, 820, 655, 526, 423, 335, 272, 215, 172, 137,
    110, 87, 70, 56, 45, 36, 29, 23, 18, 15
};
static u32 sched_weight(int nice) {
    if (nice < -20) nice = -20;
    if (nice > 19) nice = 19;
    return sched_weights[nice + 20];
}
/* vruntime eligibility window per tick (scaled units): a job
   runs only while its vruntime is within this of the tick's
   minimum vruntime over READY jobs on its CPU. */
#define SCHED_SLICE 4096u

/* Session capability mask new processes inherit (published
   by the shell at login/su/cap change; default all set until
   the shell publishes, so pre-login paths are unaffected). */
static u32 proc_session_caps = CAP_ALL;
void proc_set_session_caps(u32 caps) { proc_session_caps = caps; }
int proc_bg_caps(u32 pid, u32 *caps_out) {
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used || bg_jobs[i].p.pid != pid) continue;
        if (caps_out) *caps_out = bg_jobs[i].p.caps;
        spin_unlock_irqrestore(&bg_lock, f);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}
int proc_bg_vruntime(u32 pid, u32 *vruntime_out, u32 *weight_out, u32 *runs_out) {
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used || bg_jobs[i].p.pid != pid) continue;
        if (vruntime_out) *vruntime_out = bg_jobs[i].vruntime;
        if (weight_out) *weight_out = bg_jobs[i].weight;
        if (runs_out) *runs_out = bg_jobs[i].runs;
        spin_unlock_irqrestore(&bg_lock, f);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}
/* Snapshot one CPU's READY jobs in vruntime order (small
   stack-local output: at most MAX_BG picks). The caller
   re-validates each pick under bg_lock before running it;
   vruntime of a pick only changes when that pick runs, so
   the snapshot's vruntime stays valid for eligibility. */
static int sched_snapshot(int cpu, int *order, u32 *order_vr, u32 *min_out) {
    int picks[4];
    u32 vrs[4];
    int n = 0;
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used || bg_jobs[i].cpu != cpu || bg_jobs[i].p.state != PROC_READY) continue;
        picks[n] = i; vrs[n] = bg_jobs[i].vruntime; n++;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    for (int a = 0; a < n; a++)
        for (int b = a + 1; b < n; b++)
            if (vrs[b] < vrs[a]) {
                int ti = picks[a]; picks[a] = picks[b]; picks[b] = ti;
                u32 tv = vrs[a]; vrs[a] = vrs[b]; vrs[b] = tv;
            }
    for (int i = 0; i < n; i++) { order[i] = picks[i]; order_vr[i] = vrs[i]; }
    if (min_out) *min_out = (n > 0) ? vrs[0] : 0;
    return n;
}


/* Teardown of one slot, caller MUST hold bg_lock. Frees the
   fds, the live-registry entry, and the page directory, then
   clears `used` — so a slot is never reused while its old
   address space is still being freed. No prints inside. */
static void bg_teardown_locked(int i) {
    fd_close_all(&bg_jobs[i].p);
    live_remove(&bg_jobs[i].p);
    vmm_destroy_pd(bg_jobs[i].p.pd);
    bg_jobs[i].p.pd = 0;
    bg_jobs[i].used = 0;
    bg_jobs[i].pending_sig = 0;
    bg_jobs[i].pending_cpu = -1;
}

static void bg_copy_name(char *dst, const char *src) {
    int j = 0;
    while (src[j] && j < 31) { dst[j] = src[j]; j++; }
    dst[j] = 0;
}

/* Signal delivery for one CPU's jobs (redesign 4): the BSP tick
   delivers for cpu==0, the AP tick for cpu==1 — a CPU never
   frees a job the other CPU might be running. Termination
   frees the slot under bg_lock and prints afterwards. */
static void bg_deliver_for_cpu(int cpu) {
    for (int i = 0; i < MAX_BG; i++) {
        u32 f = spin_lock_irqsave(&bg_lock);
        if (!bg_jobs[i].used || bg_jobs[i].cpu != cpu || bg_jobs[i].pending_sig == 0) {
            spin_unlock_irqrestore(&bg_lock, f);
            continue;
        }
        u32 sig = bg_jobs[i].pending_sig;
        bg_jobs[i].pending_sig = 0;
        if (sig == 19) {
            if (bg_jobs[i].p.state != PROC_READY) { spin_unlock_irqrestore(&bg_lock, f); continue; }
            bg_jobs[i].p.state = PROC_STOPPED;
            char nm[32]; u32 pid = bg_jobs[i].p.pid;
            bg_copy_name(nm, bg_jobs[i].name);
            spin_unlock_irqrestore(&bg_lock, f);
            console_printf("\nBackground job %s (pid %u) stopped\n", nm, pid);
        } else if (sig == 18) {
            if (bg_jobs[i].p.state != PROC_STOPPED) { spin_unlock_irqrestore(&bg_lock, f); continue; }
            bg_jobs[i].p.state = PROC_READY;
            char nm[32]; u32 pid = bg_jobs[i].p.pid;
            bg_copy_name(nm, bg_jobs[i].name);
            spin_unlock_irqrestore(&bg_lock, f);
            console_printf("\nBackground job %s (pid %u) continued\n", nm, pid);
        } else { /* 1 HUP, 2 INT, 9 KILL, 15 TERM: terminate */
            char nm[32]; u32 pid = bg_jobs[i].p.pid;
            bg_copy_name(nm, bg_jobs[i].name);
            bg_teardown_locked(i);
            spin_unlock_irqrestore(&bg_lock, f);
            console_printf("\nBackground job %s (pid %u) terminated by signal %u\n", nm, pid, sig);
        }
    }
}

/* Exit-status reap table (deep-core phase): 4 entries, oldest
   overwritten when full. Filled by proc_bg_tick on job exit;
   consumed by wait/fg via proc_reap_take. */
struct reap_entry { int used; u32 pid; char name[32]; u32 uid; u32 code; u32 seq; };
static struct reap_entry reap_table[4];
static u32 reap_seq = 0;

static void reap_store(u32 pid, const char *name, u32 uid, u32 code) {
    int slot = -1;
    for (int i = 0; i < 4; i++) if (!reap_table[i].used) { slot = i; break; }
    if (slot < 0) {
        /* Full: overwrite the oldest entry. */
        slot = 0;
        for (int i = 1; i < 4; i++)
            if (reap_table[i].seq < reap_table[slot].seq) slot = i;
    }
    reap_table[slot].used = 1;
    reap_table[slot].pid = pid;
    reap_table[slot].uid = uid;
    reap_table[slot].code = code;
    reap_table[slot].seq = reap_seq++;
    int j = 0;
    while (name[j] && j < 31) { reap_table[slot].name[j] = name[j]; j++; }
    reap_table[slot].name[j] = 0;
}

int proc_reap_take(u32 pid, u32 uid, u32 *code_out) {
    /* The reap table is shared by both CPUs' ticks (reap_store
       runs under bg_lock), so take it under the same lock. */
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < 4; i++) {
        if (!reap_table[i].used || reap_table[i].pid != pid) continue;
        if (uid != 0 && reap_table[i].uid != uid) { spin_unlock_irqrestore(&bg_lock, f); return -1; }
        if (code_out) *code_out = reap_table[i].code;
        reap_table[i].used = 0;
        spin_unlock_irqrestore(&bg_lock, f);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}

int proc_bg_signal(u32 pid, u32 uid, int sig) {
    if (sig != 1 && sig != 2 && sig != 9 && sig != 15 && sig != 18 && sig != 19) return -2;
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used || bg_jobs[i].p.pid != pid) continue;
        if (uid != 0 && bg_jobs[i].p.uid != uid) { spin_unlock_irqrestore(&bg_lock, f); return -1; }
        bg_jobs[i].pending_sig = (u32)sig;
        spin_unlock_irqrestore(&bg_lock, f);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}

int proc_bg_count(void) {
    u32 f = spin_lock_irqsave(&bg_lock);
    int n = 0;
    for (int i = 0; i < MAX_BG; i++) if (bg_jobs[i].used) n++;
    spin_unlock_irqrestore(&bg_lock, f);
    return n;
}
int proc_bg_start_nice(const char *name, u32 uid, int nice) {
    if (nice < -20) nice = -20;
    if (nice > 19) nice = 19;
    /* Find a free slot first (BSP-only start, but the publish
       below still takes the lock: the AP tick scans this table
       and must never see a half-published job). The ELF load
       runs BEFORE the lock: file IO under bg_lock would nest
       the filesystem under the job table for no benefit. */
    int slot = -1;
    {
        u32 f = spin_lock_irqsave(&bg_lock);
        for (int i = 0; i < MAX_BG; i++)
            if (!bg_jobs[i].used) { slot = i; break; }
        spin_unlock_irqrestore(&bg_lock, f);
    }
    if (slot < 0) return -1; /* job table full */
    if (elf_create_proc(name, uid, &bg_jobs[slot].p) != 0) return -1;
    bg_jobs[slot].p.pid = 10u + (u32)slot;
    bg_jobs[slot].p.caps = proc_session_caps;
    bg_jobs[slot].p.kernel_stack_top = (u32)&bg_jobs[slot].stack[8192];
    {
        u32 f = spin_lock_irqsave(&bg_lock);
        memset(bg_jobs[slot].name, 0, sizeof(bg_jobs[slot].name));
        bg_copy_name(bg_jobs[slot].name, name);
        bg_jobs[slot].nice = nice;
        bg_jobs[slot].weight = sched_weight(nice);
        /* A new job starts at the current minimum vruntime
           (CFS behaviour): it neither jumps the queue nor
           starves waiting for others to catch up from 0. */
        {
            u32 mn = 0; int any = 0;
            for (int k = 0; k < MAX_BG; k++) {
                if (!bg_jobs[k].used) continue;
                if (!any || bg_jobs[k].vruntime < mn) mn = bg_jobs[k].vruntime;
                any = 1;
            }
            bg_jobs[slot].vruntime = any ? mn : 0;
        }
        bg_jobs[slot].runs = 0;
        bg_jobs[slot].pending_sig = 0;
        bg_jobs[slot].cpu = 0; /* new jobs start on the BSP */
        bg_jobs[slot].pending_cpu = -1;
        bg_jobs[slot].used = 1; /* publish last */
        spin_unlock_irqrestore(&bg_lock, f);
    }
    live_add(&bg_jobs[slot].p);
    console_printf("Background job %s started (pid %u, uid %u)\n",
                   bg_jobs[slot].name, bg_jobs[slot].p.pid, uid);
    return 0;
}
int proc_bg_start(const char *name, u32 uid) {
    return proc_bg_start_nice(name, uid, 0);
}
int proc_bg_set_nice(u32 pid, u32 uid, int nice) {
    if (nice < -20 || nice > 19) return -1;
    if (nice < 0 && uid != 0) return -2; /* raising priority needs root */
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used || bg_jobs[i].p.pid != pid) continue;
        if (uid != 0 && bg_jobs[i].p.uid != uid) { spin_unlock_irqrestore(&bg_lock, f); return -1; }
        bg_jobs[i].nice = nice;
        bg_jobs[i].weight = sched_weight(nice);
        spin_unlock_irqrestore(&bg_lock, f);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}
int proc_bg_get_nice(u32 pid, int *nice_out, u32 *runs_out) {
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used || bg_jobs[i].p.pid != pid) continue;
        if (nice_out) *nice_out = bg_jobs[i].nice;
        if (runs_out) *runs_out = bg_jobs[i].runs;
        spin_unlock_irqrestore(&bg_lock, f);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}
int proc_bg_info(int n, char *name_out, u32 *pid_out, u32 *uid_out, int *nice_out, u32 *runs_out) {
    u32 f = spin_lock_irqsave(&bg_lock);
    int seen = 0;
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used) continue;
        if (seen++ != n) continue;
        if (name_out) bg_copy_name(name_out, bg_jobs[i].name);
        if (pid_out) *pid_out = bg_jobs[i].p.pid;
        if (uid_out) *uid_out = bg_jobs[i].p.uid;
        if (nice_out) *nice_out = bg_jobs[i].nice;
        if (runs_out) *runs_out = bg_jobs[i].runs;
        spin_unlock_irqrestore(&bg_lock, f);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}
/* SMP affinity accessors (redesign 4). */
int proc_bg_cpu(u32 pid, int *cpu_out, int *pending_out) {
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used || bg_jobs[i].p.pid != pid) continue;
        if (cpu_out) *cpu_out = bg_jobs[i].cpu;
        if (pending_out) *pending_out = bg_jobs[i].pending_cpu;
        spin_unlock_irqrestore(&bg_lock, f);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}
int proc_bg_set_cpu(u32 pid, u32 uid, int cpu) {
    if (cpu < 0 || cpu > 1) return -3;
    if (cpu == 1 && !smp_ap_online()) return -2;
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used || bg_jobs[i].p.pid != pid) continue;
        if (uid != 0 && bg_jobs[i].p.uid != uid) { spin_unlock_irqrestore(&bg_lock, f); return -1; }
        /* A READY/STOPPED/BLOCKED job moves at once (its owner
           tick picks it up by the cpu field). A RUNNING job is
           mid-quantum on its current CPU: pend the move and let
           the owning tick apply it at the next READY transition
           — moving it mid-quantum would strand its switch state. */
        if (bg_jobs[i].p.state == PROC_RUNNING) bg_jobs[i].pending_cpu = cpu;
        else { bg_jobs[i].cpu = cpu; bg_jobs[i].pending_cpu = -1; }
        spin_unlock_irqrestore(&bg_lock, f);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}
void proc_bg_tick(void) {
    /* Signal delivery at the tick boundary, before any job runs
       (BSP-owned jobs only — the AP delivers its own). STOPPED
       jobs still receive CONT here (they are skipped by the
       run loop below, not by this pass). */
    bg_deliver_for_cpu(0);
    /* Apply pended affinity moves for READY jobs first, so the
       snapshot below sees the settled CPU assignment. The lock
       is held for the field move only — never across run_process. */
    for (int i = 0; i < MAX_BG; i++) {
        u32 f = spin_lock_irqsave(&bg_lock);
        if (bg_jobs[i].used && bg_jobs[i].p.state == PROC_READY && bg_jobs[i].pending_cpu >= 0) {
            bg_jobs[i].cpu = bg_jobs[i].pending_cpu;
            bg_jobs[i].pending_cpu = -1;
        }
        spin_unlock_irqrestore(&bg_lock, f);
    }
    /* vruntime runqueue (redesign 5): jobs run in vruntime
       order, and only while within one slice of the tick's
       minimum vruntime. A job ahead of its fair share skips
       this tick; its vruntime stands still while the minimum
       advances, so it becomes eligible again on its own. */
    int order[4];
    u32 order_vr[4];
    u32 tick_min = 0;
    int norder = sched_snapshot(0, order, order_vr, &tick_min);
    for (int oi = 0; oi < norder; oi++) {
        int i = order[oi];
        if (order_vr[oi] > tick_min + SCHED_SLICE) continue;
        u32 f = spin_lock_irqsave(&bg_lock);
        int mine = bg_jobs[i].used && bg_jobs[i].cpu == 0 && bg_jobs[i].p.state == PROC_READY;
        spin_unlock_irqrestore(&bg_lock, f);
        if (!mine) continue;
        /* D2: a woken job retries its blocked op before user
           code resumes; if it blocks again, skip the run. */
        if (bg_jobs[i].p.pend.op != PEND_NONE) {
            if (!fd_retry_pending(&bg_jobs[i].p)) continue;
        }
        run_process(&bg_jobs[i].p);
        /* One quantum of virtual time, then reap exactly as
           before (an EXITED job is terminal; the slot could
           have been freed by a concurrent kill between the
           run and this check — reap + teardown exactly once,
           whoever gets there first). */
        char nm[32]; u32 pid = 0; int exited = 0;
        {
            u32 g = spin_lock_irqsave(&bg_lock);
            if (bg_jobs[i].used) {
                bg_jobs[i].vruntime += 1048576u / bg_jobs[i].weight;
                bg_jobs[i].runs++;
            }
            exited = bg_jobs[i].used && bg_jobs[i].p.state == PROC_EXITED;
            if (exited) {
                bg_copy_name(nm, bg_jobs[i].name);
                pid = bg_jobs[i].p.pid;
                reap_store(bg_jobs[i].p.pid, bg_jobs[i].name,
                           bg_jobs[i].p.uid, bg_jobs[i].p.exit_code);
                bg_teardown_locked(i);
            }
            spin_unlock_irqrestore(&bg_lock, g);
        }
        if (exited) {
            console_printf("\nBackground job %s (pid %u) finished\n", nm, pid);
        }
    }
}

/* AP scheduler tick (redesign 4): one runqueue per CPU — the AP
   owns cpu==1 jobs and never touches cpu==0 jobs, and vice
   versa. Work-stealing is explicitly OUT until per-CPU queues
   prove stable. The claim protocol: under bg_lock, a READY
   cpu==1 job is marked RUNNING (reserving it against a
   concurrent BSP kill, which then signals instead of freeing);
   the lock is released before run_process_ap, and the post-run
   state (EXITED -> reap + teardown, READY -> pending affinity
   move, BLOCKED -> left alone) is settled under bg_lock again. */
void ap_sched_tick(void) {
    bg_deliver_for_cpu(1);
    for (int i = 0; i < MAX_BG; i++) {
        u32 f = spin_lock_irqsave(&bg_lock);
        if (bg_jobs[i].used && bg_jobs[i].p.state == PROC_READY && bg_jobs[i].pending_cpu >= 0) {
            bg_jobs[i].cpu = bg_jobs[i].pending_cpu;
            bg_jobs[i].pending_cpu = -1;
        }
        spin_unlock_irqrestore(&bg_lock, f);
    }
    /* vruntime runqueue (redesign 5), same rule as the BSP
       tick: vruntime order, within one slice of the tick
       minimum. The claim protocol is unchanged: under
       bg_lock, a READY cpu==1 job is marked RUNNING
       (reserving it against a concurrent BSP kill, which
       then signals instead of freeing); the lock is released
       before run_process_ap, and the post-run state is
       settled under bg_lock again. */
    int order[4];
    u32 order_vr[4];
    u32 tick_min = 0;
    int norder = sched_snapshot(1, order, order_vr, &tick_min);
    for (int oi = 0; oi < norder; oi++) {
        int i = order[oi];
        if (order_vr[oi] > tick_min + SCHED_SLICE) continue;
        u32 f = spin_lock_irqsave(&bg_lock);
        if (!bg_jobs[i].used || bg_jobs[i].cpu != 1 || bg_jobs[i].p.state != PROC_READY) {
            spin_unlock_irqrestore(&bg_lock, f);
            continue;
        }
        bg_jobs[i].p.state = PROC_RUNNING; /* claim */
        spin_unlock_irqrestore(&bg_lock, f);
        if (bg_jobs[i].p.pend.op != PEND_NONE) {
            if (!fd_retry_pending(&bg_jobs[i].p)) {
                /* Still blocked: fd_retry_pending leaves the
                   state untouched, so the claim must be
                   released back to READY (BSP semantics) or
                   the job would strand as RUNNING forever. */
                u32 g = spin_lock_irqsave(&bg_lock);
                if (bg_jobs[i].used && bg_jobs[i].p.state == PROC_RUNNING)
                    bg_jobs[i].p.state = PROC_READY;
                spin_unlock_irqrestore(&bg_lock, g);
                continue;
            }
        }
        run_process_ap(&bg_jobs[i].p);
        ap_runs_total++;
        bg_jobs[i].runs++;
        char nm[32]; u32 pid = 0; int exited = 0;
        {
            u32 h = spin_lock_irqsave(&bg_lock);
            if (bg_jobs[i].used) bg_jobs[i].vruntime += 1048576u / bg_jobs[i].weight;
            exited = bg_jobs[i].used && bg_jobs[i].p.state == PROC_EXITED;
            if (exited) {
                bg_copy_name(nm, bg_jobs[i].name);
                pid = bg_jobs[i].p.pid;
                reap_store(bg_jobs[i].p.pid, bg_jobs[i].name,
                           bg_jobs[i].p.uid, bg_jobs[i].p.exit_code);
                bg_teardown_locked(i);
            }
            spin_unlock_irqrestore(&bg_lock, h);
        }
        if (exited) {
            ap_done_total++;
            console_printf("\nBackground job %s (pid %u) finished\n", nm, pid);
            continue;
        }
        if (bg_jobs[i].p.state == PROC_BLOCKED) continue;
        /* READY (yield/preempt): apply a pended affinity move
           now, while the job is between quanta. */
        u32 h = spin_lock_irqsave(&bg_lock);
        if (bg_jobs[i].used && bg_jobs[i].p.state == PROC_READY && bg_jobs[i].pending_cpu >= 0) {
            bg_jobs[i].cpu = bg_jobs[i].pending_cpu;
            bg_jobs[i].pending_cpu = -1;
        }
        spin_unlock_irqrestore(&bg_lock, h);
        if (bg_jobs[i].cpu != 1) continue; /* moved away: stop running it here */
    }
}
int proc_bg_exists(u32 pid) {
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < MAX_BG; i++)
        if (bg_jobs[i].used && bg_jobs[i].p.pid == pid) { spin_unlock_irqrestore(&bg_lock, f); return 1; }
    spin_unlock_irqrestore(&bg_lock, f);
    return 0;
}
int proc_bg_at(int n, char *name_out, u32 *pid_out, u32 *uid_out) {
    u32 f = spin_lock_irqsave(&bg_lock);
    int seen = 0;
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used) continue;
        if (seen++ != n) continue;
        if (name_out) bg_copy_name(name_out, bg_jobs[i].name);
        if (pid_out) *pid_out = bg_jobs[i].p.pid;
        if (uid_out) *uid_out = bg_jobs[i].p.uid;
        spin_unlock_irqrestore(&bg_lock, f);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}
int proc_bg_list(void) {
    /* List view (Work D): header + footer count around the pinned
       row format (`pid %u  %s  uid %u`, relied on by tests); the
       zero-case line is preserved verbatim. Snapshot under
       bg_lock, print after: the AP tick can reap jobs while
       this lists, and no print may run under bg_lock. */
    struct { u32 pid; char name[32]; u32 uid; } snap[MAX_BG];
    int n = 0;
    {
        u32 f = spin_lock_irqsave(&bg_lock);
        for (int i = 0; i < MAX_BG; i++) {
            if (!bg_jobs[i].used) continue;
            snap[n].pid = bg_jobs[i].p.pid;
            bg_copy_name(snap[n].name, bg_jobs[i].name);
            snap[n].uid = bg_jobs[i].p.uid;
            n++;
        }
        spin_unlock_irqrestore(&bg_lock, f);
    }
    if (n == 0) { console_write("(no background jobs)\n"); return 0; }
    console_write("PID  NAME  UID\n");
    for (int i = 0; i < n; i++)
        console_printf("pid %u  %s  uid %u\n", snap[i].pid, snap[i].name, snap[i].uid);
    console_printf("(%u background job(s))\n", n);
    return n;
}
int proc_bg_kill(u32 pid, u32 uid) {
    /* A RUNNING job (mid-quantum on either CPU) is never freed
       from here: it gets a TERM signal, delivered at the owning
       tick's boundary. Freeing it mid-quantum would destroy the
       address space its switch state points at. */
    u32 f = spin_lock_irqsave(&bg_lock);
    for (int i = 0; i < MAX_BG; i++) {
        if (!bg_jobs[i].used || bg_jobs[i].p.pid != pid) continue;
        if (uid != 0 && bg_jobs[i].p.uid != uid) { spin_unlock_irqrestore(&bg_lock, f); return -1; } /* not yours */
        if (bg_jobs[i].p.state == PROC_RUNNING) {
            bg_jobs[i].pending_sig = 15;
            spin_unlock_irqrestore(&bg_lock, f);
            console_printf("Kill signalled to background job pid %u (running, terminates at the next tick)\n", pid);
            return 0;
        }
        bg_teardown_locked(i);
        spin_unlock_irqrestore(&bg_lock, f);
        console_printf("Killed background job pid %u\n", pid);
        return 0;
    }
    spin_unlock_irqrestore(&bg_lock, f);
    return -1;
}
int proc_bg_kill_for_uid(u32 uid) {
    int n = 0;
    for (int i = 0; i < MAX_BG; i++) {
        u32 f = spin_lock_irqsave(&bg_lock);
        if (!bg_jobs[i].used || bg_jobs[i].p.uid != uid) { spin_unlock_irqrestore(&bg_lock, f); continue; }
        if (bg_jobs[i].p.state == PROC_RUNNING) {
            bg_jobs[i].pending_sig = 15; /* terminates at its tick */
            spin_unlock_irqrestore(&bg_lock, f);
            n++;
            continue;
        }
        bg_teardown_locked(i);
        spin_unlock_irqrestore(&bg_lock, f);
        n++;
    }
    return n;
}

int proc_exec_file(const char *name, u32 uid) {
    /* Run a single ELF program to completion, in the shell's context.
       Yield/preemption return here with state READY, so loop until
       the program exits; then free its address space. */
    static struct proc exec_proc;
    if (elf_create_proc(name, uid, &exec_proc) != 0) return -1;
    exec_proc.pid = 3;
    exec_proc.caps = proc_session_caps;
    exec_proc.kernel_stack_top = (u32)&exec_kernel_stack[8192];
    live_add(&exec_proc);
    console_printf("Running %s (pid %u, uid %u)...\n", name, exec_proc.pid, uid);
    /* D2: a BLOCKED foreground proc ticks background jobs (its
       FIFO/lock counterpart may be one of them) and retries its
       op; hlt between ticks so this never busy-spins. Any other
       state (EXITED, or STOPPED which signals never set here)
       ends the loop. */
    /* Redesign 5 foreground Ctrl-C: at every loop boundary
       (between quanta, never mid-quantum) peek the type-ahead
       buffer. keyboard_peek never consumes; a Ctrl-C byte is
       consumed only as the signal itself, and every other
       buffered byte survives for the shell (see the test's
       typed-ahead echo). keyboard_poll first picks up a byte
       whose IRQ was lost. */
    int fg_interrupted = 0;
    do {
        keyboard_poll();
        if (keyboard_peek() == 3) {
            (void)keyboard_getchar();
            fg_interrupted = 1;
            break;
        }
        if (keyboard_peek_ctrl_c()) {
            fg_interrupted = 1;
            break;
        }
        if (exec_proc.state == PROC_BLOCKED) {
            proc_bg_tick();
            if (exec_proc.state == PROC_BLOCKED) {
                if (exec_proc.pend.op != PEND_NONE)
                    fd_retry_pending(&exec_proc);
                if (exec_proc.state == PROC_BLOCKED)
                    __asm__ volatile ("hlt");
            }
            continue;
        }
        if (exec_proc.state == PROC_READY) {
            if (exec_proc.pend.op != PEND_NONE) {
                if (!fd_retry_pending(&exec_proc)) continue;
            }
            run_process(&exec_proc);
        }
    } while (exec_proc.state == PROC_READY || exec_proc.state == PROC_BLOCKED);
    u32 fg_code = exec_proc.exit_code;
    fd_close_all(&exec_proc);
    live_remove(&exec_proc);
    vmm_destroy_pd(exec_proc.pd);
    exec_proc.pd = 0;
    if (fg_interrupted) {
        console_printf("\nProgram %s interrupted (SIGINT)\n", name);
        return 0;
    }
    /* Status 0 keeps the exact historical line (tests assert it);
       a non-zero status is appended, never hidden. */
    if (fg_code == 0) console_printf("Program %s finished\n", name);
    else console_printf("Program %s finished (status %u)\n", name, fg_code);
    return 0;
}

void proc_init(void) {
    u32 blob_size = (u32)(user_prog_blob_end - user_prog_blob);
    console_printf("User program blob: %u bytes\n", blob_size);
    for (int i = 0; i < 2; i++) {
        struct proc *p = &procs[proc_count];
        p->pid = (u32)(proc_count + 1);
        p->uid = 0;
        p->state = PROC_READY;
        p->pd = vmm_create_pd();
        p->code_pages = vmm_map_user(p->pd, user_prog_blob, blob_size);
        p->kernel_stack_top = (u32)&kernel_stacks[proc_count][8192];
        p->eip = USER_BASE; p->esp = USER_STACK_TOP; p->eflags = 0x202;
        p->edi = p->esi = p->ebp = p->ebx = p->edx = p->ecx = p->eax = 0;
        live_add(p);
        console_printf("Process %u created: pd=0x%x code_pages=%u\n",
                       p->pid, p->pd, p->code_pages);
        proc_count++;
    }
}

void scheduler_run(void) {
    int remaining;
    do {
        remaining = 0;
        for (int i = 0; i < proc_count; i++) {
            if (procs[i].state == PROC_READY) {
                remaining++;
                run_process(&procs[i]);
            } else if (procs[i].state == PROC_RUNNING) {
                remaining++;
            }
        }
    } while (remaining > 0);
    /* Teardown (fixes the v0.2.0 leak): free each exited process's
       user frames, page tables, and page directory. */
    for (int i = 0; i < proc_count; i++) {
        if (procs[i].state == PROC_EXITED) {
            fd_close_all(&procs[i]);
            live_remove(&procs[i]);
            vmm_destroy_pd(procs[i].pd);
            procs[i].pd = 0;
        }
    }
    console_printf("All user processes finished. PMM used=%u frames\n",
                   pmm_used_frames());
}

void timer_maybe_preempt(struct regs *r) {
    static u32 last_preempt = 0;
    if (current_proc == 0) return;
    /* SMP guard (permanent): the BSP preempt path runs only on the
       BSP. A PIT IRQ0 reaching the AP used to run this path on the
       AP, saving the AP job's registers into the BSP job's struct
       and switching to the BSP scheduler stack on the AP — the
       cross-CPU job-state corruption (see CORE_CLI.md §15.3). */
    if (smp_cpu_index() != 0) return;
    if (r->cs != 0x1B) return; /* only preempt code running in user mode */
    if (timer_ticks - last_preempt < 10) return; /* 100 ms quantum */
    last_preempt = timer_ticks;
    proc_save_from_regs(current_proc, r);
    current_proc->state = PROC_READY;
    sched_switch_asm(); /* noreturn */
}
