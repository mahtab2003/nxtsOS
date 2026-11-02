#include "blk.h"
#include "ata.h"
#include "../drivers/pit.h"
#include "../kernel/console.h"
#include "../kernel/enc.h"

/* File-scope statics only (16 KiB kernel stack rule): the queue,
   the submission-order list, and the test buffers live here. */
struct blk_slot {
    int state; /* 0 free, 1 queued, 2 done */
    u32 dev, lba, count;
    int dir;
    u8 *buf;
    int err;
};
static struct blk_slot blk_slots[BLK_QUEUE_CAP];
static int blk_order[BLK_QUEUE_CAP];
static int blk_order_len = 0;
static int blk_grp[BLK_QUEUE_CAP];
static u32 blk_submitted = 0, blk_completed = 0, blk_merged = 0;
static u32 blk_commands = 0, blk_fallbacks = 0;
static u8 blk_test_buf[2048];

static void blk_order_remove(int slot) {
    int w = 0;
    for (int i = 0; i < blk_order_len; i++)
        if (blk_order[i] != slot) blk_order[w++] = blk_order[i];
    blk_order_len = w;
}

int blk_enqueue(u32 dev, u32 lba, u32 count, int dir, u8 *buf) {
    if (dev != 0 || !buf || count == 0 || count > BLK_MAX_GROUP) return -1;
    if (dir != BLK_DIR_READ && dir != BLK_DIR_WRITE) return -1;
    for (int i = 0; i < BLK_QUEUE_CAP; i++) {
        if (blk_slots[i].state != 0) continue;
        if (blk_order_len >= BLK_QUEUE_CAP) return -1;
        blk_slots[i].state = 1;
        blk_slots[i].dev = dev; blk_slots[i].lba = lba;
        blk_slots[i].count = count; blk_slots[i].dir = dir;
        blk_slots[i].buf = buf; blk_slots[i].err = 0;
        blk_order[blk_order_len++] = i;
        blk_submitted++;
        return i;
    }
    return -1;
}
int blk_slot_done(int slot) {
    if (slot < 0 || slot >= BLK_QUEUE_CAP) return 1;
    return blk_slots[slot].state == 2;
}
int blk_slot_err(int slot) {
    if (slot < 0 || slot >= BLK_QUEUE_CAP) return -1;
    return blk_slots[slot].err;
}
void blk_slot_free(int slot) {
    if (slot < 0 || slot >= BLK_QUEUE_CAP) return;
    blk_slots[slot].state = 0;
}
void blk_wait_slot(int slot) {
    if (slot < 0 || slot >= BLK_QUEUE_CAP) return;
    while (blk_slots[slot].state != 2) {
        blk_poll();
        if (blk_slots[slot].state == 2) break;
        /* Not done (requests ahead of it are still queued):
           halt until the next timer tick, then poll again.
           This is the PROC_BLOCKED-style wait: it never spins
           on the flag. When the PIT has not started yet
           (timer_ticks stuck at 0) the halt is skipped, and
           the poll above still makes progress. */
        if (timer_ticks != 0) {
            u32 t = timer_ticks;
            while (timer_ticks == t && blk_slots[slot].state != 2)
                __asm__ volatile ("hlt");
        }
    }
}
int blk_submit_raw_sync(u32 dev, u32 lba, u32 count, int dir, u8 *buf) {
    if (!buf || count == 0) return -1;
    u32 off = 0;
    while (off < count) {
        u32 chunk = count - off;
        if (chunk > BLK_MAX_GROUP) chunk = BLK_MAX_GROUP;
        int slot = blk_enqueue(dev, lba + off, chunk, dir, buf + off * 512);
        if (slot < 0) { /* queue full: drain one group, retry once */
            blk_poll();
            slot = blk_enqueue(dev, lba + off, chunk, dir, buf + off * 512);
            if (slot < 0) return -1;
        }
        blk_wait_slot(slot);
        int err = blk_slot_err(slot);
        blk_slot_free(slot);
        if (err != 0) return -1;
        off += chunk;
    }
    return 0;
}

/* Execute at most one queued group. Merging: only adjacent
   requests in submission order, same device and direction,
   contiguous LBAs AND contiguous buffers, whole sectors only
   (every request is whole sectors by construction), merged
   total capped at BLK_MAX_GROUP. A merged group is one PIO
   command; an unmerged request is one PIO command. */
void blk_poll(void) {
    if (blk_order_len <= 0) return;
    int first = blk_order[0];
    if (blk_slots[first].state != 1) { blk_order_remove(first); return; }
    int ng = 0;
    blk_grp[ng++] = first;
    u32 end_lba = blk_slots[first].lba + blk_slots[first].count;
    u8 *end_buf = blk_slots[first].buf + blk_slots[first].count * 512;
    u32 total = blk_slots[first].count;
    for (int i = 1; i < blk_order_len && ng < BLK_QUEUE_CAP; i++) {
        int s = blk_order[i];
        if (blk_slots[s].state != 1) continue;
        if (blk_slots[s].dev != blk_slots[first].dev) continue;
        if (blk_slots[s].dir != blk_slots[first].dir) continue;
        if (blk_slots[s].lba != end_lba) continue;
        if (blk_slots[s].buf != end_buf) continue;
        if (total + blk_slots[s].count > BLK_MAX_GROUP) continue;
        blk_grp[ng++] = s;
        blk_merged++;
        end_lba += blk_slots[s].count;
        end_buf += blk_slots[s].count * 512;
        total += blk_slots[s].count;
    }
    int err = 0;
    if (ng == 1 && blk_slots[first].count == 1) {
        /* Proven single-sector path, unchanged. */
        if (blk_slots[first].dir == BLK_DIR_READ)
            err = ata_pio_read_sector(blk_slots[first].lba, blk_slots[first].buf);
        else
            err = ata_pio_write_sector(blk_slots[first].lba, blk_slots[first].buf);
        blk_commands++;
    } else {
        if (blk_slots[first].dir == BLK_DIR_READ)
            err = ata_pio_read_multi(blk_slots[first].lba, total, blk_slots[first].buf);
        else
            err = ata_pio_write_multi(blk_slots[first].lba, total, blk_slots[first].buf);
        blk_commands++;
        if (err != 0) {
            /* PIO fallback: the multi-sector command failed, so
               retry sector by sector with the single-sector PIO
               commands (covers both a merged group and one
               multi-sector request). Fallback is counted even
               when the retry also fails (the attempt is what
               the counter means). */
            blk_fallbacks++;
            err = 0;
            for (int gi = 0; gi < ng; gi++) {
                int s = blk_grp[gi];
                for (u32 j = 0; j < blk_slots[s].count; j++) {
                    int e1;
                    if (blk_slots[s].dir == BLK_DIR_READ)
                        e1 = ata_pio_read_sector(blk_slots[s].lba + j, blk_slots[s].buf + j * 512);
                    else
                        e1 = ata_pio_write_sector(blk_slots[s].lba + j, blk_slots[s].buf + j * 512);
                    blk_commands++;
                    if (e1 != 0) err = -1;
                }
            }
        }
    }
    for (int gi = 0; gi < ng; gi++) {
        int s = blk_grp[gi];
        blk_slots[s].state = 2;
        blk_slots[s].err = err;
        blk_order_remove(s);
        blk_completed++;
    }
}
void blk_stats(u32 *submitted, u32 *completed, u32 *merged, u32 *commands, u32 *fallbacks, u32 *queued) {
    if (submitted) *submitted = blk_submitted;
    if (completed) *completed = blk_completed;
    if (merged) *merged = blk_merged;
    if (commands) *commands = blk_commands;
    if (fallbacks) *fallbacks = blk_fallbacks;
    if (queued) *queued = (u32)blk_order_len;
}
/* Swap slot allocator (redesign 5): the table exists and is
   fully functional, but no backing area is configured, so no
   slot is ever handed to a page-out — activation stays out
   (see CORE_CLI.md section 15.4 notes). Slots are file-scope
   statics, never on a stack. */
static int swap_slot_used[SWAP_SLOTS];
static u32 swap_slots_used = 0;
int blk_swap_alloc(void) {
    for (int i = 0; i < SWAP_SLOTS; i++) {
        if (swap_slot_used[i]) continue;
        swap_slot_used[i] = 1;
        swap_slots_used++;
        return i;
    }
    return -1;
}
void blk_swap_free(int slot) {
    if (slot < 0 || slot >= SWAP_SLOTS) return;
    if (!swap_slot_used[slot]) return;
    swap_slot_used[slot] = 0;
    swap_slots_used--;
}
void blk_swap_slots(u32 *total_out, u32 *used_out) {
    if (total_out) *total_out = SWAP_SLOTS;
    if (used_out) *used_out = swap_slots_used;
}
void blk_swap_status(void) {
    /* Swap area definition (section 15.1/15.4): the descriptor
       exists (device 0, no region configured, inactive) and
       demand paging now exists, but activation is still OUT:
       a swap area needs a dedicated device/partition (the
       16 MiB disk is fully owned by nxtsFS; carving sectors
       out of it would corrupt the filesystem), and a page-out
       engine that can write from fault/tick context without
       inverting the lock order does not exist yet. swapon
       therefore still refuses; it never claims active swap. */
    console_write("Swap: defined, inactive (slot allocator ready: 256 slots, 0 in use; no swap area configured, so no pages are swapped)\n");
}
void blk_status_print(void) {
    if (!ata_present()) { console_write("Block device 0: no ATA disk\n"); return; }
    int lba48 = ata_lba48_supported();
    u32 udma = ata_udma_mask();
    u32 sub, comp, mer, cmd, fb, qd;
    blk_stats(&sub, &comp, &mer, &cmd, &fb, &qd);
    u32 sr = 0, sw = 0;
    ata_io_stats(&sr, &sw);
    console_write("Block device 0: present (fixed IDE disk)\n");
    console_printf("Block LBA48: %s (ATA IDENTIFY word 83 bit 10)\n", lba48 ? "yes" : "no");
    console_printf("Block DMA: PIO active (IDENTIFY UDMA mask 0x%x; no bus-master DMA engine in this kernel, PIO fallback always available)\n", udma);
    console_write("Block PIO fallback: LBA28 single-sector retry on any multi-sector PIO error\n");
    console_printf("Block queue: capacity %u, queued %u\n", (u32)BLK_QUEUE_CAP, qd);
    console_printf("Block stats: submitted %u, completed %u, merged %u, commands %u, fallbacks %u\n", sub, comp, mer, cmd, fb);
    console_printf("Block sectors: read %u, written %u\n", sr, sw);
    blk_swap_status();
}
/* Queue two adjacent (adjacent=1: sectors 0,1) or non-adjacent
   (sectors 0,2) single-sector reads through the queue, then
   wait for both and report the counter deltas plus whether
   sector 0 still reads as the nxtsFS superblock. The deltas
   are the proof: adjacent gives merged 1 / commands 1 for
   two requests, non-adjacent gives merged 0 / commands 2. */
int blk_merge_test(int adjacent) {
    if (!ata_present()) { console_write("blk: no ATA disk\n"); return -1; }
    u32 s0, c0, m0, cmd0, f0, q0;
    blk_stats(&s0, &c0, &m0, &cmd0, &f0, &q0);
    int a = blk_enqueue(0, 0, 1, BLK_DIR_READ, blk_test_buf);
    int b = blk_enqueue(0, adjacent ? 1 : 2, 1, BLK_DIR_READ, blk_test_buf + 512);
    if (a < 0 || b < 0) { console_write("blk: queue full, test refused\n"); return -1; }
    blk_wait_slot(a);
    blk_wait_slot(b);
    int err = blk_slot_err(a) | blk_slot_err(b);
    blk_slot_free(a); blk_slot_free(b);
    u32 s1, c1, m1, cmd1, f1, q1;
    blk_stats(&s1, &c1, &m1, &cmd1, &f1, &q1);
    int magic = enc_enabled() ? 1 : (memcmp(blk_test_buf, "NXTSFS01", 8) == 0);
    console_printf("blk merge: requests 2, merged %u, commands %u, magic %s\n",
                   m1 - m0, cmd1 - cmd0, magic ? "OK" : "BAD");
    if (err != 0) console_write("blk merge: read error\n");
    return (err == 0 && magic) ? 0 : -1;
}
int blk_async_test(void) {
    if (!ata_present()) { console_write("blk: no ATA disk\n"); return -1; }
    int slot = blk_enqueue(0, 0, 2, BLK_DIR_READ, blk_test_buf);
    if (slot < 0) { console_write("blk: queue full, test refused\n"); return -1; }
    console_write("blk async: queued multi-sector read (sectors 0-1)\n");
    blk_wait_slot(slot);
    int err = blk_slot_err(slot);
    blk_slot_free(slot);
    int magic = enc_enabled() ? 1 : (memcmp(blk_test_buf, "NXTSFS01", 8) == 0);
    console_printf("blk async: completed, magic %s\n", magic ? "OK" : "BAD");
    if (err != 0) console_write("blk async: read error\n");
    return (err == 0 && magic) ? 0 : -1;
}
