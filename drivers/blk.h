#ifndef NXTS_BLK_H
#define NXTS_BLK_H
#include "../kernel/common.h"
/* Block-device layer (CORE_CLI.md section 15.1): a bio/request
   queue over the ATA PIO primitives in drivers/ata.c.
   Device 0 is the only block device (the fixed IDE disk); a
   second device does not exist, so dev != 0 is refused.
   Requests are PHYSICAL sectors: the encryption translation
   in drivers/ata.c (logical L -> physical L+1) sits above
   this layer, and ata_read_sector_raw/write_sector_raw are
   thin wrappers over blk_submit_raw_sync, so every ATA caller
   goes through the queue and no bypass remains.
   Async model: blk_enqueue submits without executing;
   blk_poll executes one queued group (merging adjacent
   same-direction requests whose buffers are also contiguous);
   blk_wait_slot blocks on the request's completion flag and,
   while it is not done, halts until the next timer tick
   (PROC_BLOCKED-style wait, never a busy-spin). There is no
   disk interrupt in this kernel, so completion is poll-driven:
   the queue, not a spin loop, is what makes it async. */
#define BLK_DIR_READ 0
#define BLK_DIR_WRITE 1
#define BLK_QUEUE_CAP 16
#define BLK_MAX_GROUP 64 /* sectors per merged PIO group */
int blk_enqueue(u32 dev, u32 lba, u32 count, int dir, u8 *buf); /* slot >= 0, or -1 (bad arg / queue full) */
int blk_slot_done(int slot); /* 1 when the slot completed (ok or error) */
int blk_slot_err(int slot);  /* 0 ok, -1 error (valid after done) */
void blk_slot_free(int slot);
void blk_poll(void); /* execute at most one queued group */
void blk_wait_slot(int slot); /* poll + hlt-until-tick until done */
int blk_submit_raw_sync(u32 dev, u32 lba, u32 count, int dir, u8 *buf); /* chunked sync wrapper: 0 ok, -1 error */
void blk_stats(u32 *submitted, u32 *completed, u32 *merged, u32 *commands, u32 *fallbacks, u32 *queued);
void blk_status_print(void); /* `blk` bare: device, LBA48, DMA, queue, stats, swap */
int blk_merge_test(int adjacent); /* queue 2 reads, wait, print merged/commands/magic result; 0 ok */
int blk_async_test(void); /* one async 2-sector read: print queued, then waited completion; 0 ok */
void blk_swap_status(void); /* one line: swap defined, inactive */
/* Swap slot allocator (redesign 5 foundations only): a table
   of SWAP_SLOTS slots over a reserved region that does not
   exist yet — no swap area is configured, so the allocator
   is never used to page anything out. It exists so the
   page-out engine (a future phase) has a slot layer to
   build on, and so `swapinfo` can report honest state. */
#define SWAP_SLOTS 256
int blk_swap_alloc(void); /* slot >= 0, or -1 when full */
void blk_swap_free(int slot);
void blk_swap_slots(u32 *total_out, u32 *used_out);
#endif
