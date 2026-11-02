#ifndef NXTS_ATA_H
#define NXTS_ATA_H
#include "../kernel/common.h"
int ata_present(void);
/* Sector I/O counters (Linux-comparability run, for `iostat`):
   counted in the raw sector paths, so encrypted disks count the
   same logical sectors once. Never reset by a shell command. */
void ata_io_stats(u32 *sectors_read, u32 *sectors_written);
/* Low-level PIO primitives (section 15.1 block layer): called
   ONLY by drivers/blk.c. Single-sector paths are the proven
   pre-block-layer code; multi-sector paths use one LBA48
   command (0x24/0x34) when IDENTIFY proves LBA48, else one
   LBA28 command. DMA is NOT used: there is no bus-master
   engine in this kernel, so PIO is the proven path. */
int ata_pio_read_sector(u32 lba, u8 *buf);
int ata_pio_write_sector(u32 lba, const u8 *buf);
int ata_pio_read_multi(u32 lba, u32 count, u8 *buf);   /* 1..255 sectors */
int ata_pio_write_multi(u32 lba, u32 count, const u8 *buf);
/* IDENTIFY results (cached, probed lazily; a failed probe
   reports "not supported" rather than inventing a feature). */
int ata_lba48_supported(void);
u32 ata_udma_mask(void);
int ata_read_sector_raw(u32 lba, u8 *buf);        /* physical sector, no encryption; via the block queue */
int ata_write_sector_raw(u32 lba, const u8 *buf); /* physical sector, no encryption; via the block queue */
/* Translated sector: if disk encryption is enabled (kernel/enc.c),
   logical sector L is physical L+1, decrypted/encrypted with CTR.
   If encryption is off, these are identical to the raw functions. */
int ata_read_sector(u32 lba, u8 *buf);        /* buf must hold 512 bytes */
int ata_write_sector(u32 lba, const u8 *buf); /* buf must hold 512 bytes */
#endif
