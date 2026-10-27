#ifndef NXTS_ATA_H
#define NXTS_ATA_H
#include "../kernel/common.h"
int ata_present(void);
int ata_read_sector_raw(u32 lba, u8 *buf);        /* physical sector, no encryption */
int ata_write_sector_raw(u32 lba, const u8 *buf); /* physical sector, no encryption */
/* Translated sector: if disk encryption is enabled (kernel/enc.c),
   logical sector L is physical L+1, decrypted/encrypted with CTR.
   If encryption is off, these are identical to the raw functions. */
int ata_read_sector(u32 lba, u8 *buf);        /* buf must hold 512 bytes */
int ata_write_sector(u32 lba, const u8 *buf); /* buf must hold 512 bytes */
#endif
