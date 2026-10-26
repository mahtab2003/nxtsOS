#ifndef NXTS_ATA_H
#define NXTS_ATA_H
#include "../kernel/common.h"
int ata_present(void);
int ata_read_sector(u32 lba, u8 *buf);        /* buf must hold 512 bytes */
int ata_write_sector(u32 lba, const u8 *buf); /* buf must hold 512 bytes */
#endif
