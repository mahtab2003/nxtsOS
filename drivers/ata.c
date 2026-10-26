#include "ata.h"

#define ATA_DATA     0x1F0
#define ATA_SECTORS  0x1F2
#define ATA_LBA_LO   0x1F3
#define ATA_LBA_MID  0x1F4
#define ATA_LBA_HI   0x1F5
#define ATA_DRIVE    0x1F6
#define ATA_STATUS   0x1F7
#define ATA_CMD      0x1F7

static int ata_wait_ready(void) {
    /* Wait for BSY clear, with a timeout so a missing/faulty disk
       returns an error instead of hanging the kernel forever. */
    for (u32 i = 0; i < 1000000; i++) {
        u8 st = inb(ATA_STATUS);
        if (st == 0xFF) return -1; /* no drive on this bus */
        if ((st & 0x80) == 0) return 0;
    }
    return -1;
}
static int ata_wait_drq(void) {
    for (u32 i = 0; i < 1000000; i++) {
        u8 st = inb(ATA_STATUS);
        if (st & 0x01) return -1; /* ERR */
        if (st & 0x08) return 0;  /* DRQ */
        if ((st & 0x80) == 0 && (st & 0x08) == 0) {
            /* Not busy and no data yet: keep waiting briefly. */
        }
    }
    return -1;
}

int ata_present(void) {
    u8 st = inb(ATA_STATUS);
    if (st == 0xFF) return 0;
    outb(ATA_DRIVE, 0xE0);
    io_wait();
    st = inb(ATA_STATUS);
    return st != 0xFF;
}

static int ata_select(u32 lba) {
    if (ata_wait_ready() != 0) return -1;
    outb(ATA_DRIVE, (u8)(0xE0 | ((lba >> 24) & 0x0F)));
    outb(ATA_SECTORS, 1);
    outb(ATA_LBA_LO, (u8)(lba & 0xFF));
    outb(ATA_LBA_MID, (u8)((lba >> 8) & 0xFF));
    outb(ATA_LBA_HI, (u8)((lba >> 16) & 0xFF));
    return 0;
}

int ata_read_sector(u32 lba, u8 *buf) {
    if (ata_select(lba) != 0) return -1;
    outb(ATA_CMD, 0x20);
    if (ata_wait_drq() != 0) return -1;
    u16 *w = (u16 *)buf;
    for (int i = 0; i < 256; i++) w[i] = inw(ATA_DATA);
    return 0;
}

int ata_write_sector(u32 lba, const u8 *buf) {
    if (ata_select(lba) != 0) return -1;
    outb(ATA_CMD, 0x30);
    if (ata_wait_drq() != 0) return -1;
    const u16 *w = (const u16 *)buf;
    for (int i = 0; i < 256; i++) outw(ATA_DATA, w[i]);
    outb(ATA_CMD, 0xE7); /* cache flush */
    if (ata_wait_ready() != 0) return -1;
    return 0;
}
