#include "ata.h"
#include "blk.h"
#include "../kernel/enc.h"

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


/* IDENTIFY DEVICE (0xEC), cached: word 83 bit 10 is LBA48
   support, word 88 bits 0-6 are the supported UDMA modes.
   A failed probe means "not proven": LBA48 off, UDMA mask 0,
   and every transfer stays on the LBA28 PIO path. The probe
   is raw port I/O, never a queued request (it is a device
   command, not sector data). */
static int ident_done = 0, ident_lba48 = 0;
static u32 ident_udma = 0;
static void ata_identify_probe(void) {
    if (ident_done) return;
    ident_done = 1;
    if (!ata_present()) return;
    if (ata_wait_ready() != 0) return;
    outb(ATA_DRIVE, 0xE0);
    io_wait();
    if (ata_wait_ready() != 0) return;
    outb(ATA_CMD, 0xEC);
    if (ata_wait_drq() != 0) return;
    static u16 ident[256];
    for (int i = 0; i < 256; i++) ident[i] = inw(ATA_DATA);
    if (ident[83] & 0x0400) ident_lba48 = 1;
    ident_udma = ident[88] & 0x7F;
}
int ata_lba48_supported(void) { ata_identify_probe(); return ident_lba48; }
u32 ata_udma_mask(void) { ata_identify_probe(); return ident_udma; }

/* LBA48 register block: high bytes first, then low bytes
   (the ATA "previous/current" register sequence), drive
   0x40 = LBA + master. lba is u32 here, so the high bytes
   are zero, but the command is a genuine LBA48 command. */
static int ata_select48(u32 lba, u32 count) {
    if (ata_wait_ready() != 0) return -1;
    outb(ATA_DRIVE, 0x40);
    outb(ATA_SECTORS, (u8)((count >> 8) & 0xFF));
    outb(ATA_LBA_LO, (u8)((lba >> 24) & 0xFF));
    outb(ATA_LBA_MID, 0);
    outb(ATA_LBA_HI, 0);
    outb(ATA_SECTORS, (u8)(count & 0xFF));
    outb(ATA_LBA_LO, (u8)(lba & 0xFF));
    outb(ATA_LBA_MID, (u8)((lba >> 8) & 0xFF));
    outb(ATA_LBA_HI, (u8)((lba >> 16) & 0xFF));
    return 0;
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

static u32 ata_sec_read = 0, ata_sec_written = 0;
void ata_io_stats(u32 *sectors_read, u32 *sectors_written) {
    if (sectors_read) *sectors_read = ata_sec_read;
    if (sectors_written) *sectors_written = ata_sec_written;
}

/* Low-level PIO primitives, called ONLY by the block layer
   (drivers/blk.c). The public raw/translated functions below
   go through the queue instead, so no caller bypasses it. */
int ata_pio_read_sector(u32 lba, u8 *buf) {
    if (ata_select(lba) != 0) return -1;
    outb(ATA_CMD, 0x20);
    if (ata_wait_drq() != 0) return -1;
    u16 *w = (u16 *)buf;
    for (int i = 0; i < 256; i++) w[i] = inw(ATA_DATA);
    ata_sec_read++;
    return 0;
}

int ata_pio_write_sector(u32 lba, const u8 *buf) {
    if (ata_select(lba) != 0) return -1;
    outb(ATA_CMD, 0x30);
    if (ata_wait_drq() != 0) return -1;
    const u16 *w = (const u16 *)buf;
    for (int i = 0; i < 256; i++) outw(ATA_DATA, w[i]);
    outb(ATA_CMD, 0xE7); /* cache flush */
    if (ata_wait_ready() != 0) return -1;
    ata_sec_written++;
    return 0;
}


int ata_pio_read_multi(u32 lba, u32 count, u8 *buf) {
    if (count == 0 || count > 255) return -1;
    int use48 = ata_lba48_supported();
    if (use48) { if (ata_select48(lba, count) != 0) return -1; outb(ATA_CMD, 0x24); }
    else { if (ata_wait_ready() != 0) return -1;
           outb(ATA_DRIVE, (u8)(0xE0 | ((lba >> 24) & 0x0F)));
           outb(ATA_SECTORS, (u8)count);
           outb(ATA_LBA_LO, (u8)(lba & 0xFF));
           outb(ATA_LBA_MID, (u8)((lba >> 8) & 0xFF));
           outb(ATA_LBA_HI, (u8)((lba >> 16) & 0xFF));
           outb(ATA_CMD, 0x20); }
    for (u32 s = 0; s < count; s++) {
        if (ata_wait_drq() != 0) return -1;
        u16 *w = (u16 *)(buf + s * 512);
        for (int i = 0; i < 256; i++) w[i] = inw(ATA_DATA);
    }
    ata_sec_read += count;
    return 0;
}
int ata_pio_write_multi(u32 lba, u32 count, const u8 *buf) {
    if (count == 0 || count > 255) return -1;
    int use48 = ata_lba48_supported();
    if (use48) { if (ata_select48(lba, count) != 0) return -1; outb(ATA_CMD, 0x34); }
    else { if (ata_wait_ready() != 0) return -1;
           outb(ATA_DRIVE, (u8)(0xE0 | ((lba >> 24) & 0x0F)));
           outb(ATA_SECTORS, (u8)count);
           outb(ATA_LBA_LO, (u8)(lba & 0xFF));
           outb(ATA_LBA_MID, (u8)((lba >> 8) & 0xFF));
           outb(ATA_LBA_HI, (u8)((lba >> 16) & 0xFF));
           outb(ATA_CMD, 0x30); }
    for (u32 s = 0; s < count; s++) {
        if (ata_wait_drq() != 0) return -1;
        const u16 *w = (const u16 *)(buf + s * 512);
        for (int i = 0; i < 256; i++) outw(ATA_DATA, w[i]);
    }
    outb(ATA_CMD, 0xE7); /* cache flush */
    if (ata_wait_ready() != 0) return -1;
    ata_sec_written += count;
    return 0;
}

int ata_read_sector_raw(u32 lba, u8 *buf) {
    return blk_submit_raw_sync(0, lba, 1, BLK_DIR_READ, buf);
}
int ata_write_sector_raw(u32 lba, const u8 *buf) {
    return blk_submit_raw_sync(0, lba, 1, BLK_DIR_WRITE, (u8 *)buf);
}

int ata_read_sector(u32 lba, u8 *buf) {
    if (!enc_enabled()) return ata_read_sector_raw(lba, buf);
    /* Encrypted: logical L is physical L+1, CTR-decrypted. */
    u8 cipher[512];
    if (ata_read_sector_raw(lba + 1, cipher) != 0) return -1;
    enc_sector_crypt(lba, cipher, buf);
    return 0;
}

int ata_write_sector(u32 lba, const u8 *buf) {
    if (!enc_enabled()) return ata_write_sector_raw(lba, buf);
    /* Encrypt into a temporary buffer so the caller's buffer is
       never modified in place (callers reuse their buffers). */
    static u8 cipher[512];
    enc_sector_crypt(lba, buf, cipher);
    return ata_write_sector_raw(lba + 1, cipher);
}
