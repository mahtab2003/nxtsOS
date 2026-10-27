#include "vfs.h"
#include "../drivers/ata.h"
#include "../kernel/console.h"

#define FS_MAX_FILES 32
#define FS_DIR_SECTORS 4
#define FS_BITMAP_MAX_BYTES 4096

struct superblock {
    char magic[8];
    u32 version, total_sectors, bitmap_sectors;
    u32 dir_sector, dir_sectors, data_start, max_files;
} __attribute__((packed));
struct dir_entry {
    char name[32];
    u32 size, start_sector, sector_count, uid, mode, flags;
    u32 reserved[2];
} __attribute__((packed));

static int mounted = 0;
static struct superblock sb;
static u8 bitmap[FS_BITMAP_MAX_BYTES];
static struct dir_entry dir[FS_MAX_FILES];
static u8 sector_buf[512];

static int bit_used(u32 sector) {
    return (bitmap[sector / 8] >> (sector % 8)) & 1;
}
static void bit_set(u32 sector, int used) {
    if (used) bitmap[sector / 8] |= (u8)(1u << (sector % 8));
    else bitmap[sector / 8] &= (u8)~(1u << (sector % 8));
}

static int read_sector_checked(u32 lba, u8 *buf) {
    if (lba >= sb.total_sectors) return -1;
    return ata_read_sector(lba, buf);
}
static int write_sector_checked(u32 lba, const u8 *buf) {
    if (lba >= sb.total_sectors) return -1;
    return ata_write_sector(lba, buf);
}

static int valid_name(const char *name) {
    u32 len = 0;
    if (name[0] == 0) return 0;
    while (name[len]) {
        if (len >= 31) return 0;
        char c = name[len];
        if (c < 32 || c > 126 || c == '/') return 0;
        len++;
    }
    return len > 0;
}
static int valid_entry(struct dir_entry *e) {
    if ((e->flags & 1) == 0) return 0;
    if (!valid_name(e->name)) return 0;
    if (e->mode > 0777) return 0;
    if (e->sector_count == 0 && e->size != 0) return 0;
    if (e->size > e->sector_count * 512u) return 0;
    if (e->sector_count > 0) {
        if (e->start_sector < sb.data_start) return 0;
        if (e->start_sector + e->sector_count > sb.total_sectors) return 0;
    }
    return 1;
}
static int find_entry(const char *name) {
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if (!valid_entry(&dir[i])) continue;
        if (strcmp(dir[i].name, name) == 0) return i;
    }
    return -1;
}
static int save_bitmap(void) {
    for (u32 i = 0; i < sb.bitmap_sectors; i++) {
        u8 buf[512];
        memset(buf, 0, 512);
        u32 off = i * 512;
        u32 n = 512;
        if (off + n > sizeof(bitmap)) n = sizeof(bitmap) - off;
        memcpy(buf, bitmap + off, n);
        if (write_sector_checked(1 + i, buf) != 0) return -1;
    }
    return 0;
}
static int save_dir(void) {
    for (u32 i = 0; i < sb.dir_sectors; i++) {
        if (write_sector_checked(sb.dir_sector + i,
                (const u8 *)dir + i * 512) != 0) return -1;
    }
    return 0;
}
static int find_contiguous(u32 count, u32 *out_start) {
    u32 run = 0, run_start = 0;
    for (u32 s = sb.data_start; s < sb.total_sectors; s++) {
        if (!bit_used(s)) {
            if (run == 0) run_start = s;
            run++;
            if (run >= count) { *out_start = run_start; return 0; }
        } else run = 0;
    }
    return -1;
}

int fs_mounted(void) { return mounted; }

int fs_mount(void) {
    mounted = 0;
    if (!ata_present()) return -1;
    if (ata_read_sector(0, sector_buf) != 0) return -1;
    struct superblock *s = (struct superblock *)sector_buf;
    if (memcmp(s->magic, "NXTSFS01", 8) != 0) return -2;
    if (s->version != 1) return -2;
    if (s->total_sectors < 100 || s->total_sectors > 1000000) return -2;
    if (s->bitmap_sectors == 0 || s->bitmap_sectors * 512 > FS_BITMAP_MAX_BYTES) return -2;
    /* The bitmap must actually cover the claimed disk: otherwise a
       huge total_sectors would make the free-space scan loop over
       billions of sectors (a denial of service from a corrupt disk). */
    if (s->total_sectors > s->bitmap_sectors * 4096u) return -2;
    if (s->total_sectors <= (s->bitmap_sectors - 1) * 4096u) return -2;
    if (s->dir_sector != 1 + s->bitmap_sectors) return -2;
    if (s->dir_sectors != FS_DIR_SECTORS) return -2;
    if (s->data_start != s->dir_sector + s->dir_sectors) return -2;
    if (s->data_start >= s->total_sectors) return -2;
    if (s->max_files != FS_MAX_FILES) return -2;
    sb = *s;
    memset(bitmap, 0, sizeof(bitmap));
    for (u32 i = 0; i < sb.bitmap_sectors; i++) {
        if (read_sector_checked(1 + i, sector_buf) != 0) return -2;
        memcpy(bitmap + i * 512, sector_buf, 512);
    }
    memset(dir, 0, sizeof(dir));
    for (u32 i = 0; i < sb.dir_sectors; i++) {
        if (read_sector_checked(sb.dir_sector + i,
                (u8 *)dir + i * 512) != 0) return -2;
    }
    int skipped = 0;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if ((dir[i].flags & 1) && !valid_entry(&dir[i])) {
            console_printf("FS warning: skipping invalid directory entry %d\n", i);
            dir[i].flags = 0;
            skipped++;
        }
    }
    (void)skipped;
    mounted = 1;
    return 0;
}

void fs_status(void) {
    if (!mounted) { console_write("Filesystem: not mounted (no disk or bad filesystem)\n"); return; }
    console_printf("Filesystem: nxtsFS v1, %u sectors total, %u free, %u files max\n",
                   sb.total_sectors, fs_free_sectors(), FS_MAX_FILES);
}

u32 fs_free_sectors(void) {
    if (!mounted) return 0;
    u32 free = 0;
    for (u32 s = sb.data_start; s < sb.total_sectors; s++)
        if (!bit_used(s)) free++;
    return free;
}

int fs_list(void) {
    if (!mounted) return -1;
    int count = 0;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if (!valid_entry(&dir[i])) continue;
        console_printf("%s  %u bytes  uid %u  mode %u\n",
                       dir[i].name, dir[i].size, dir[i].uid, dir[i].mode);
        count++;
    }
    if (count == 0) console_write("(no files)\n");
    return count;
}

int fs_read(const char *name, u8 *buf, u32 buf_size, u32 *out_size) {
    if (!mounted || !valid_name(name)) return -1;
    int idx = find_entry(name);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    if (e->size > buf_size) return -1;
    u32 done = 0;
    for (u32 i = 0; i < e->sector_count && done < e->size; i++) {
        if (read_sector_checked(e->start_sector + i, sector_buf) != 0) return -1;
        u32 chunk = e->size - done;
        if (chunk > 512) chunk = 512;
        memcpy(buf + done, sector_buf, chunk);
        done += chunk;
    }
    *out_size = done;
    return 0;
}

int fs_write(const char *name, const u8 *data, u32 len, u32 uid, u32 mode) {
    if (!mounted || !valid_name(name) || mode > 0777) return -1;
    u32 need = (len + 511) / 512;
    if (need == 0) need = 1;
    u32 start = 0;
    if (find_contiguous(need, &start) != 0) return -1; /* no space: old file kept */
    int old = find_entry(name);
    int slot = old >= 0 ? old : -1;
    if (slot < 0) {
        for (int i = 0; i < FS_MAX_FILES; i++) {
            if ((dir[i].flags & 1) == 0) { slot = i; break; }
        }
        if (slot < 0) return -1; /* directory full */
    }
    /* Write data sectors first, then commit bitmap + directory. */
    for (u32 i = 0; i < need; i++) {
        u8 buf[512];
        memset(buf, 0, 512);
        u32 off = i * 512;
        if (off < len) {
            u32 chunk = len - off;
            if (chunk > 512) chunk = 512;
            memcpy(buf, data + off, chunk);
        }
        if (write_sector_checked(start + i, buf) != 0) return -1;
        bit_set(start + i, 1);
    }
    if (old >= 0) {
        struct dir_entry *oe = &dir[old];
        for (u32 i = 0; i < oe->sector_count; i++) bit_set(oe->start_sector + i, 0);
        /* Re-mark the newly written blocks (in case they overlapped the
           old range, which allocation already prevented, this is safe). */
        for (u32 i = 0; i < need; i++) bit_set(start + i, 1);
    }
    struct dir_entry *e = &dir[slot];
    memset(e, 0, sizeof(*e));
    u32 nl = strlen(name);
    memcpy(e->name, name, nl);
    e->size = len; e->start_sector = start; e->sector_count = need;
    e->uid = uid; e->mode = mode; e->flags = 1;
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    return 0;
}

int fs_delete(const char *name) {
    if (!mounted || !valid_name(name)) return -1;
    int idx = find_entry(name);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    for (u32 i = 0; i < e->sector_count; i++) bit_set(e->start_sector + i, 0);
    memset(e, 0, sizeof(*e));
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    return 0;
}
