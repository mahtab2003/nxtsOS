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

static int is_system_file(const char *name) {
    /* fails.txt holds persistent per-user failed-login counts (v0.4.1);
       like users.txt/audit.log it must never be created or written by
       a non-root user, or the brute-force lockout could be cleared.
       pubkeys.txt (Phase 11 keyring) joins the list: otherwise a
       non-root user could create it before root does, and a later
       root install would trust the attacker's key. tlsanchors.txt
       (Phase 12 TLS anchors) joins for the same reason: a planted
       anchor would let a later anchored handshake trust a MITM. */
    if (strcmp(name, "users.txt") == 0 || strcmp(name, "audit.log") == 0
        || strcmp(name, "fails.txt") == 0 || strcmp(name, "packages.txt") == 0
        || strcmp(name, "pubkeys.txt") == 0
        || strcmp(name, "rollback.txt") == 0 || strcmp(name, "rb_packages.txt") == 0
        || strcmp(name, "repo.txt") == 0
        || strcmp(name, "repo_index.txt") == 0 || strcmp(name, "repo_index.sig") == 0
        || strcmp(name, "tlsanchors.txt") == 0)
        return 1;
    /* Rollback backups rb0..rb63 (Phase 11 snapshot): same rule —
       a non-root user must not pre-create one, or a later root
       snapshot could be tricked into trusting attacker content. */
    if (name[0] == 'r' && name[1] == 'b' && name[2] >= '0' && name[2] <= '9') {
        if (name[3] == 0) return 1;
        if (name[3] >= '0' && name[3] <= '9' && name[4] == 0) return 1;
    }
    return 0;
}
static int can_read_entry(struct dir_entry *e, u32 uid) {
    if (uid == 0) return 1;
    if (strcmp(e->name, "audit.log") == 0) return 0;
    if (e->uid == uid) return (e->mode >> 6) & 4;
    return e->mode & 4;
}
static int can_write_entry(struct dir_entry *e, u32 uid) {
    if (uid == 0) return 1;
    if (e->uid == uid) return (e->mode >> 6) & 2;
    return e->mode & 2;
}
static int find_entry(const char *name) {
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if (!valid_entry(&dir[i])) continue;
        if (strcmp(dir[i].name, name) == 0) return i;
    }
    return -1;
}
int fs_exists(const char *name) {
    if (!mounted || !valid_name(name)) return 0;
    return find_entry(name) >= 0 ? 1 : 0;
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
u32 fs_total_sectors(void) {
    if (!mounted) return 0;
    return sb.total_sectors;
}

int fs_list_as(u32 uid) {
    if (!mounted) return -1;
    int count = 0;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if (!valid_entry(&dir[i])) continue;
        if (!can_read_entry(&dir[i], uid)) continue;
        console_printf("%s  %u bytes  uid %u  mode %u\n",
                       dir[i].name, dir[i].size, dir[i].uid, dir[i].mode);
        count++;
    }
    if (count == 0) console_write("(no files)\n");
    return count;
}
int fs_list(void) { return fs_list_as(0); }
int fs_enum_as(u32 uid, char names[][32], u32 sizes[], int max) {
    if (!mounted || max <= 0) return 0;
    int count = 0;
    for (int i = 0; i < FS_MAX_FILES && count < max; i++) {
        if (!valid_entry(&dir[i])) continue;
        if (!can_read_entry(&dir[i], uid)) continue;
        int j = 0;
        while (dir[i].name[j] && j < 31) { names[count][j] = dir[i].name[j]; j++; }
        names[count][j] = 0;
        sizes[count] = dir[i].size;
        count++;
    }
    return count;
}

int fs_read_as(const char *name, u8 *buf, u32 buf_size, u32 *out_size, u32 uid) {
    if (!mounted || !valid_name(name)) return -1;
    int idx = find_entry(name);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    if (!can_read_entry(e, uid)) return -1;
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
int fs_read_range_as(const char *name, u8 *buf, u32 buf_size, u32 offset, u32 *out_size, u32 uid) {
    /* Windowed read for cat: the same entry lookup and permission
       check as fs_read_as, but starting at offset, so a caller with
       a small buffer can walk a file of any size instead of being
       refused outright. Returns 0 with *out_size == 0 at end of
       file (and for a zero-length read); a missing file, a bad
       name, or an unreadable entry is -1 on every call, so the
       first call already reports it. A short sector run ends the
       read with what was copied, matching fs_read_as. */
    if (!mounted || !valid_name(name)) return -1;
    int idx = find_entry(name);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    if (!can_read_entry(e, uid)) return -1;
    if (offset >= e->size || buf_size == 0) { *out_size = 0; return 0; }
    u32 want = e->size - offset;
    if (want > buf_size) want = buf_size;
    u32 done = 0;
    u32 pos = offset;
    while (done < want) {
        u32 sec = pos / 512;
        u32 within = pos % 512;
        if (sec >= e->sector_count) break;
        if (read_sector_checked(e->start_sector + sec, sector_buf) != 0) return -1;
        u32 chunk = 512 - within;
        if (chunk > want - done) chunk = want - done;
        memcpy(buf + done, sector_buf + within, chunk);
        done += chunk;
        pos += chunk;
    }
    *out_size = done;
    return 0;
}
int fs_read(const char *name, u8 *buf, u32 buf_size, u32 *out_size) {
    return fs_read_as(name, buf, buf_size, out_size, 0);
}

int fs_write_as(const char *name, const u8 *data, u32 len, u32 uid, u32 mode) {
    if (!mounted || !valid_name(name) || mode > 0777) return -1;
    int existing = find_entry(name);
    if (existing >= 0) {
        if (!can_write_entry(&dir[existing], uid)) return -1;
    } else if (uid != 0 && is_system_file(name)) {
        return -1; /* only root may create system files */
    }
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

int fs_write(const char *name, const u8 *data, u32 len, u32 uid, u32 mode) {
    return fs_write_as(name, data, len, uid, mode);
}

int fs_delete_as(const char *name, u32 uid) {
    if (!mounted || !valid_name(name)) return -1;
    int idx = find_entry(name);
    if (idx < 0) return -1;
    if (!can_write_entry(&dir[idx], uid)) return -1;
    struct dir_entry *e = &dir[idx];
    for (u32 i = 0; i < e->sector_count; i++) bit_set(e->start_sector + i, 0);
    memset(e, 0, sizeof(*e));
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    return 0;
}

int fs_delete(const char *name) { return fs_delete_as(name, 0); }

/* Metadata-only rename: the directory entry keeps its uid, mode,
   size, and data sectors; only the name changes, so a rename can
   never silently re-own or re-permit a file. It refuses when the
   source is missing, the destination already exists (never
   overwrites), the caller may not write the source (same rule as
   delete), or a non-root caller would create or move a system file
   (same rule as create). */
int fs_rename_as(const char *oldname, const char *newname, u32 uid) {
    if (!mounted || !valid_name(oldname) || !valid_name(newname)) return -1;
    int idx = find_entry(oldname);
    if (idx < 0) return -1;
    if (find_entry(newname) >= 0) return -1;
    if (!can_write_entry(&dir[idx], uid)) return -1;
    if (uid != 0 && (is_system_file(oldname) || is_system_file(newname))) return -1;
    struct dir_entry *e = &dir[idx];
    memset(e->name, 0, sizeof(e->name));
    u32 nl = strlen(newname);
    memcpy(e->name, newname, nl);
    if (save_dir() != 0) return -1;
    return 0;
}

/* Metadata-only mode change: only the mode changes; owner, size and
   data sectors are untouched, so a chmod can never silently re-own
   or truncate a file. Only root or the file's owner may change it —
   a non-owner writer is refused even if the file is world-writable,
   because changing who may read a file is not a write to its data.
   A mode over 0777 is refused, never masked down. */
int fs_chmod_as(const char *name, u32 mode, u32 uid) {
    if (!mounted || !valid_name(name) || mode > 0777) return -1;
    int idx = find_entry(name);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    if (uid != 0 && e->uid != uid) return -1;
    e->mode = mode;
    if (save_dir() != 0) return -1;
    return 0;
}

/* Byte-exact copy: the destination is a NEW file, not a second name
   for the source — the source is left untouched, the copy is owned
   by the caller (uid), and it keeps the source's mode. The copy
   grants no new access: the source must already be readable by the
   caller (same rule as read), and a non-root caller may not create
   a system-named destination (same rule as create), so a copy can
   neither plant a system file nor read one the caller may not read.
   It refuses a missing source and an existing destination (never
   overwrites, including a copy onto itself). Data moves sector by
   sector through the file-scope sector_buf, so any file size works
   and no buffer of any size sits on the kernel stack; the bitmap
   and directory are committed only after every sector copied, and
   a mid-copy read/write failure unmarks the sectors already
   claimed (the in-memory bitmap is not saved until the end, so
   the on-disk state is untouched on failure). */
int fs_copy_as(const char *srcname, const char *dstname, u32 uid) {
    if (!mounted || !valid_name(srcname) || !valid_name(dstname)) return -1;
    int idx = find_entry(srcname);
    if (idx < 0) return -1;
    if (find_entry(dstname) >= 0) return -1;
    struct dir_entry *src = &dir[idx];
    if (!can_read_entry(src, uid)) return -1;
    if (uid != 0 && is_system_file(dstname)) return -1;
    u32 need = src->sector_count;
    if (need == 0) need = 1;
    int slot = -1;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if ((dir[i].flags & 1) == 0) { slot = i; break; }
    }
    if (slot < 0) return -1; /* directory full */
    u32 start = 0;
    if (find_contiguous(need, &start) != 0) return -1; /* no space */
    u32 copied = 0;
    for (u32 i = 0; i < need; i++) {
        if (i < src->sector_count) {
            if (read_sector_checked(src->start_sector + i, sector_buf) != 0) goto fail;
        } else {
            memset(sector_buf, 0, 512);
        }
        if (write_sector_checked(start + i, sector_buf) != 0) goto fail;
        bit_set(start + i, 1);
        copied++;
    }
    {
        struct dir_entry *e = &dir[slot];
        u32 smode = src->mode, ssize = src->size;
        memset(e, 0, sizeof(*e));
        u32 nl = strlen(dstname);
        memcpy(e->name, dstname, nl);
        e->size = ssize; e->start_sector = start; e->sector_count = need;
        e->uid = uid; e->mode = smode; e->flags = 1;
    }
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    return 0;
fail:
    for (u32 i = 0; i < copied; i++) bit_set(start + i, 0);
    return -1;
}

int fs_append(const char *name, const u8 *data, u32 len) {
    /* Root-only append for the audit log. Total size is capped so a
       runaway log cannot fill the disk; when full it stops logging
       (and the caller prints a warning) instead of truncating history.
       QEMU-proven by tests/qemu_test_audit_cap.py: a log pre-seeded
       to 4080 bytes refuses the next entry, warns, and hashes
       byte-identical to the seed, while a 4000-byte seed gains
       exactly one login-ok entry. */
    if (!mounted || !valid_name(name) || len == 0) return -1;
    u8 old[4096];
    u32 old_size = 0;
    if (find_entry(name) >= 0) {
        if (fs_read_as(name, old, sizeof(old), &old_size, 0) != 0) return -1;
    }
    if (old_size + len > 4096) return -1;
    memcpy(old + old_size, data, len);
    return fs_write_as(name, old, old_size + len, 0, 0600);
}
