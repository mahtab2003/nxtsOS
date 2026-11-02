#include "vfs.h"
#include "../drivers/ata.h"
#include "../drivers/pit.h"
#include "../kernel/console.h"
#include "../kernel/groups.h"

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

/* §15 timestamp sidecar (defined with the path layer, near the
   end of this file): flat mutating calls below update it, flat
   reads never do (so the sidecar's own read cannot recurse). */
static void ts_touch(u32 pfield, const char *name, int mt_flag, int at_flag);
static void ts_remove(u32 pfield, const char *name);
static void ts_move(u32 old_pf, const char *old_name, u32 new_pf, const char *new_name);
static int ts_lookup(u32 pfield, const char *name, u32 *mt, u32 *at);
static int ts_busy = 0;

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
        || strcmp(name, "tlsanchors.txt") == 0
        || strcmp(name, "groups.txt") == 0
        || strcmp(name, "fw.txt") == 0
        || strcmp(name, "timestamps.txt") == 0
        || strcmp(name, "castore.txt") == 0 || strcmp(name, "tofuprints.txt") == 0)
        return 1;
    /* Rollback backups rb0..rb63 (Phase 11 snapshot): same rule —
       a non-root user must not pre-create one, or a later root
       snapshot could be tricked into trusting attacker content.
       castore.txt (Phase 13 CA store) and tofuprints.txt
       (Phase 13 TOFU pins) join for the same reason as
       tlsanchors.txt: a planted store member or print would
       let later handshakes trust an attacker's chain. */
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
    /* Parity run: group triple (mode>>3) applies when the
       caller belongs to the file's group. gid 0 means "no
       group" (every pre-parity file), so old disks behave
       exactly as before. */
    if (e->reserved[0] != 0 && groups_user_in_gid(uid, e->reserved[0]))
        return (e->mode >> 3) & 4;
    return e->mode & 4;
}
static int can_write_entry(struct dir_entry *e, u32 uid) {
    if (uid == 0) return 1;
    if (e->uid == uid) return (e->mode >> 6) & 2;
    if (e->reserved[0] != 0 && groups_user_in_gid(uid, e->reserved[0]))
        return (e->mode >> 3) & 2;
    return e->mode & 2;
}
/* §15: flat-name lookup is a ROOT-CHILD operation only. An entry
   in a subdirectory has reserved[1] != 0 and is invisible here,
   so every pre-§15 flat caller keeps seeing exactly the flat
   namespace it always saw (pre-§15 entries all have
   reserved[1] == 0, i.e. they already are root children). */
static int find_entry(const char *name) {
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if (!valid_entry(&dir[i])) continue;
        if (dir[i].reserved[1] != 0) continue;
        if (strcmp(dir[i].name, name) == 0) return i;
    }
    return -1;
}

/* Symbolic links (Linux-comparability run): dir_entry.flags bit 1
   marks a link; its data is the target name (a flat-namespace name,
   never a path — '/' cannot appear in names). No layout change:
   the flag bit was free (only bit 0, "valid", was used).
   resolve_link follows at most 4 hops; a loop or a dangling
   target returns -1 (Linux ELOOP/ENOENT behaviour, surfaced as
   a plain failure). Reads, range reads, stat, copy, chmod,
   chown, chgrp and writes all resolve first (they act on the
   target); delete and rename act on the link itself (they use
   find_entry directly and are NOT changed here). */
static int resolve_link(const char *name, char *out) {
    char cur[32];
    u32 i = 0;
    while (name[i] && i < 31) { cur[i] = name[i]; i++; }
    cur[i] = 0;
    for (int hop = 0; hop < 4; hop++) {
        int idx = find_entry(cur);
        if (idx < 0) return -1;
        struct dir_entry *e = &dir[idx];
        if ((e->flags & 2) == 0) {
            u32 j = 0;
            while (cur[j]) { out[j] = cur[j]; j++; }
            out[j] = 0;
            return 0;
        }
        if (e->size == 0 || e->size >= 32 || e->sector_count == 0) return -1;
        if (read_sector_checked(e->start_sector, sector_buf) != 0) return -1;
        u32 j = 0;
        while (j < e->size) { cur[j] = (char)sector_buf[j]; j++; }
        cur[j] = 0;
        if (!valid_name(cur)) return -1;
    }
    return -1; /* link loop */
}

/* Forward: fs_write_as and save_dir are defined below; the link
   creator needs them. */
int fs_write_as(const char *name, const u8 *data, u32 len, u32 uid, u32 mode);
static int save_dir(void);
int fs_symlink_as(const char *link, const char *target, u32 uid) {
    if (!mounted || !valid_name(link) || !valid_name(target)) return -1;
    if (find_entry(link) >= 0) return -1; /* never overwrite */
    if (uid != 0 && is_system_file(link)) return -1;
    u32 tl = strlen(target);
    if (fs_write_as(link, (const u8 *)target, tl, uid, 0777) != 0) return -1;
    int idx = find_entry(link);
    if (idx < 0) return -1;
    dir[idx].flags |= 2;
    return save_dir();
}

int fs_readlink_as(const char *link, char *out, u32 uid) {
    if (!mounted || !valid_name(link) || !out) return -1;
    int idx = find_entry(link);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    if ((e->flags & 2) == 0) return -1; /* not a link */
    if (uid != 0 && e->uid != uid && !can_read_entry(e, uid)) return -1;
    if (e->size == 0 || e->size >= 32 || e->sector_count == 0) return -1;
    if (read_sector_checked(e->start_sector, sector_buf) != 0) return -1;
    u32 j = 0;
    while (j < e->size) { out[j] = (char)sector_buf[j]; j++; }
    out[j] = 0;
    return valid_name(out) ? 0 : -1;
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
    /* List view (Work D): header + name column padded to 24 + footer
       count. Row fields keep their established text; the zero-case
       line is preserved verbatim. */
    console_write("NAME                    SIZE  UID  MODE\n");
    int count = 0;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if (!valid_entry(&dir[i])) continue;
        if (dir[i].reserved[1] != 0) continue; /* §15: root children only */
        if (strcmp(dir[i].name, "timestamps.txt") == 0) continue; /* §15: hidden sidecar, never listed */
        if (!can_read_entry(&dir[i], uid)) continue;
        console_write(dir[i].name);
        if ((dir[i].flags & 8) != 0) console_putchar('/');
        int nl = 0;
        while (dir[i].name[nl] && nl < 32) nl++;
        if ((dir[i].flags & 8) != 0) nl++;
        for (int s = nl; s < 24; s++) console_putchar(' ');
        if (nl >= 24) console_putchar(' ');
        console_printf("%u bytes  uid %u  mode %u\n",
                       dir[i].size, dir[i].uid, dir[i].mode);
        count++;
    }
    if (count == 0) console_write("(no files)\n");
    else console_printf("(%u files)\n", count);
    return count;
}
int fs_list(void) { return fs_list_as(0); }
int fs_enum_as(u32 uid, char names[][32], u32 sizes[], int max) {
    if (!mounted || max <= 0) return 0;
    int count = 0;
    for (int i = 0; i < FS_MAX_FILES && count < max; i++) {
        if (!valid_entry(&dir[i])) continue;
        if (dir[i].reserved[1] != 0) continue; /* §15: root children only */
        if (strcmp(dir[i].name, "timestamps.txt") == 0) continue; /* §15: hidden sidecar */
        if (!can_read_entry(&dir[i], uid)) continue;
        int j = 0;
        while (dir[i].name[j] && j < 31) { names[count][j] = dir[i].name[j]; j++; }
        names[count][j] = 0;
        sizes[count] = dir[i].size;
        count++;
    }
    return count;
}

/* Deep-core phase D2: FIFO entries (flags bit 2) are not files:
   whole-file reads/writes/copies refuse them; only the fd
   layer (kernel/fd.c) may open them as pipes. */
int fs_is_fifo(const char *name) {
    if (!mounted || !valid_name(name)) return 0;
    int idx = find_entry(name);
    if (idx < 0) return 0;
    return (dir[idx].flags & 4) != 0;
}

int fs_read_as(const char *name, u8 *buf, u32 buf_size, u32 *out_size, u32 uid) {
    if (!mounted || !valid_name(name)) return -1;
    char resolved[32];
    if (resolve_link(name, resolved) != 0) return -1;
    int idx = find_entry(resolved);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    if ((e->flags & 8) != 0) return -1; /* §15: a directory is not a file (use ls) */
    if ((e->flags & 4) != 0) return -1; /* FIFO: fd layer only */
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
    char resolved[32];
    if (resolve_link(name, resolved) != 0) return -1;
    int idx = find_entry(resolved);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    if ((e->flags & 8) != 0) return -1; /* §15: a directory is not a file */
    if ((e->flags & 4) != 0) return -1; /* FIFO: fd layer only */
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
    /* Writing through a link writes the target (Linux behaviour);
       the link itself is never destroyed by a write. A dangling
       link's write creates its target; a link loop still fails. */
    char wname[32];
    {
        u32 i = 0;
        while (name[i] && i < 31) { wname[i] = name[i]; i++; }
        wname[i] = 0;
        for (int hop = 0; hop < 4; hop++) {
            int wi = find_entry(wname);
            if (wi < 0) break; /* dangling target: create it */
            if ((dir[wi].flags & 2) == 0) break;
            struct dir_entry *le = &dir[wi];
            if (le->size == 0 || le->size >= 32 || le->sector_count == 0) return -1;
            if (read_sector_checked(le->start_sector, sector_buf) != 0) return -1;
            u32 j = 0;
            while (j < le->size) { wname[j] = (char)sector_buf[j]; j++; }
            wname[j] = 0;
            if (!valid_name(wname)) return -1;
            if (hop == 3) {
                /* After 4 hops the name must no longer be a link. */
                int wj = find_entry(wname);
                if (wj >= 0 && (dir[wj].flags & 2)) return -1;
            }
        }
        name = wname;
    }
    int existing = find_entry(name);
    if (existing >= 0 && (dir[existing].flags & 4) != 0) return -1; /* FIFO */
    if (existing >= 0 && (dir[existing].flags & 8) != 0) return -1; /* §15: a directory is not writable as a file */
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
    /* §15 hard-link sharing: capture the old location BEFORE the
       memset below. After the new entry is filled, every other
       entry sharing the old start_sector is repointed to the
       new location with the new size (a write through one link
       is visible through the other, Linux inode behaviour);
       only then are the old sectors freed — and only if the
       scan finds no entry still pointing at them. The old
       code freed the old range unconditionally, which would
       have freed live data out from under another link. */
    u32 old_start = 0, old_count = 0;
    if (old >= 0) { old_start = dir[old].start_sector; old_count = dir[old].sector_count; }
    struct dir_entry *e = &dir[slot];
    /* Parity run: gid lives in reserved[0] (no layout change).
       Overwrite keeps the old gid (a save must never silently
       re-group a file); create takes the creator's primary
       group (0 = no group, e.g. root). The memset below would
       zero it, so capture it first. */
    u32 new_gid = (old >= 0) ? dir[old].reserved[0] : groups_primary_gid(uid);
    memset(e, 0, sizeof(*e));
    u32 nl = strlen(name);
    memcpy(e->name, name, nl);
    e->size = len; e->start_sector = start; e->sector_count = need;
    e->uid = uid; e->mode = mode; e->flags = 1;
    e->reserved[0] = new_gid;
    if (old >= 0 && old_count > 0) {
        for (int j = 0; j < FS_MAX_FILES; j++) {
            if (j == slot) continue;
            if (!valid_entry(&dir[j])) continue;
            if (dir[j].sector_count == 0) continue;
            if ((dir[j].flags & 14) != 0) continue; /* symlink/dir/FIFO never share data */
            if (dir[j].start_sector != old_start) continue;
            dir[j].start_sector = start; dir[j].sector_count = need; dir[j].size = len;
        }
        int kept = 0;
        for (int j = 0; j < FS_MAX_FILES; j++) {
            if (!valid_entry(&dir[j])) continue;
            if (dir[j].sector_count == 0) continue;
            if (dir[j].start_sector == old_start) { kept = 1; break; }
        }
        if (!kept) {
            for (u32 i = 0; i < old_count; i++) bit_set(old_start + i, 0);
        }
        for (u32 i = 0; i < need; i++) bit_set(start + i, 1);
    }
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    if (!ts_busy && strcmp(name, "timestamps.txt") != 0) ts_touch(0, name, 1, 1);
    return 0;
}

int fs_write(const char *name, const u8 *data, u32 len, u32 uid, u32 mode) {
    return fs_write_as(name, data, len, uid, mode);
}

/* Deep-core phase D2: metadata probe for the fd layer.
   Unlike fs_stat_as (which applies the read rule), this
   checks exactly the permissions the caller asks for, so a
   write-only open of a write-only file can probe its size,
   owner, and mode. Resolves links like the read/write
   paths. 0 ok (stat filled), -1 denied, -2 not found. */
int fs_meta_as(const char *name, u32 uid, int want_r, int want_w, struct fs_stat *out) {
    if (!mounted || !valid_name(name) || !out) return -1;
    /* resolve_link returns -1 for a missing name too, so check
       existence first: a name with no entry at all is simply
       not found (-2), which is what O_CREAT needs to tell
       apart from a permission denial. A dangling link (entry
       exists, target missing) still resolves to -1. */
    if (find_entry(name) < 0) return -2;
    char resolved[32];
    if (resolve_link(name, resolved) != 0) return -1;
    int idx = find_entry(resolved);
    if (idx < 0) return -2;
    struct dir_entry *e = &dir[idx];
    if (want_r && !can_read_entry(e, uid)) return -1;
    if (want_w && !can_write_entry(e, uid)) return -1;
    out->size = e->size;
    out->uid = e->uid;
    out->mode = e->mode;
    out->sectors = e->sector_count;
    out->gid = e->reserved[0];
    out->is_dir = (e->flags & 8) != 0;
    if (ts_lookup(e->reserved[1], e->name, &out->mtime, &out->atime) != 0) { out->mtime = 0; out->atime = 0; }
    return 0;
}

/* Deep-core phase D2: create a named FIFO (flags bit 2, no
   layout change). No sectors: the ring lives in the kernel
   while the FIFO is open. Same creation rules as a file
   write (non-root may not create system names). */
int fs_mkfifo_as(const char *name, u32 uid) {
    if (!mounted || !valid_name(name)) return -1;
    if (find_entry(name) >= 0) return -1;
    if (uid != 0 && is_system_file(name)) return -1;
    int slot = -1;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if ((dir[i].flags & 1) == 0) { slot = i; break; }
    }
    if (slot < 0) return -1; /* directory full */
    struct dir_entry *e = &dir[slot];
    memset(e, 0, sizeof(*e));
    u32 nl = strlen(name);
    memcpy(e->name, name, nl);
    e->size = 0; e->start_sector = 0; e->sector_count = 0;
    e->uid = uid; e->mode = 0644; e->flags = 1 | 4;
    e->reserved[0] = groups_primary_gid(uid);
    if (save_dir() != 0) return -1;
    return 0;
}

int fs_delete_as(const char *name, u32 uid) {
    if (!mounted || !valid_name(name)) return -1;
    int idx = find_entry(name);
    if (idx < 0) return -1;
    if ((dir[idx].flags & 8) != 0) return -1; /* §15: directories are removed with rmdir, never rm */
    if (!can_write_entry(&dir[idx], uid)) return -1;
    struct dir_entry *e = &dir[idx];
    /* §15: the scan IS the link count — free the data sectors
       only when no other entry shares this start_sector. */
    if (e->sector_count > 0) {
        int kept = 0;
        for (int j = 0; j < FS_MAX_FILES; j++) {
            if (j == idx) continue;
            if (!valid_entry(&dir[j])) continue;
            if (dir[j].sector_count == 0) continue;
            if ((dir[j].flags & 14) != 0) continue;
            if (dir[j].start_sector == e->start_sector) { kept = 1; break; }
        }
        if (!kept) {
            for (u32 i = 0; i < e->sector_count; i++) bit_set(e->start_sector + i, 0);
        }
    }
    memset(e, 0, sizeof(*e));
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    if (!ts_busy) ts_remove(0, name);
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
    if (!ts_busy) ts_move(0, oldname, 0, newname);
    return 0;
}

/* Metadata-only owner change: only the uid changes; mode, size
   and data sectors are untouched, so a chown can never silently
   re-permit or truncate a file. ONLY root may change an owner —
   enforced here in the fs layer as well as in the shell handler,
   so a future caller cannot bypass the gate by calling this
   directly. A non-existent file is refused, never created. */
int fs_chown_as(const char *name, u32 new_uid, u32 caller_uid) {
    if (!mounted || !valid_name(name)) return -1;
    if (caller_uid != 0) return -1;
    char resolved[32];
    if (resolve_link(name, resolved) != 0) return -1;
    int idx = find_entry(resolved);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    e->uid = new_uid;
    if (save_dir() != 0) return -1;
    return 0;
}

/* Metadata-only group change (parity run): only reserved[0]
   (the gid) changes; mode, size and data sectors are
   untouched. ONLY root may change a group — enforced here
   in the fs layer as well as in the shell handler, mirroring
   fs_chown_as. A non-existent file is refused, never created. */
int fs_chgrp_as(const char *name, u32 new_gid, u32 caller_uid) {
    if (!mounted || !valid_name(name)) return -1;
    if (caller_uid != 0) return -1;
    char resolved[32];
    if (resolve_link(name, resolved) != 0) return -1;
    int idx = find_entry(resolved);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    e->reserved[0] = new_gid;
    if (save_dir() != 0) return -1;
    return 0;
}
/* Metadata read: size, owner, mode, group, sector count. Allowed iff
   the caller is root, owns the file, or may read it — metadata
   disclosure follows the read rule, so a user who cannot read
   a file learns nothing about it from stat (missing and
   unreadable both return -1). */
int fs_stat_as(const char *name, struct fs_stat *out, u32 uid) {
    if (!mounted || !valid_name(name) || !out) return -1;
    char resolved[32];
    if (resolve_link(name, resolved) != 0) return -1;
    int idx = find_entry(resolved);
    if (idx < 0) return -1;
    struct dir_entry *e = &dir[idx];
    if (uid != 0 && e->uid != uid && !can_read_entry(e, uid)) return -1;
    out->size = e->size;
    out->uid = e->uid;
    out->mode = e->mode;
    out->sectors = e->sector_count;
    out->gid = e->reserved[0];
    out->is_dir = (e->flags & 8) != 0;
    if (ts_lookup(e->reserved[1], e->name, &out->mtime, &out->atime) != 0) { out->mtime = 0; out->atime = 0; }
    return 0;
}
int fs_chmod_as(const char *name, u32 mode, u32 uid) {
    if (!mounted || !valid_name(name) || mode > 0777) return -1;
    char resolved[32];
    if (resolve_link(name, resolved) != 0) return -1;
    int idx = find_entry(resolved);
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
    char sresolved[32];
    if (resolve_link(srcname, sresolved) != 0) return -1;
    srcname = sresolved;
    int idx = find_entry(srcname);
    if (idx < 0) return -1;
    if (find_entry(dstname) >= 0) return -1;
    struct dir_entry *src = &dir[idx];
    if ((src->flags & 8) != 0) return -1; /* §15: directories are not copied as files */
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
        /* Copy creates a new file, so it takes the creator's
           primary group (like create) — never the source's
           gid, and never a silently dropped group. */
        e->reserved[0] = groups_primary_gid(uid);
    }
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    return 0;
fail:
    for (u32 i = 0; i < copied; i++) bit_set(start + i, 0);
    return -1;
}

/* ============ §15: timestamp sidecar ============
   dir_entry has no time fields and its 64-byte slot is full,
   so mtime/atime live in a root-owned hidden sidecar file,
   "timestamps.txt" (0600, system-file protected, never listed
   by ls/enum). Lines are "P<TAB>NAME<TAB>MT<TAB>AT" where P
   is the entry's parent field (0 = root child, else parent
   entry index + 1) and MT/AT are 100 Hz tick counts since
   boot (timer_ticks) — NOT wall-clock times; the fs layer
   has no RTC-to-epoch conversion, and a tick count labelled
   as a tick count is honest where a fabricated date would
   not be. Files survive sidecar loss, timestamps do not:
   a missing or corrupt sidecar line simply reads as 0
   (unknown). Names containing ':' are fine (the separator
   is TAB, and TAB cannot appear in a valid name); a name
   containing TAB cannot exist, so the format cannot be
   confused by a filename. A v2 on-disk format with wider
   entries remains a future step, not a hidden change. */
static char ts_read[4096];
static char ts_out[4096];
static u32 ts_now(void) { return timer_ticks; }
static int ts_parse_num(const char *s, u32 len, u32 *out) {
    u32 v = 0;
    if (len == 0) return -1;
    for (u32 i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10u + (u32)(s[i] - '0');
        if (v > 4000000000u) return -1;
    }
    *out = v;
    return 0;
}
/* Parse one sidecar line (no trailing newline). Returns 0 and
   fills pfield/name/mt/at, or -1 if malformed. */
static int ts_parse_line(const char *line, u32 len, u32 *pfield, char *name, u32 *mt, u32 *at) {
    u32 i = 0, start = 0;
    while (i < len && line[i] != '\t') i++;
    if (i >= len || ts_parse_num(line, i, pfield) != 0) return -1;
    start = i + 1; i = start;
    while (i < len && line[i] != '\t') i++;
    if (i >= len || i - start == 0 || i - start > 31) return -1;
    u32 nl = i - start;
    for (u32 k = 0; k < nl; k++) name[k] = line[start + k];
    name[nl] = 0;
    start = i + 1; i = start;
    while (i < len && line[i] != '\t') i++;
    if (i >= len || ts_parse_num(line + start, i - start, mt) != 0) return -1;
    start = i + 1;
    if (ts_parse_num(line + start, len - start, at) != 0) return -1;
    return 0;
}
static void ts_emit_line(char *dst, u32 *pos, u32 pfield, const char *name, u32 mt, u32 at) {
    /* Appends "P\tNAME\tMT\tAT\n" if it fits in 4096 bytes. */
    char num[16];
    u32 p = *pos;
    u32 v = pfield; int nd = 0;
    if (v == 0) num[nd++] = '0';
    else { char rev[12]; int rn = 0; while (v > 0) { rev[rn++] = (char)('0' + (v % 10)); v /= 10; } while (rn > 0) num[nd++] = rev[--rn]; }
    if (p + (u32)nd + 1 + 31 + 1 + 11 + 1 + 11 + 1 > 4095) return;
    for (int k = 0; k < nd; k++) dst[p++] = num[k];
    dst[p++] = '\t';
    u32 nl = strlen(name);
    for (u32 k = 0; k < nl; k++) dst[p++] = name[k];
    dst[p++] = '\t';
    v = mt; nd = 0;
    if (v == 0) num[nd++] = '0';
    else { char rev[12]; int rn = 0; while (v > 0) { rev[rn++] = (char)('0' + (v % 10)); v /= 10; } while (rn > 0) num[nd++] = rev[--rn]; }
    for (int k = 0; k < nd; k++) dst[p++] = num[k];
    dst[p++] = '\t';
    v = at; nd = 0;
    if (v == 0) num[nd++] = '0';
    else { char rev[12]; int rn = 0; while (v > 0) { rev[rn++] = (char)('0' + (v % 10)); v /= 10; } while (rn > 0) num[nd++] = rev[--rn]; }
    for (int k = 0; k < nd; k++) dst[p++] = num[k];
    dst[p++] = '\n';
    *pos = p;
}
/* mode: 0 remove, 1 touch, 2 move, 3 purge-parent. Touch sets
   MT when mt_flag and AT when at_flag to now; a missing line
   is created by a touch (MT/AT 0 for the untouched field).
   Never fails the caller's operation: all errors are silent. */
static void ts_rewrite(u32 pfield, const char *name, u32 new_pf, const char *new_name, int mode, int mt_flag, int at_flag) {
    if (!mounted) return;
    if (ts_busy) return;
    if (name && strcmp(name, "timestamps.txt") == 0) return;
    u32 got = 0;
    int existed = (find_entry("timestamps.txt") >= 0);
    if (existed) {
        if (fs_read_as("timestamps.txt", (u8 *)ts_read, sizeof(ts_read) - 1, &got, 0) != 0) got = 0;
    }
    ts_read[got] = 0;
    u32 out_pos = 0;
    int found = 0, changed = 0;
    u32 i = 0;
    while (i < got) {
        u32 j = i;
        while (j < got && ts_read[j] != '\n') j++;
        u32 lp = 0, mt = 0, at = 0;
        char lname[32];
        int ok = (ts_parse_line(ts_read + i, j - i, &lp, lname, &mt, &at) == 0);
        if (mode == 3) {
            if (ok && lp == pfield) { changed = 1; }
            else if (ok) ts_emit_line(ts_out, &out_pos, lp, lname, mt, at);
            /* malformed lines are dropped: the sidecar is
               kernel-owned scratch, never user data */
        } else if (ok && lp == pfield && strcmp(lname, name) == 0) {
            found = 1;
            if (mode == 0) { changed = 1; }
            else if (mode == 1) {
                if (mt_flag) mt = ts_now();
                if (at_flag) at = ts_now();
                ts_emit_line(ts_out, &out_pos, lp, lname, mt, at);
                changed = 1;
            } else if (mode == 2) {
                ts_emit_line(ts_out, &out_pos, new_pf, new_name, mt, at);
                changed = 1;
            }
        } else if (ok) {
            ts_emit_line(ts_out, &out_pos, lp, lname, mt, at);
        } else {
            changed = 1; /* drop a malformed line */
        }
        i = (j < got) ? j + 1 : got;
    }
    if (mode == 1 && !found) {
        ts_emit_line(ts_out, &out_pos, pfield, name, mt_flag ? ts_now() : 0, at_flag ? ts_now() : 0);
        changed = 1;
    }
    if (!changed) return;
    if (out_pos == 0 && !existed) return;
    ts_busy = 1;
    fs_write_as("timestamps.txt", (const u8 *)ts_out, out_pos, 0, 0600);
    ts_busy = 0;
}
static void ts_touch(u32 pfield, const char *name, int mt_flag, int at_flag) {
    ts_rewrite(pfield, name, 0, "", 1, mt_flag, at_flag);
}
static void ts_remove(u32 pfield, const char *name) {
    ts_rewrite(pfield, name, 0, "", 0, 0, 0);
}
static void ts_move(u32 old_pf, const char *old_name, u32 new_pf, const char *new_name) {
    ts_rewrite(old_pf, old_name, new_pf, new_name, 2, 0, 0);
}
static void ts_purge_parent(u32 pfield) {
    ts_rewrite(pfield, "", 0, "", 3, 0, 0);
}
static int ts_lookup(u32 pfield, const char *name, u32 *mt, u32 *at) {
    if (!mounted) return -1;
    if (find_entry("timestamps.txt") < 0) return -1;
    u32 got = 0;
    if (fs_read_as("timestamps.txt", (u8 *)ts_read, sizeof(ts_read) - 1, &got, 0) != 0) return -1;
    u32 i = 0;
    while (i < got) {
        u32 j = i;
        while (j < got && ts_read[j] != '\n') j++;
        u32 lp = 0, m = 0, a = 0;
        char lname[32];
        if (ts_parse_line(ts_read + i, j - i, &lp, lname, &m, &a) == 0
            && lp == pfield && strcmp(lname, name) == 0) {
            *mt = m; *at = a; return 0;
        }
        i = (j < got) ? j + 1 : got;
    }
    return -1;
}

/* ============ §15: path layer ============
   All buffers below are file-scope statics (16 KiB kernel
   stack: no component array ever lives on the stack). */
static char vfs_lex[16][32];
static char vfs_base[16][32];
static char vfs_tgt[16][32];
static char vfs_expA[24][32];
static char vfs_expB[24][32];
static char vfs_tstr[256];

static void vfs_copy_comp(char *dst, const char *src, u32 len) {
    u32 k = 0;
    while (k < len && k < 31) { dst[k] = src[k]; k++; }
    dst[k] = 0;
}
static int vfs_comp_ok(const char *s, u32 len) {
    if (len == 0 || len > 31) return 0;
    for (u32 i = 0; i < len; i++) {
        char c = s[i];
        if (c < 32 || c > 126 || c == '/') return 0;
    }
    return 1;
}
/* Lexical resolution: base comps + path -> out comps. Absolute
   paths ignore base; '.' is skipped, '..' pops (clamped at
   root). Returns 0 or -1 (malformed: empty component, overlong
   component, > 16 components, total path > 255, trailing slash,
   control characters). */
static int lex_comps(const char *path, char base[][32], int base_n, char out[][32], int *out_n) {
    if (!path || !path[0]) return -1;
    u32 len = strlen(path);
    if (len > 255) return -1;
    if (len > 1 && path[len - 1] == '/') return -1;
    int n = 0;
    if (path[0] != '/') {
        if (base_n < 0 || base_n > 16) return -1;
        for (int i = 0; i < base_n; i++) vfs_copy_comp(out[n++], base[i], strlen(base[i]));
    }
    if (path[0] == '/' && len == 1) { *out_n = 0; return 0; }
    u32 i = (path[0] == '/') ? 1 : 0;
    while (i < len) {
        u32 j = i;
        while (j < len && path[j] != '/') j++;
        u32 sl = j - i;
        if (sl == 0) return -1; /* "//" */
        if (sl == 1 && path[i] == '.') {
            /* skip */
        } else if (sl == 2 && path[i] == '.' && path[i + 1] == '.') {
            if (n > 0) n--;
        } else {
            if (!vfs_comp_ok(path + i, sl)) return -1;
            if (n >= 16) return -1;
            vfs_copy_comp(out[n++], path + i, sl);
        }
        i = j + 1;
    }
    *out_n = n;
    return 0;
}
/* Parent of an entry index: -1 for root children, else the
   parent entry index. The parent field is reserved[1]. */
static int dir_parent_idx(int idx) {
    if (idx < 0) return -1;
    if (dir[idx].reserved[1] == 0) return -1;
    if (dir[idx].reserved[1] > FS_MAX_FILES) return -1;
    return (int)dir[idx].reserved[1] - 1;
}
static int find_child(int parent_idx, const char *name) {
    u32 want = (parent_idx < 0) ? 0 : (u32)parent_idx + 1;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if (!valid_entry(&dir[i])) continue;
        if (dir[i].reserved[1] != want) continue;
        if (strcmp(dir[i].name, name) == 0) return i;
    }
    return -1;
}
/* Component list of a directory entry's path (root -> -1). */
static int dir_comps(int idx, char out[][32], int *out_n) {
    char rev[16][32];
    int rn = 0, cur = idx;
    while (cur >= 0) {
        if (rn >= 16) return -1;
        vfs_copy_comp(rev[rn++], dir[cur].name, strlen(dir[cur].name));
        cur = dir_parent_idx(cur);
    }
    for (int i = 0; i < rn; i++) vfs_copy_comp(out[i], rev[rn - 1 - i], strlen(rev[rn - 1 - i]));
    *out_n = rn;
    return 0;
}
static int link_target(int idx, char *out, u32 out_size) {
    struct dir_entry *e = &dir[idx];
    if (e->size == 0 || e->size >= out_size || e->sector_count == 0) return -1;
    u32 done = 0;
    for (u32 i = 0; i < e->sector_count && done < e->size; i++) {
        if (read_sector_checked(e->start_sector + i, sector_buf) != 0) return -1;
        u32 chunk = e->size - done;
        if (chunk > 512) chunk = 512;
        memcpy(out + done, sector_buf, chunk);
        done += chunk;
    }
    out[done] = 0;
    for (u32 i = 0; i < done; i++) if (out[i] < 32 || out[i] > 126) return -1;
    return 0;
}
/* Walk a component list. Returns 0 with *out_idx = entry index
   (or -2 for root) and *out_parent = parent index (or -1 for
   root); -1 not found/loop, -2 a component is not a
   directory, -3 permission denied (traversal needs read on
   each intermediate directory; the root is always open).
   Intermediate symlinks always expand; the final component
   expands only when follow_final is set. The hop budget is
   4 expansions per whole path resolution. */
static int walk_comps(char comps[][32], int n, u32 uid, int follow_final, int *out_idx, int *out_parent) {
    if (n == 0) { *out_idx = -2; *out_parent = -1; return 0; }
    char (*cur)[32] = comps;
    int cur_n = n, useA = 1, hops = 0;
    for (;;) {
        int restart = 0, pdir = -1;
        for (int i = 0; i < cur_n; i++) {
            int child = find_child(pdir, cur[i]);
            if (child < 0) return -1;
            struct dir_entry *e = &dir[child];
            int is_link = (e->flags & 2) != 0;
            int is_last = (i == cur_n - 1);
            if (is_link && (!is_last || follow_final)) {
                if (hops >= 4) return -1;
                hops++;
                if (link_target(child, vfs_tstr, sizeof(vfs_tstr)) != 0) return -1;
                int bn = 0;
                if (vfs_tstr[0] != '/') {
                    if (dir_comps(pdir, vfs_base, &bn) != 0) return -1;
                }
                int tn = 0;
                if (lex_comps(vfs_tstr, vfs_base, bn, vfs_tgt, &tn) != 0) return -1;
                int nn = tn + (cur_n - i - 1);
                if (nn > 24) return -1;
                char (*dst)[32] = useA ? vfs_expB : vfs_expA;
                useA = !useA;
                for (int k = 0; k < tn; k++) vfs_copy_comp(dst[k], vfs_tgt[k], strlen(vfs_tgt[k]));
                for (int k = 0; k < cur_n - i - 1; k++) vfs_copy_comp(dst[tn + k], cur[i + 1 + k], strlen(cur[i + 1 + k]));
                cur = dst; cur_n = nn;
                restart = 1;
                break;
            }
            if (!is_last) {
                if ((e->flags & 8) == 0) return -2;
                if (uid != 0 && !can_read_entry(e, uid)) return -3;
                pdir = child;
            } else {
                *out_idx = child; *out_parent = pdir;
                return 0;
            }
        }
        if (!restart) return -1;
    }
}
/* Resolve a user path. Returns 0/-1/-2/-3 as walk_comps, or
   -4 for a malformed path. */
static int vfs_resolve(const char *path, const char *cwd, u32 uid, int follow_final, int *out_idx, int *out_parent) {
    if (!mounted || !path || !cwd) return -1;
    int cn = 0;
    if (lex_comps(cwd, vfs_tgt, 0, vfs_base, &cn) != 0) return -4;
    int n = 0;
    if (lex_comps(path, vfs_base, cn, vfs_lex, &n) != 0) return -4;
    return walk_comps(vfs_lex, n, uid, follow_final, out_idx, out_parent);
}
/* Resolve the parent directory of a path + its basename.
   Returns 0 with *out_parent (-1 = root), or -1/-2/-3/-4 as
   vfs_resolve, or -5 when the path is the root itself. */
static int vfs_resolve_parent(const char *path, const char *cwd, u32 uid, int *out_parent, char *basename_out) {
    if (!mounted || !path || !cwd) return -1;
    int cn = 0;
    if (lex_comps(cwd, vfs_tgt, 0, vfs_base, &cn) != 0) return -4;
    int n = 0;
    if (lex_comps(path, vfs_base, cn, vfs_lex, &n) != 0) return -4;
    if (n == 0) return -5;
    vfs_copy_comp(basename_out, vfs_lex[n - 1], strlen(vfs_lex[n - 1]));
    int idx = -2, par = -1;
    int r = walk_comps(vfs_lex, n - 1, uid, 1, &idx, &par);
    if (r != 0) return r;
    if (idx == -2) { *out_parent = -1; return 0; }
    if ((dir[idx].flags & 8) == 0) return -2;
    *out_parent = idx;
    return 0;
}
static int parent_writable(int parent_idx, u32 uid) {
    if (parent_idx < 0) return 1; /* root: file rules govern */
    if (uid == 0) return 1;
    return can_write_entry(&dir[parent_idx], uid);
}
static void parent_mtime_touch(int parent_idx) {
    if (parent_idx < 0) return;
    ts_touch(dir[parent_idx].reserved[1], dir[parent_idx].name, 1, 0);
}
/* Free data sectors only when the scan finds no other entry
   sharing this start_sector (the scan IS the link count). */
static void free_sectors_scanned(int idx) {
    struct dir_entry *e = &dir[idx];
    if (e->sector_count == 0) return;
    for (int j = 0; j < FS_MAX_FILES; j++) {
        if (j == idx) continue;
        if (!valid_entry(&dir[j])) continue;
        if (dir[j].sector_count == 0) continue;
        if ((dir[j].flags & 14) != 0) continue;
        if (dir[j].start_sector == e->start_sector) return;
    }
    for (u32 i = 0; i < e->sector_count; i++) bit_set(e->start_sector + i, 0);
}
/* Create one entry (caller has done parent/exists/permission
   checks). flags: 0 file, 2 symlink, 4 FIFO, 8 directory.
   Files/symlinks allocate data sectors; dirs/FIFOs none. */
static int create_entry(int parent_idx, const char *name, u32 uid, u32 mode, u32 flags, const u8 *data, u32 len, int *out_idx) {
    int slot = -1;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if ((dir[i].flags & 1) == 0) { slot = i; break; }
    }
    if (slot < 0) return -8;
    u32 need = 0, start = 0;
    int is_dir = (flags & 8) != 0, is_fifo = (flags & 4) != 0;
    if (!is_dir && !is_fifo) {
        need = (len + 511) / 512;
        if (need == 0) need = 1;
        if (find_contiguous(need, &start) != 0) return -8;
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
    }
    struct dir_entry *e = &dir[slot];
    memset(e, 0, sizeof(*e));
    u32 nl = strlen(name);
    memcpy(e->name, name, nl);
    e->size = (is_dir || is_fifo) ? 0 : len;
    e->start_sector = start;
    e->sector_count = (is_dir || is_fifo) ? 0 : need;
    e->uid = uid; e->mode = mode; e->flags = 1 | flags;
    e->reserved[0] = groups_primary_gid(uid);
    e->reserved[1] = (parent_idx < 0) ? 0 : (u32)parent_idx + 1;
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    *out_idx = slot;
    return 0;
}
/* Overwrite an existing regular file entry with new data,
   repointing every hard-link sharer to the new location
   (same semantics as the flat write tail). */
static int write_entry_data(int idx, const u8 *data, u32 len, u32 uid, u32 mode) {
    u32 need = (len + 511) / 512;
    if (need == 0) need = 1;
    u32 start = 0;
    if (find_contiguous(need, &start) != 0) return -8;
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
    struct dir_entry *self = &dir[idx];
    u32 old_start = self->start_sector, old_count = self->sector_count;
    u32 old_gid = self->reserved[0];
    if (old_count > 0) {
        for (int j = 0; j < FS_MAX_FILES; j++) {
            if (j == idx) continue;
            if (!valid_entry(&dir[j])) continue;
            if (dir[j].sector_count == 0) continue;
            if ((dir[j].flags & 14) != 0) continue;
            if (dir[j].start_sector != old_start) continue;
            dir[j].start_sector = start; dir[j].sector_count = need; dir[j].size = len;
        }
    }
    self->start_sector = start; self->sector_count = need; self->size = len;
    self->uid = uid; self->mode = mode; self->reserved[0] = old_gid;
    /* Every sharer was repointed above, so no entry points at
       the old range any more: freeing it directly is exact.
       (free_sectors_scanned would look at the NEW start here,
       find the just-repointed sharers, and leak the old range.) */
    for (u32 i = 0; i < old_count; i++) bit_set(old_start + i, 0);
    for (u32 i = 0; i < need; i++) bit_set(start + i, 1);
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    return 0;
}
static void fill_stat_idx(int idx, struct fs_stat *out) {
    if (idx == -2) {
        out->size = 0; out->uid = 0; out->mode = 0755; out->sectors = 0;
        out->gid = 0; out->is_dir = 1; out->mtime = 0; out->atime = 0;
        return;
    }
    struct dir_entry *e = &dir[idx];
    out->size = e->size; out->uid = e->uid; out->mode = e->mode;
    out->sectors = e->sector_count; out->gid = e->reserved[0];
    out->is_dir = (e->flags & 8) != 0;
    if (ts_lookup(e->reserved[1], e->name, &out->mtime, &out->atime) != 0) { out->mtime = 0; out->atime = 0; }
}

int fs_canonical_path(const char *path, const char *cwd, char *out, u32 out_size) {
    if (!path || !cwd || !out || out_size < 2) return -1;
    int cn = 0;
    if (lex_comps(cwd, vfs_tgt, 0, vfs_base, &cn) != 0) return -1;
    int n = 0;
    if (lex_comps(path, vfs_base, cn, vfs_lex, &n) != 0) return -1;
    if (n == 0) { out[0] = '/'; out[1] = 0; return 0; }
    u32 pos = 0;
    for (int i = 0; i < n; i++) {
        u32 cl = strlen(vfs_lex[i]);
        if (pos + 1 + cl + 1 > out_size) return -1;
        out[pos++] = '/';
        for (u32 k = 0; k < cl; k++) out[pos++] = vfs_lex[i][k];
    }
    out[pos] = 0;
    return 0;
}
int fs_dir_status_path(const char *path, const char *cwd, u32 uid) {
    if (!mounted) return 1;
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, uid, 1, &idx, &par);
    if (r == -4) return 4;
    if (r == -3) return 3;
    if (r == -2) return 2;
    if (r != 0) return 1;
    if (idx == -2) return 0;
    if ((dir[idx].flags & 8) == 0) return 2;
    if (uid != 0 && !can_read_entry(&dir[idx], uid)) return 3;
    return 0;
}
static int path_read_common(const char *path, const char *cwd, u8 *buf, u32 buf_size, u32 offset, u32 range, u32 *out_size, u32 uid) {
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, uid, 1, &idx, &par);
    if (r != 0) return r;
    if (idx == -2) return -7;
    struct dir_entry *e = &dir[idx];
    if ((e->flags & 8) != 0) return -7;
    if ((e->flags & 4) != 0) return -1;
    if (!can_read_entry(e, uid)) return -3;
    if (range) {
        if (offset >= e->size || buf_size == 0) { *out_size = 0; ts_touch(e->reserved[1], e->name, 0, 1); return 0; }
        u32 want = e->size - offset;
        if (want > buf_size) want = buf_size;
        u32 done = 0, pos = offset;
        while (done < want) {
            u32 sec = pos / 512, within = pos % 512;
            if (sec >= e->sector_count) break;
            if (read_sector_checked(e->start_sector + sec, sector_buf) != 0) return -1;
            u32 chunk = 512 - within;
            if (chunk > want - done) chunk = want - done;
            memcpy(buf + done, sector_buf + within, chunk);
            done += chunk; pos += chunk;
        }
        *out_size = done;
    } else {
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
    }
    ts_touch(e->reserved[1], e->name, 0, 1);
    return 0;
}
int fs_read_path(const char *path, const char *cwd, u8 *buf, u32 buf_size, u32 *out_size, u32 uid) {
    if (!mounted || !buf || !out_size) return -1;
    return path_read_common(path, cwd, buf, buf_size, 0, 0, out_size, uid);
}
int fs_read_range_path(const char *path, const char *cwd, u8 *buf, u32 buf_size, u32 offset, u32 *out_size, u32 uid) {
    if (!mounted || !buf || !out_size) return -1;
    return path_read_common(path, cwd, buf, buf_size, offset, 1, out_size, uid);
}
static int write_depth = 0;
int fs_write_path(const char *path, const char *cwd, const u8 *data, u32 len, u32 uid, u32 mode) {
    if (!mounted || mode > 0777) return -1;
    int parent = -1;
    char base[32];
    int r = vfs_resolve_parent(path, cwd, uid, &parent, base);
    if (r == -5) return -4; /* the path IS the root: not a file */
    if (r != 0) return r;
    int child = find_child(parent, base);
    if (child >= 0) {
        struct dir_entry *e = &dir[child];
        if ((e->flags & 2) != 0) {
            /* Write through a link: follow it. If the target
               exists, write it in place; if it dangles, create
               it by writing to the target path (relative to
               the link's parent directory, as the path layer
               resolves it). Depth-capped so a link loop ends
               in a refusal, never recursion without end. */
            int tidx = -2, tpar = -1;
            int rr = vfs_resolve(path, cwd, uid, 1, &tidx, &tpar);
            if (rr == 0 && tidx != -2) {
                struct dir_entry *t = &dir[tidx];
                if ((t->flags & 8) != 0) return -7;
                if ((t->flags & 4) != 0) return -1;
                if (!can_write_entry(t, uid)) return -3;
                if (write_entry_data(tidx, data, len, uid, mode) != 0) return -1;
                ts_touch(t->reserved[1], t->name, 1, 1);
                return 0;
            }
            if (write_depth >= 4) return -1;
            if (link_target(child, vfs_tstr, sizeof(vfs_tstr)) != 0) return -1;
            /* Build the target's absolute path: absolute
               targets stand; relative targets resolve from
               the link's parent directory. */
            char tabs[256];
            if (vfs_tstr[0] == '/') {
                u32 k = 0;
                while (vfs_tstr[k] && k < 255) { tabs[k] = vfs_tstr[k]; k++; }
                tabs[k] = 0;
            } else {
                int bn = 0;
                if (dir_comps(parent, vfs_base, &bn) != 0) return -1;
                char pc[256];
                u32 pos = 0;
                pc[pos++] = '/';
                for (int i = 0; i < bn; i++) {
                    u32 cl = strlen(vfs_base[i]);
                    for (u32 k = 0; k < cl && pos < 254; k++) pc[pos++] = vfs_base[i][k];
                    pc[pos++] = '/';
                }
                u32 tl = strlen(vfs_tstr);
                for (u32 k = 0; k < tl && pos < 255; k++) pc[pos++] = vfs_tstr[k];
                pc[pos] = 0;
                u32 k = 0;
                while (pc[k] && k < 255) { tabs[k] = pc[k]; k++; }
                tabs[k] = 0;
            }
            write_depth++;
            int wr = fs_write_path(tabs, "/", data, len, uid, mode);
            write_depth--;
            return wr;
        }
        if ((e->flags & 8) != 0) return -7;
        if ((e->flags & 4) != 0) return -1;
        if (!can_write_entry(e, uid)) return -3;
        if (write_entry_data(child, data, len, uid, mode) != 0) return -1;
        ts_touch(e->reserved[1], e->name, 1, 1);
        parent_mtime_touch(parent);
        return 0;
    }
    if (!parent_writable(parent, uid)) return -3;
    if (uid != 0 && is_system_file(base)) return -3;
    int idx = -1;
    if (create_entry(parent, base, uid, mode, 0, data, len, &idx) != 0) return -1;
    ts_touch((parent < 0) ? 0 : (u32)parent + 1, base, 1, 1);
    parent_mtime_touch(parent);
    return 0;
}
int fs_delete_path(const char *path, const char *cwd, u32 uid) {
    if (!mounted) return -1;
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, uid, 0, &idx, &par);
    if (r != 0) return r;
    if (idx == -2) return -7;
    struct dir_entry *e = &dir[idx];
    if ((e->flags & 8) != 0) return -7; /* use rmdir */
    if (!parent_writable(par, uid)) return -3;
    if (!can_write_entry(e, uid)) return -3;
    u32 pf = e->reserved[1];
    char nm[32];
    vfs_copy_comp(nm, e->name, strlen(e->name));
    free_sectors_scanned(idx);
    memset(e, 0, sizeof(*e));
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    ts_remove(pf, nm);
    parent_mtime_touch(par);
    return 0;
}
int fs_stat_path(const char *path, const char *cwd, struct fs_stat *out, u32 uid) {
    if (!mounted || !out) return -1;
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, uid, 1, &idx, &par);
    if (r != 0) return r;
    if (idx == -2) { fill_stat_idx(-2, out); return 0; }
    struct dir_entry *e = &dir[idx];
    if (uid != 0 && e->uid != uid && !can_read_entry(e, uid)) return -3;
    fill_stat_idx(idx, out);
    return 0;
}
int fs_list_path(const char *path, const char *cwd, u32 uid) {
    if (!mounted) return -1;
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, uid, 1, &idx, &par);
    if (r != 0) return r;
    int parent_idx = -1;
    if (idx == -2) parent_idx = -1;
    else {
        if ((dir[idx].flags & 8) == 0) {
            /* A file path lists just that file, Linux-style. */
            if (uid != 0 && !can_read_entry(&dir[idx], uid)) return -3;
            console_write("NAME                    SIZE  UID  MODE\n");
            console_write(dir[idx].name);
            int nl = 0;
            while (dir[idx].name[nl] && nl < 32) nl++;
            for (int s = nl; s < 24; s++) console_putchar(' ');
            if (nl >= 24) console_putchar(' ');
            console_printf("%u bytes  uid %u  mode %u\n", dir[idx].size, dir[idx].uid, dir[idx].mode);
            console_write("(1 files)\n");
            return 1;
        }
        if (uid != 0 && !can_read_entry(&dir[idx], uid)) return -3;
        parent_idx = idx;
    }
    u32 want = (parent_idx < 0) ? 0 : (u32)parent_idx + 1;
    console_write("NAME                    SIZE  UID  MODE\n");
    int count = 0;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if (!valid_entry(&dir[i])) continue;
        if (dir[i].reserved[1] != want) continue;
        if (strcmp(dir[i].name, "timestamps.txt") == 0) continue;
        if (!can_read_entry(&dir[i], uid)) continue;
        console_write(dir[i].name);
        if ((dir[i].flags & 8) != 0) console_putchar('/');
        int nl = 0;
        while (dir[i].name[nl] && nl < 32) nl++;
        if ((dir[i].flags & 8) != 0) nl++;
        for (int s = nl; s < 24; s++) console_putchar(' ');
        if (nl >= 24) console_putchar(' ');
        console_printf("%u bytes  uid %u  mode %u\n", dir[i].size, dir[i].uid, dir[i].mode);
        count++;
    }
    if (count == 0) console_write("(no files)\n");
    else console_printf("(%u files)\n", count);
    if (parent_idx >= 0) ts_touch(dir[parent_idx].reserved[1], dir[parent_idx].name, 0, 1);
    return count;
}
int fs_mkdir_path(const char *path, const char *cwd, u32 uid, u32 mode) {
    if (!mounted || mode > 0777) return -1;
    int parent = -1;
    char base[32];
    int r = vfs_resolve_parent(path, cwd, uid, &parent, base);
    if (r != 0) return r;
    if (!parent_writable(parent, uid)) return -3;
    if (uid != 0 && is_system_file(base)) return -3;
    if (find_child(parent, base) >= 0) return -5;
    int idx = -1;
    if (create_entry(parent, base, uid, mode, 8, 0, 0, &idx) != 0) return -1;
    ts_touch((parent < 0) ? 0 : (u32)parent + 1, base, 1, 1);
    parent_mtime_touch(parent);
    return 0;
}
int fs_rmdir_path(const char *path, const char *cwd, u32 uid) {
    if (!mounted) return -1;
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, uid, 0, &idx, &par);
    if (r != 0) return r;
    if (idx == -2) return -7;
    struct dir_entry *e = &dir[idx];
    if ((e->flags & 8) == 0) return -2;
    if (!parent_writable(par, uid)) return -3;
    if (!can_write_entry(e, uid)) return -3;
    u32 want = (u32)idx + 1;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if (!valid_entry(&dir[i])) continue;
        if (dir[i].reserved[1] == want) return -6;
    }
    u32 pf = e->reserved[1];
    char nm[32];
    vfs_copy_comp(nm, e->name, strlen(e->name));
    memset(e, 0, sizeof(*e));
    if (save_dir() != 0) return -1;
    ts_remove(pf, nm);
    ts_purge_parent(want);
    parent_mtime_touch(par);
    return 0;
}
int fs_rename_path(const char *oldpath, const char *newpath, const char *cwd, u32 uid) {
    if (!mounted) return -1;
    int sidx = -2, spar = -1;
    int r = vfs_resolve(oldpath, cwd, uid, 0, &sidx, &spar);
    if (r != 0) return r;
    if (sidx == -2) return -1;
    int dparent = -1;
    char dbase[32];
    r = vfs_resolve_parent(newpath, cwd, uid, &dparent, dbase);
    if (r != 0) return r;
    if (find_child(dparent, dbase) >= 0) return -5;
    if (!parent_writable(spar, uid)) return -3;
    if (!parent_writable(dparent, uid)) return -3;
    struct dir_entry *e = &dir[sidx];
    if (!can_write_entry(e, uid)) return -3;
    char obase[32];
    vfs_copy_comp(obase, e->name, strlen(e->name));
    if (uid != 0 && (is_system_file(obase) || is_system_file(dbase))) return -3;
    if ((e->flags & 8) != 0) {
        /* Never move a directory into itself or below itself. */
        int p = dparent;
        while (p >= 0) {
            if (p == sidx) return -1;
            p = dir_parent_idx(p);
        }
    }
    u32 old_pf = e->reserved[1];
    u32 new_pf = (dparent < 0) ? 0 : (u32)dparent + 1;
    memset(e->name, 0, sizeof(e->name));
    u32 nl = strlen(dbase);
    memcpy(e->name, dbase, nl);
    e->reserved[1] = new_pf;
    if (save_dir() != 0) return -1;
    ts_move(old_pf, obase, new_pf, dbase);
    if (spar >= 0 && spar != dparent) parent_mtime_touch(spar);
    parent_mtime_touch(dparent);
    return 0;
}
int fs_link_path(const char *srcpath, const char *linkpath, const char *cwd, u32 uid) {
    if (!mounted) return -1;
    int sidx = -2, spar = -1;
    int r = vfs_resolve(srcpath, cwd, uid, 1, &sidx, &spar);
    if (r != 0) return r;
    if (sidx == -2) return -7;
    struct dir_entry *src = &dir[sidx];
    if ((src->flags & 8) != 0) return -7;
    if ((src->flags & 4) != 0) return -1;
    if ((src->flags & 2) != 0) return -1; /* resolve already followed links; a bare link entry cannot be the target */
    if (!can_read_entry(src, uid)) return -3;
    int dparent = -1;
    char dbase[32];
    r = vfs_resolve_parent(linkpath, cwd, uid, &dparent, dbase);
    if (r != 0) return r;
    if (!parent_writable(dparent, uid)) return -3;
    if (uid != 0 && is_system_file(dbase)) return -3;
    if (find_child(dparent, dbase) >= 0) return -5;
    int slot = -1;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if ((dir[i].flags & 1) == 0) { slot = i; break; }
    }
    if (slot < 0) return -8;
    struct dir_entry *e = &dir[slot];
    memset(e, 0, sizeof(*e));
    u32 nl = strlen(dbase);
    memcpy(e->name, dbase, nl);
    e->size = src->size; e->start_sector = src->start_sector; e->sector_count = src->sector_count;
    e->uid = src->uid; e->mode = src->mode; e->flags = 1;
    e->reserved[0] = src->reserved[0];
    e->reserved[1] = (dparent < 0) ? 0 : (u32)dparent + 1;
    if (save_dir() != 0) return -1;
    ts_touch(e->reserved[1], dbase, 1, 1);
    parent_mtime_touch(dparent);
    return 0;
}
int fs_symlink_path(const char *linkpath, const char *target, const char *cwd, u32 uid) {
    if (!mounted || !target || !target[0]) return -1;
    /* Validate the target as a path (components, lengths,
       no empty component, no trailing slash). The stored
       text is the raw target; resolution is relative to the
       link's parent directory unless it starts with '/'. */
    int tn = 0;
    if (lex_comps(target, vfs_tgt, 0, vfs_lex, &tn) != 0) return -4;
    int dparent = -1;
    char dbase[32];
    int r = vfs_resolve_parent(linkpath, cwd, uid, &dparent, dbase);
    if (r != 0) return r;
    if (!parent_writable(dparent, uid)) return -3;
    if (uid != 0 && is_system_file(dbase)) return -3;
    if (find_child(dparent, dbase) >= 0) return -5;
    int idx = -1;
    if (create_entry(dparent, dbase, uid, 0777, 2, (const u8 *)target, strlen(target), &idx) != 0) return -1;
    ts_touch((dparent < 0) ? 0 : (u32)dparent + 1, dbase, 1, 1);
    parent_mtime_touch(dparent);
    return 0;
}
int fs_readlink_path(const char *linkpath, const char *cwd, char *out, u32 uid) {
    if (!mounted || !out) return -1;
    int idx = -2, par = -1;
    int r = vfs_resolve(linkpath, cwd, uid, 0, &idx, &par);
    if (r != 0) return r;
    if (idx == -2) return -1;
    struct dir_entry *e = &dir[idx];
    if ((e->flags & 2) == 0) return -1;
    if (uid != 0 && e->uid != uid && !can_read_entry(e, uid)) return -3;
    return link_target(idx, out, 256);
}
int fs_chmod_path(const char *path, const char *cwd, u32 mode, u32 uid) {
    if (!mounted || mode > 0777) return -1;
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, uid, 1, &idx, &par);
    if (r != 0) return r;
    if (idx == -2) return -1;
    struct dir_entry *e = &dir[idx];
    if (uid != 0 && e->uid != uid) return -3;
    e->mode = mode;
    if (save_dir() != 0) return -1;
    return 0;
}
int fs_chown_path(const char *path, const char *cwd, u32 new_uid, u32 caller_uid) {
    if (!mounted || caller_uid != 0) return -3;
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, caller_uid, 1, &idx, &par);
    if (r != 0) return r;
    if (idx == -2) return -1;
    dir[idx].uid = new_uid;
    if (save_dir() != 0) return -1;
    return 0;
}
int fs_chgrp_path(const char *path, const char *cwd, u32 new_gid, u32 caller_uid) {
    if (!mounted || caller_uid != 0) return -3;
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, caller_uid, 1, &idx, &par);
    if (r != 0) return r;
    if (idx == -2) return -1;
    dir[idx].reserved[0] = new_gid;
    if (save_dir() != 0) return -1;
    return 0;
}
int fs_copy_path(const char *srcpath, const char *dstpath, const char *cwd, u32 uid) {
    if (!mounted) return -1;
    int sidx = -2, spar = -1;
    int r = vfs_resolve(srcpath, cwd, uid, 1, &sidx, &spar);
    if (r != 0) return r;
    if (sidx == -2) return -7;
    struct dir_entry *src = &dir[sidx];
    if ((src->flags & 8) != 0) return -7;
    if ((src->flags & 4) != 0) return -1;
    if (!can_read_entry(src, uid)) return -3;
    int dparent = -1;
    char dbase[32];
    r = vfs_resolve_parent(dstpath, cwd, uid, &dparent, dbase);
    if (r != 0) return r;
    if (!parent_writable(dparent, uid)) return -3;
    if (uid != 0 && is_system_file(dbase)) return -3;
    if (find_child(dparent, dbase) >= 0) return -5;
    u32 need = src->sector_count;
    if (need == 0) need = 1;
    int slot = -1;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if ((dir[i].flags & 1) == 0) { slot = i; break; }
    }
    if (slot < 0) return -8;
    u32 start = 0;
    if (find_contiguous(need, &start) != 0) return -8;
    u32 copied = 0;
    for (u32 i = 0; i < need; i++) {
        if (i < src->sector_count) {
            if (read_sector_checked(src->start_sector + i, sector_buf) != 0) goto copy_fail;
        } else {
            memset(sector_buf, 0, 512);
        }
        if (write_sector_checked(start + i, sector_buf) != 0) goto copy_fail;
        bit_set(start + i, 1);
        copied++;
    }
    {
        struct dir_entry *e = &dir[slot];
        u32 smode = src->mode, ssize = src->size;
        memset(e, 0, sizeof(*e));
        u32 nl = strlen(dbase);
        memcpy(e->name, dbase, nl);
        e->size = ssize; e->start_sector = start; e->sector_count = need;
        e->uid = uid; e->mode = smode; e->flags = 1;
        e->reserved[0] = groups_primary_gid(uid);
        e->reserved[1] = (dparent < 0) ? 0 : (u32)dparent + 1;
    }
    if (save_bitmap() != 0) return -1;
    if (save_dir() != 0) return -1;
    ts_touch((dparent < 0) ? 0 : (u32)dparent + 1, dbase, 1, 1);
    parent_mtime_touch(dparent);
    return 0;
copy_fail:
    for (u32 i = 0; i < copied; i++) bit_set(start + i, 0);
    return -1;
}
int fs_mkfifo_path(const char *path, const char *cwd, u32 uid) {
    if (!mounted) return -1;
    int parent = -1;
    char base[32];
    int r = vfs_resolve_parent(path, cwd, uid, &parent, base);
    if (r != 0) return r;
    if (!parent_writable(parent, uid)) return -3;
    if (uid != 0 && is_system_file(base)) return -3;
    if (find_child(parent, base) >= 0) return -5;
    int idx = -1;
    if (create_entry(parent, base, uid, 0644, 4, 0, 0, &idx) != 0) return -1;
    parent_mtime_touch(parent);
    return 0;
}
int fs_exists_path(const char *path, const char *cwd) {
    if (!mounted) return 0;
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, 0, 0, &idx, &par);
    if (r != 0) return 0;
    return (idx == -2) ? 0 : 1;
}
int fs_touch_path(const char *path, const char *cwd, u32 uid) {
    if (!mounted) return -1;
    int idx = -2, par = -1;
    int r = vfs_resolve(path, cwd, uid, 1, &idx, &par);
    if (r != 0) return r;
    if (idx == -2) return -1;
    struct dir_entry *e = &dir[idx];
    if ((e->flags & 4) != 0) return -1;
    if (!can_write_entry(e, uid)) return -3;
    ts_touch(e->reserved[1], e->name, 1, 1);
    return 0;
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
/* ---- Block layer foundations (section 15.1), appended ---- */
/* Mount table: one fixed nxtsFS mount at first. The table is
   the data structure a second mount would need; a second
   mount is refused until a second block device exists. */
void fs_mount_list(void) {
    if (!mounted) { console_write("Mounts: none (filesystem not mounted)\n"); return; }
    console_write("Mounts:\n  / on device 0 (nxtsFS, mounted)\n");
}
int fs_mount_extra(void) {
    /* Always refused: there is exactly one block device. */
    return -1;
}
/* fsck read-only scan buffers (file-scope statics, never the
   stack): the scan re-reads the superblock, bitmap, and
   directory from disk through the block queue, so it sees
   on-disk corruption even though the mounted copies are
   cached in memory. It NEVER writes: no save_* call appears
   in this function, and a corrupted disk is reported, not
   repaired. */
static u8 fsck_sb_buf[512];
static struct superblock fsck_sb;
static u8 fsck_bitmap_buf[FS_BITMAP_MAX_BYTES];
static u8 fsck_dir_buf[2048];
static u8 fsck_claimed[FS_BITMAP_MAX_BYTES];
static int fsck_bit(const u8 *bm, u32 sector) {
    return (bm[sector / 8] >> (sector % 8)) & 1;
}
static void fsck_claim(u32 sector) {
    fsck_claimed[sector / 8] |= (u8)(1u << (sector % 8));
}
void fs_fsck(void) {
    if (!mounted) { console_write("fsck: no filesystem mounted\n"); return; }
    if (ata_read_sector(0, fsck_sb_buf) != 0) {
        console_write("fsck: cannot read superblock\n"); return;
    }
    fsck_sb = *(struct superblock *)fsck_sb_buf;
    struct superblock *s = &fsck_sb;
    int bad = 0, detail = 0;
    if (memcmp(s->magic, "NXTSFS01", 8) != 0) {
        console_write("fsck: superblock magic BAD (not nxtsFS)\n");
        console_write("fsck: 1 inconsistency(s) found (no changes made; repair not implemented)\n");
        return;
    }
    if (s->version != 1) { console_write("fsck: superblock version BAD\n"); bad++; }
    if (s->total_sectors < 100 || s->total_sectors > 1000000) { console_write("fsck: total_sectors out of range\n"); bad++; }
    if (s->bitmap_sectors == 0 || s->bitmap_sectors * 512 > FS_BITMAP_MAX_BYTES) { console_write("fsck: bitmap_sectors out of range\n"); bad++; }
    if (bad == 0) {
        if (s->total_sectors > s->bitmap_sectors * 4096u) { console_write("fsck: bitmap too small for total_sectors\n"); bad++; }
        if (s->total_sectors <= (s->bitmap_sectors - 1) * 4096u) { console_write("fsck: bitmap larger than total_sectors needs\n"); bad++; }
        if (s->dir_sector != 1 + s->bitmap_sectors) { console_write("fsck: dir_sector mismatch\n"); bad++; }
        if (s->dir_sectors != FS_DIR_SECTORS) { console_write("fsck: dir_sectors mismatch\n"); bad++; }
        if (s->data_start != s->dir_sector + s->dir_sectors) { console_write("fsck: data_start mismatch\n"); bad++; }
        if (s->max_files != FS_MAX_FILES) { console_write("fsck: max_files mismatch\n"); bad++; }
        if (s->data_start >= s->total_sectors) { console_write("fsck: data_start beyond disk\n"); bad++; }
    }
    if (bad != 0) {
        console_printf("fsck: %d inconsistency(s) found (no changes made; repair not implemented)\n", bad);
        return;
    }
    console_write("fsck: superblock OK\n");
    memset(fsck_bitmap_buf, 0, sizeof(fsck_bitmap_buf));
    for (u32 i = 0; i < s->bitmap_sectors; i++) {
        if (ata_read_sector(1 + i, fsck_sb_buf) != 0) {
            console_write("fsck: cannot read bitmap\n"); return;
        }
        memcpy(fsck_bitmap_buf + i * 512, fsck_sb_buf, 512);
    }
    memset(fsck_dir_buf, 0, sizeof(fsck_dir_buf));
    for (u32 i = 0; i < s->dir_sectors; i++) {
        if (ata_read_sector(s->dir_sector + i, fsck_sb_buf) != 0) {
            console_write("fsck: cannot read directory\n"); return;
        }
        memcpy(fsck_dir_buf + i * 512, fsck_sb_buf, 512);
    }
    memset(fsck_claimed, 0, sizeof(fsck_claimed));
    for (u32 sec = 0; sec < s->data_start; sec++) {
        if (!fsck_bit(fsck_bitmap_buf, sec)) {
            if (detail < 8) console_printf("fsck: metadata sector %u marked free\n", sec);
            detail++; bad++;
        }
    }
    int checked = 0;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        struct dir_entry *e = (struct dir_entry *)(fsck_dir_buf + i * 64);
        if ((e->flags & 1) == 0) continue;
        checked++;
        int ok = 1;
        if (!valid_name(e->name)) ok = 0;
        if (e->mode > 0777) ok = 0;
        if (e->sector_count == 0 && e->size != 0) ok = 0;
        if (e->size > e->sector_count * 512u) ok = 0;
        if (e->sector_count > 0) {
            if (e->start_sector < s->data_start) ok = 0;
            if (e->start_sector + e->sector_count > s->total_sectors) ok = 0;
        }
        if (!ok) {
            console_printf("fsck: directory entry %d invalid\n", i);
            bad++;
            continue;
        }
        for (u32 j = 0; j < e->sector_count; j++) {
            u32 sec = e->start_sector + j;
            fsck_claim(sec);
            if (!fsck_bit(fsck_bitmap_buf, sec)) {
                if (detail < 8) console_printf("fsck: sector %u claimed by entry %d but marked free\n", sec, i);
                detail++; bad++;
            }
        }
    }
    console_printf("fsck: %d directory entries checked\n", checked);
    for (u32 sec = s->data_start; sec < s->total_sectors; sec++) {
        if (fsck_bit(fsck_bitmap_buf, sec) && !fsck_bit(fsck_claimed, sec)) {
            if (detail < 8) console_printf("fsck: orphan sector %u (marked used, claimed by no file)\n", sec);
            detail++; bad++;
        }
    }
    if (bad == 0) console_write("fsck: clean (no changes made)\n");
    else console_printf("fsck: %d inconsistency(s) found (no changes made; repair not implemented)\n", bad);
}
