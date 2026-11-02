#ifndef NXTS_VFS_H
#define NXTS_VFS_H
#include "../kernel/common.h"
/* VFS API. The first backend is nxtsFS (fs/nxtsfs.c); later backends
   plug in behind these same calls. All calls return 0 on success and
   a negative error on failure, and never panic on a bad name, size,
   or on-disk value.
   The _as variants enforce permissions for the given UID (0 = root,
   bypasses all checks). The plain variants are root-only kernel
   shortcuts, kept for internal use. */
int  fs_mount(void);          /* 0 ok, -1 no disk, -2 bad filesystem */
int  fs_mounted(void);
void fs_status(void);         /* print mount status to console */
int  fs_list(void);
int  fs_enum_as(u32 uid, char names[][32], u32 sizes[], int max); /* fill names/sizes for readable files, return count */
int  fs_list_as(u32 uid);
int  fs_read(const char *name, u8 *buf, u32 buf_size, u32 *out_size);
int  fs_read_as(const char *name, u8 *buf, u32 buf_size, u32 *out_size, u32 uid);
int  fs_read_range_as(const char *name, u8 *buf, u32 buf_size, u32 offset, u32 *out_size, u32 uid); /* windowed read: same lookup + permission check as fs_read_as, but up to buf_size bytes starting at offset; 0 bytes at end of file */
int  fs_write(const char *name, const u8 *data, u32 len, u32 uid, u32 mode);
int  fs_write_as(const char *name, const u8 *data, u32 len, u32 uid, u32 mode);
int  fs_delete(const char *name);
int  fs_delete_as(const char *name, u32 uid);
int  fs_rename_as(const char *oldname, const char *newname, u32 uid); /* metadata-only rename: same entry, same uid/mode/data */
int  fs_chmod_as(const char *name, u32 mode, u32 uid); /* metadata-only mode change: root or owner only, mode <= 0777 */
int  fs_copy_as(const char *srcname, const char *dstname, u32 uid); /* byte-exact copy: new entry owned by the caller, source mode kept */
int  fs_exists(const char *name); /* 1 if a valid entry exists, else 0 */
/* Metadata for one file. fs_stat_as fills size (bytes), uid
   (owner), mode (decimal, as ls prints it), and sector_count.
   is_dir is 1 for a directory entry (flags bit 3, §15);
   mtime/atime are sidecar tick counts (100 Hz ticks since
   boot, 0 = unknown/no sidecar entry — see §15), never
   wall-clock times. */
struct fs_stat { u32 size, uid, mode, sectors, gid, is_dir, mtime, atime; };
int  fs_stat_as(const char *name, struct fs_stat *out, u32 uid); /* metadata read: root, owner, or any reader of the file; -1 on missing/unreadable */
int  fs_chown_as(const char *name, u32 new_uid, u32 caller_uid); /* metadata-only owner change: caller MUST be root (enforced here, not only in the shell); mirrors fs_chmod_as */
int  fs_symlink_as(const char *link, const char *target, u32 uid); /* create a symbolic link (flags bit 1, no layout change); refuses an existing link name */
int  fs_readlink_as(const char *link, char *out, u32 uid); /* print a link's target into out (32 bytes); -1 if not a link, missing, or unreadable */
int  fs_chgrp_as(const char *name, u32 new_gid, u32 caller_uid); /* metadata-only group change (parity run): caller MUST be root; gid lives in dir_entry.reserved[0], no layout change */
/* Deep-core phase D2: FIFO entries (flags bit 2) + the fd
   layer's metadata probe (see fs/nxtsfs.c for semantics). */
int  fs_is_fifo(const char *name); /* 1 if the entry exists and is a FIFO */
int  fs_meta_as(const char *name, u32 uid, int want_r, int want_w, struct fs_stat *out); /* 0 ok, -1 denied, -2 not found */
int  fs_mkfifo_as(const char *name, u32 uid); /* create a named FIFO */
int  fs_append(const char *name, const u8 *data, u32 len); /* root-only, audit log */
/* Directories + VFS tree (§15.0). Path calls take a session cwd
   (an absolute canonical path, "/" for root); relative paths
   resolve from it, absolute paths from root. Components are
   <= 31 chars, at most 16 after lexical '.'/'..' resolution,
   total path <= 255; empty components (including a trailing
   slash or "//") are malformed, never silently skipped.
   Symlink hops: at most 4 expansions per path resolution
   (the existing flat 4-hop rule, applied to the whole path;
   a chain longer than 4 across components is refused rather
   than followed — stricter than a fresh budget per component,
   same loop refusal). Error codes, shared by every _path call:
   0 ok, -1 not found (or generic failure), -2 a path
   component is not a directory, -3 permission denied,
   -4 malformed path, -5 already exists, -6 directory not
   empty, -7 is a directory (where a file was expected),
   -8 no space or directory full. Directory entries use
   flags bit 3 and parent in reserved[1] (0 = root child,
   else entry_index + 1); the root directory itself is not
   an entry and is always readable/writable (the legacy flat
   namespace: file rules alone govern root children).
   The flat fs_* calls are root-child operations only: they
   see entries whose reserved[1] == 0 and never touch a
   subdirectory entry, so existing callers keep working. */
int  fs_canonical_path(const char *path, const char *cwd, char *out, u32 out_size); /* lexical only, no fs access; 0 ok, -1 malformed */
int  fs_dir_status_path(const char *path, const char *cwd, u32 uid); /* 0 = directory readable by uid, 1 not found, 2 not a directory, 3 permission denied, 4 malformed */
int  fs_read_path(const char *path, const char *cwd, u8 *buf, u32 buf_size, u32 *out_size, u32 uid);
int  fs_read_range_path(const char *path, const char *cwd, u8 *buf, u32 buf_size, u32 offset, u32 *out_size, u32 uid);
int  fs_write_path(const char *path, const char *cwd, const u8 *data, u32 len, u32 uid, u32 mode);
int  fs_delete_path(const char *path, const char *cwd, u32 uid);
int  fs_stat_path(const char *path, const char *cwd, struct fs_stat *out, u32 uid);
int  fs_list_path(const char *path, const char *cwd, u32 uid); /* list view of a directory's children (or the root); returns the child count, negative on failure */
int  fs_mkdir_path(const char *path, const char *cwd, u32 uid, u32 mode);
int  fs_rmdir_path(const char *path, const char *cwd, u32 uid);
int  fs_rename_path(const char *oldpath, const char *newpath, const char *cwd, u32 uid); /* parent-only change for cross-directory moves; data untouched */
int  fs_link_path(const char *srcpath, const char *linkpath, const char *cwd, u32 uid); /* hard link: second entry sharing the source's data sectors */
int  fs_symlink_path(const char *linkpath, const char *target, const char *cwd, u32 uid); /* target may be a path (absolute, or relative to the link's parent directory) */
int  fs_readlink_path(const char *linkpath, const char *cwd, char *out, u32 uid); /* out must hold 256 bytes */
int  fs_chmod_path(const char *path, const char *cwd, u32 mode, u32 uid);
int  fs_chown_path(const char *path, const char *cwd, u32 new_uid, u32 caller_uid);
int  fs_chgrp_path(const char *path, const char *cwd, u32 new_gid, u32 caller_uid);
int  fs_copy_path(const char *srcpath, const char *dstpath, const char *cwd, u32 uid);
int  fs_mkfifo_path(const char *path, const char *cwd, u32 uid);
int  fs_touch_path(const char *path, const char *cwd, u32 uid); /* existing file/dir: mtime+atime = now (caller must be able to write it); missing file: -1, the shell creates it */
int  fs_exists_path(const char *path, const char *cwd); /* 1 if the path resolves to an entry (permission-blind, like flat fs_exists), else 0; the root itself counts as 0 */
/* Block layer foundations (section 15.1): mount table (one
   nxtsFS mount; a second mount is refused until a second
   block device exists), read-only fsck scan (never writes,
   never repairs), and the swap definition (inactive). */
void fs_mount_list(void);
int  fs_mount_extra(void); /* always -1: no second device */
void fs_fsck(void);
u32  fs_free_sectors(void);
u32  fs_total_sectors(void); /* 0 when not mounted, like fs_free_sectors */
#endif
