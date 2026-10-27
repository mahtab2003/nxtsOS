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
int  fs_write(const char *name, const u8 *data, u32 len, u32 uid, u32 mode);
int  fs_write_as(const char *name, const u8 *data, u32 len, u32 uid, u32 mode);
int  fs_delete(const char *name);
int  fs_delete_as(const char *name, u32 uid);
int  fs_exists(const char *name); /* 1 if a valid entry exists, else 0 */
int  fs_append(const char *name, const u8 *data, u32 len); /* root-only, audit log */
u32  fs_free_sectors(void);
#endif
