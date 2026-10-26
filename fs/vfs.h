#ifndef NXTS_VFS_H
#define NXTS_VFS_H
#include "../kernel/common.h"
/* VFS API. The first backend is nxtsFS (fs/nxtsfs.c); later backends
   plug in behind these same calls. All calls return 0 on success and
   a negative error on failure, and never panic on a bad name, size,
   or on-disk value. */
int  fs_mount(void);          /* 0 ok, -1 no disk, -2 bad filesystem */
int  fs_mounted(void);
void fs_status(void);         /* print mount status to console */
int  fs_list(void);           /* print files, return count or -1 */
int  fs_read(const char *name, u8 *buf, u32 buf_size, u32 *out_size);
int  fs_write(const char *name, const u8 *data, u32 len, u32 uid, u32 mode);
int  fs_delete(const char *name);
u32  fs_free_sectors(void);
#endif
