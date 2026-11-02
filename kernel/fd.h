/* Deep-core phase D2: per-process file descriptors, kernel
   pipes / named FIFOs, brk, flock. See docs/CORE_CLI.md
   §14.12 for semantics and documented bounds.
   Return convention for fd_read/fd_write/fd_open_fifo:
   0 ok, -1 fail, -2 would-block (caller stores the pending
   op and parks the proc as PROC_BLOCKED). */
#ifndef NXTS_FD_H
#define NXTS_FD_H
#include "proc.h"

/* Open flags (low 2 bits = access mode, as in the design). */
#define NXTS_O_RDONLY 0u
#define NXTS_O_WRONLY 1u
#define NXTS_O_RDWR   2u
#define NXTS_O_CREAT  0x40u
#define NXTS_O_TRUNC  0x200u
#define NXTS_O_APPEND 0x400u
#define NXTS_O_NONBLOCK 0x800u

/* flock ops (Linux numbers). */
#define NXTS_LOCK_SH 1u
#define NXTS_LOCK_EX 2u
#define NXTS_LOCK_UN 8u
#define NXTS_LOCK_NB 4u

/* Limits (documented bounds, §14.12). */
#define FD_MAX_FILE_SIZE (64u * 1024u) /* fd-written files */
#define FD_MAX_IO 8192u                /* per read/write call */
#define FD_MAX_HEAP (256u * 1024u)     /* brk growth cap */

int  fd_open(struct proc *p, const char *name, u32 flags, int *fd_out);
int  fd_read(struct proc *p, int fd, u8 *buf, u32 len, u32 *done_out);
int  fd_write(struct proc *p, int fd, const u8 *buf, u32 len, u32 *done_out);
int  fd_close(struct proc *p, int fd);
/* §15.2: wrap a socket-table index as a proc fd (kind
   PFD_SOCK, RDWR so read/write checks pass), or translate
   an fd back to its socket index (-1 if not a socket fd). */
int  fd_socket(struct proc *p, int sock_idx, int *fd_out);
int  fd_sock_index(struct proc *p, int fd);
int  fd_has_free(struct proc *p); /* 1 if any fd slot is free */
int  fd_lseek(struct proc *p, int fd, int offset, int whence, u32 *new_out);
int  fd_pipe(struct proc *p, int *fd0_out, int *fd1_out);
int  fd_brk(struct proc *p, u32 new_end, u32 *out);
int  fd_flock(struct proc *p, int fd, u32 op);
void fd_close_all(struct proc *p);
/* Retry a blocked op (tick / exec loop, before resuming user
   code). 1 = completed or no pending op, 0 = still blocked.
   Switches CR3 to the proc's PD for user-buffer access and
   restores the kernel PD before returning. */
int  fd_retry_pending(struct proc *p);
/* Wake every BLOCKED proc waiting on this ring (retry decides
   whether it really proceeds; losers re-block). */
void fd_wake_ring(void *ring);

#endif
