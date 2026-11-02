#include "fd.h"
#include "console.h"
#include "../mm/vmm.h"
#include "../mm/pmm.h"
#include "../mm/vma.h"
#include "../mm/kmalloc.h"
#include "../fs/vfs.h"
#include "../net/sock.h"

/* Pipes/FIFOs: one ring mechanism. 8 concurrent rings max
   (static table, never the stack). Anonymous pipe() rings
   and FIFO rings share the table; FIFO rings are looked up
   by name, anonymous rings only by fd. */
#define MAX_RINGS 8
#define RING_SIZE 4096u
struct pring {
    int used;
    int named; /* 1 = FIFO (name set), 0 = anonymous pipe() */
    char name[32];
    u8 *buf; /* kmalloc'd RING_SIZE */
    u32 rpos, wpos, count;
    u32 readers, writers;
    /* FIFO open waiters: a parked opener counts here, so the
       counterpart's open can complete against it (without
       this, a parked reader + a new writer deadlock: the
       writer sees readers == 0 and parks too). */
    u32 wait_readers, wait_writers;
};
static struct pring rings[MAX_RINGS];

static struct pring *ring_alloc(int named, const char *name) {
    for (int i = 0; i < MAX_RINGS; i++) {
        if (rings[i].used) continue;
        u8 *buf = (u8 *)kmalloc(RING_SIZE);
        if (!buf) return 0;
        memset(&rings[i], 0, sizeof(rings[i]));
        rings[i].used = 1;
        rings[i].named = named;
        rings[i].buf = buf;
        if (name) {
            u32 j = 0;
            while (name[j] && j < 31) { rings[i].name[j] = name[j]; j++; }
            rings[i].name[j] = 0;
        }
        return &rings[i];
    }
    return 0;
}

static struct pring *ring_find_named(const char *name) {
    for (int i = 0; i < MAX_RINGS; i++)
        if (rings[i].used && rings[i].named && strcmp(rings[i].name, name) == 0)
            return &rings[i];
    return 0;
}

static void ring_free(struct pring *r) {
    if (r->buf) kfree(r->buf);
    memset(r, 0, sizeof(*r));
}

/* Drop one reference; free the ring only when the last
   reference AND the last open waiter go (an open waiter
   holds no reference, but freeing under it would lose its
   wait count). Wake waiters (readers see EOF, writers fail). */
static void ring_unref(struct pring *r, int is_reader) {
    if (is_reader) { if (r->readers > 0) r->readers--; }
    else { if (r->writers > 0) r->writers--; }
    if (r->readers == 0 && r->writers == 0 &&
        r->wait_readers == 0 && r->wait_writers == 0) {
        fd_wake_ring(r);
        ring_free(r);
        return;
    }
    fd_wake_ring(r);
}

/* Wake every BLOCKED proc waiting to OPEN this FIFO (name
   match — open waiters hold no ring pointer, so fd_wake_ring
   cannot see them). Called on every park and every
   completion: a new waiter may pair with opposite waiters,
   and a new holder may pair with waiters. */
static void fifo_wake_waiters(const char *name) {
    struct proc *live[16];
    int n = proc_live_list(live, 16);
    for (int i = 0; i < n; i++) {
        struct proc *q = live[i];
        if (q->state == PROC_BLOCKED && q->pend.op == PEND_OPEN_FIFO &&
            strcmp(q->pend.name, name) == 0)
            q->state = PROC_READY;
    }
}

void fd_wake_ring(void *ring) {
    struct proc *live[16];
    int n = proc_live_list(live, 16);
    for (int i = 0; i < n; i++) {
        struct proc *q = live[i];
        if (q->state == PROC_BLOCKED && q->pend.op != PEND_NONE &&
            q->pend.ring == ring)
            q->state = PROC_READY;
    }
}

/* flock table: one entry per file name (static, 16 max). */
#define MAX_LOCKS 16
struct flock_entry {
    int used;
    char name[32];
    u32 ex_pid; /* 0 = no exclusive holder */
    u32 ex_count; /* fds holding EX (all one pid) */
    u32 sh_count; /* fds holding SH */
};
static struct flock_entry locks[MAX_LOCKS];

static struct flock_entry *lock_find(const char *name) {
    for (int i = 0; i < MAX_LOCKS; i++)
        if (locks[i].used && strcmp(locks[i].name, name) == 0)
            return &locks[i];
    return 0;
}

static struct flock_entry *lock_get(const char *name) {
    struct flock_entry *e = lock_find(name);
    if (e) return e;
    for (int i = 0; i < MAX_LOCKS; i++) {
        if (locks[i].used) continue;
        memset(&locks[i], 0, sizeof(locks[i]));
        locks[i].used = 1;
        u32 j = 0;
        while (name[j] && j < 31) { locks[i].name[j] = name[j]; j++; }
        locks[i].name[j] = 0;
        return &locks[i];
    }
    return 0;
}

static void lock_wake_waiters(const char *name) {
    struct proc *live[16];
    int n = proc_live_list(live, 16);
    for (int i = 0; i < n; i++) {
        struct proc *q = live[i];
        if (q->state == PROC_BLOCKED && q->pend.op == PEND_FLOCK &&
            strcmp(q->pend.name, name) == 0)
            q->state = PROC_READY;
    }
}

static void lock_release_fd(struct proc_fd *f) {
    if (f->lock == 0 || f->kind != PFD_FILE) return;
    struct flock_entry *e = lock_find(f->name);
    if (e) {
        if (f->lock == 2) {
            if (e->ex_count > 0) e->ex_count--;
            if (e->ex_count == 0) e->ex_pid = 0;
        } else if (f->lock == 1) {
            if (e->sh_count > 0) e->sh_count--;
        }
        if (e->ex_count == 0 && e->sh_count == 0 && e->ex_pid == 0)
            e->used = 0;
    }
    f->lock = 0;
    lock_wake_waiters(f->name);
}

static int fd_alloc(struct proc *p) {
    for (int i = 0; i < PROC_MAX_FD; i++)
        if (!p->fds[i].used) return i;
    return -1;
}

static struct proc_fd *fd_get(struct proc *p, int fd) {
    if (fd < 0 || fd >= PROC_MAX_FD) return 0;
    if (!p->fds[fd].used) return 0;
    return &p->fds[fd];
}

/* FIFO open pairing. Returns 0 (opened, fd_out set), -1
   (fail), -2 (would block: no counterpart yet). */
/* FIFO open pairing. Returns 0 (opened, fd_out set), -1
   (fail), -2 (would block: no counterpart yet). is_retry
   distinguishes a first attempt (which counts itself as a
   waiter when it parks) from a retry (already counted; a
   completion uncounts it). A counterpart counts as present
   when it holds the ring OR waits for it — otherwise a
   parked reader + a new writer deadlock (both see a zero
   count and both park). */
static int fifo_open(struct proc *p, const char *name, u32 flags, int *fd_out, int is_retry) {
    u32 mode = flags & 3u;
    struct pring *r = ring_find_named(name);
    if (!r) {
        r = ring_alloc(1, name);
        if (!r) return -1;
    }
    int is_rd = (mode == NXTS_O_RDONLY);
    int is_wr = (mode == NXTS_O_WRONLY);
    if (is_rd && r->writers == 0 && r->wait_writers == 0) {
        if (flags & NXTS_O_NONBLOCK) return -1; /* no writer */
        if (!is_retry) { r->wait_readers++; fifo_wake_waiters(name); }
        return -2;
    }
    if (is_wr && r->readers == 0 && r->wait_readers == 0) {
        if (flags & NXTS_O_NONBLOCK) return -1; /* no reader */
        if (!is_retry) { r->wait_writers++; fifo_wake_waiters(name); }
        return -2;
    }
    int fd = fd_alloc(p);
    if (fd < 0) return -1;
    struct proc_fd *f = &p->fds[fd];
    memset(f, 0, sizeof(*f));
    f->used = 1;
    f->kind = PFD_PIPE;
    f->flags = flags;
    f->ring = r;
    u32 j = 0;
    while (name[j] && j < 31) { f->name[j] = name[j]; j++; }
    f->name[j] = 0;
    if (is_rd) {
        f->pipe_end = 0; r->readers++;
        if (is_retry && r->wait_readers > 0) r->wait_readers--;
    } else if (is_wr) {
        f->pipe_end = 1; r->writers++;
        if (is_retry && r->wait_writers > 0) r->wait_writers--;
    } else { /* RDWR counts as both ends, never blocks */
        f->pipe_end = 0; /* read end; write via same fd is allowed */
        r->readers++; r->writers++;
        f->flags |= 0x10000u; /* internal: both-ends marker */
    }
    *fd_out = fd;
    fd_wake_ring(r); /* data waiters may proceed */
    fifo_wake_waiters(name); /* open waiters may now pair */
    return 0;
}

int fd_open(struct proc *p, const char *name, u32 flags, int *fd_out) {
    /* The audit log is append-only (fs_append); no program may
       open it, not even root — otherwise a root program could
       rewrite audit history through an fd. */
    if (strcmp(name, "audit.log") == 0) return -1;
    if (fs_is_fifo(name)) {
        if (flags & NXTS_O_CREAT) return -1; /* already a FIFO */
        if (flags & NXTS_O_TRUNC) return -1;
        /* FIFO opens honour the entry's mode bits, like files. */
        u32 fmode = flags & 3u;
        struct fs_stat fst;
        if (fs_meta_as(name, p->uid,
                       (fmode == NXTS_O_RDONLY || fmode == NXTS_O_RDWR),
                       (fmode == NXTS_O_WRONLY || fmode == NXTS_O_RDWR),
                       &fst) != 0)
            return -1;
        return fifo_open(p, name, flags, fd_out, 0);
    }
    u32 mode = flags & 3u;
    int want_r = (mode == NXTS_O_RDONLY || mode == NXTS_O_RDWR);
    int want_w = (mode == NXTS_O_WRONLY || mode == NXTS_O_RDWR);
    struct fs_stat st;
    int acc = fs_meta_as(name, p->uid, want_r, want_w, &st);
    if (acc == -2) { /* not found */
        if (!(flags & NXTS_O_CREAT)) return -1;
        if (!want_w) return -1; /* cannot create read-only */
        if (fs_write_as(name, (const u8 *)"", 0, p->uid, 0644) != 0) return -1;
        acc = fs_meta_as(name, p->uid, want_r, want_w, &st);
        if (acc != 0) return -1;
    } else if (acc != 0) {
        return -1;
    }
    if ((flags & NXTS_O_TRUNC) && want_w) {
        /* Truncate keeps owner/mode (fs_write_as would re-own
           and re-permit if handed the caller's values). */
        if (fs_write_as(name, (const u8 *)"", 0, st.uid, st.mode) != 0) return -1;
        st.size = 0;
    }
    int fd = fd_alloc(p);
    if (fd < 0) return -1;
    struct proc_fd *f = &p->fds[fd];
    memset(f, 0, sizeof(*f));
    f->used = 1;
    f->kind = PFD_FILE;
    f->flags = flags;
    u32 j = 0;
    while (name[j] && j < 31) { f->name[j] = name[j]; j++; }
    f->name[j] = 0;
    if (flags & NXTS_O_APPEND) f->offset = st.size;
    else f->offset = 0;
    *fd_out = fd;
    return 0;
}

int fd_socket(struct proc *p, int sock_idx, int *fd_out) {
    int fd = fd_alloc(p);
    if (fd < 0) return -1;
    struct proc_fd *f = &p->fds[fd];
    memset(f, 0, sizeof(*f));
    f->used = 1;
    f->kind = PFD_SOCK;
    f->flags = NXTS_O_RDWR;
    f->sock = sock_idx;
    *fd_out = fd;
    return 0;
}

int fd_sock_index(struct proc *p, int fd) {
    struct proc_fd *f = fd_get(p, fd);
    if (!f || f->kind != PFD_SOCK) return -1;
    return f->sock;
}

int fd_has_free(struct proc *p) {
    for (int i = 0; i < PROC_MAX_FD; i++)
        if (!p->fds[i].used) return 1;
    return 0;
}

int fd_read(struct proc *p, int fd, u8 *buf, u32 len, u32 *done_out) {
    struct proc_fd *f = fd_get(p, fd);
    if (!f) return -1;
    if ((f->flags & 3u) == NXTS_O_WRONLY) return -1;
    if (len > FD_MAX_IO) len = FD_MAX_IO;
    if (f->kind == PFD_SOCK) {
        /* Poll-based (§15.2): 0 bytes means no data yet,
           -1 means closed/reset — never a park, so no new
           pend kind is needed for socket reads. */
        u32 done = 0;
        int rc;
        int st = sock_type(f->sock);
        if (st == SK_STREAM) {
            rc = sock_tcp_recv_nb(f->sock, buf, len, &done);
        } else if (st == SK_DGRAM) {
            rc = sock_udp_recv_nb(f->sock, buf, len, 0, 0, &done);
        } else {
            return -1;
        }
        if (rc != 0) return -1;
        *done_out = done;
        return 0;
    }
    if (f->kind == PFD_FILE) {
        struct fs_stat st;
        if (fs_meta_as(f->name, p->uid, 1, 0, &st) != 0) return -1;
        if (f->offset >= st.size) { *done_out = 0; return 0; }
        u32 want = st.size - f->offset;
        if (want > len) want = len;
        u32 got = 0;
        if (fs_read_range_as(f->name, buf, want, f->offset, &got, p->uid) != 0)
            return -1;
        f->offset += got;
        *done_out = got;
        return 0;
    }
    /* Pipe / FIFO. */
    struct pring *r = (struct pring *)f->ring;
    if (!r || !r->used) return -1;
    if (r->count > 0) {
        u32 want = r->count;
        if (want > len) want = len;
        for (u32 i = 0; i < want; i++) {
            buf[i] = r->buf[r->rpos];
            r->rpos = (r->rpos + 1) % RING_SIZE;
        }
        r->count -= want;
        *done_out = want;
        fd_wake_ring(r); /* writers may proceed */
        return 0;
    }
    /* Empty: EOF when no writers remain at all (holders or
       waiters); would-block when a writer is still on its way
       in (its open paired with a waiter, or it is parked in
       open itself). NONBLOCK never waits. */
    if (r->writers == 0 && r->wait_writers == 0) { *done_out = 0; return 0; }
    if (f->flags & NXTS_O_NONBLOCK) return -1;
    return -2;
}

int fd_write(struct proc *p, int fd, const u8 *buf, u32 len, u32 *done_out) {
    struct proc_fd *f = fd_get(p, fd);
    if (!f) return -1;
    if ((f->flags & 3u) == NXTS_O_RDONLY) return -1;
    if (len > FD_MAX_IO) len = FD_MAX_IO;
    if (f->kind == PFD_SOCK) {
        int st = sock_type(f->sock);
        if (st == SK_STREAM) {
            /* Stream writes chunk at the segment cap; a
               failed chunk after partial success reports
               the partial count (Unix-style). */
            u32 sent = 0;
            while (sent < len) {
                u32 chunk = len - sent;
                if (chunk > SK_MAX_SEG) chunk = SK_MAX_SEG;
                if (sock_tcp_send(f->sock, buf + sent, chunk) != 0) {
                    if (sent == 0) return -1;
                    break;
                }
                sent += chunk;
            }
            *done_out = sent;
            return 0;
        } else if (st == SK_DGRAM) {
            /* Datagrams are atomic: no chunking, and only
               to a connected peer via plain write. */
            if (len > 1300) return -1;
            if (sock_udp_send_connected(f->sock, buf, len) != 0) return -1;
            *done_out = len;
            return 0;
        }
        return -1;
    }
    if (f->kind == PFD_FILE) {
        struct fs_stat st;
        if (fs_meta_as(f->name, p->uid, 0, 1, &st) != 0) return -1;
        u32 off = f->offset;
        if (f->flags & NXTS_O_APPEND) off = st.size;
        u32 newsize = off + len;
        if (newsize > FD_MAX_FILE_SIZE) return -1;
        /* Stage the whole file (zero-filled gap), preserving
           owner/mode exactly — fs_write_as would otherwise
           re-own and re-permit to the caller. */
        u8 *stage = (u8 *)kmalloc(newsize == 0 ? 1 : newsize);
        if (!stage) return -1;
        memset(stage, 0, newsize == 0 ? 1 : newsize);
        if (st.size > 0) {
            u32 got = 0;
            if (fs_read_as(f->name, stage, st.size, &got, p->uid) != 0) {
                kfree(stage); return -1;
            }
        }
        memcpy(stage + off, buf, len);
        int rc = fs_write_as(f->name, stage, newsize, st.uid, st.mode);
        kfree(stage);
        if (rc != 0) return -1;
        f->offset = off + len;
        *done_out = len;
        return 0;
    }
    /* Pipe / FIFO. */
    struct pring *r = (struct pring *)f->ring;
    if (!r || !r->used) return -1;
    /* No readers at all (holders or waiters) is EPIPE; a
       reader still on its way in means block, not fail — the
       writer's open may have paired with a waiter whose open
       has not completed yet (see the read side above). */
    if (r->readers == 0 && r->wait_readers == 0 &&
        !(f->flags & 0x10000u)) return -1; /* EPIPE: no readers */
    if (r->readers == 0 && !(f->flags & 0x10000u)) {
        if (f->flags & NXTS_O_NONBLOCK) return -1;
        return -2;
    }
    u32 free = RING_SIZE - r->count;
    if (free == 0) {
        if (f->flags & NXTS_O_NONBLOCK) return -1;
        return -2;
    }
    u32 want = free;
    if (want > len) want = len;
    for (u32 i = 0; i < want; i++) {
        r->buf[r->wpos] = buf[i];
        r->wpos = (r->wpos + 1) % RING_SIZE;
    }
    r->count += want;
    *done_out = want;
    fd_wake_ring(r); /* readers may proceed */
    return 0;
}

int fd_close(struct proc *p, int fd) {
    struct proc_fd *f = fd_get(p, fd);
    if (!f) return -1;
    lock_release_fd(f);
    if (f->kind == PFD_SOCK) {
        int s = f->sock;
        memset(f, 0, sizeof(*f));
        sock_close(s);
        return 0;
    }
    if (f->kind == PFD_PIPE) {
        struct pring *r = (struct pring *)f->ring;
        int both = (f->flags & 0x10000u) != 0;
        memset(f, 0, sizeof(*f));
        if (r && r->used) {
            if (both) { ring_unref(r, 1); if (r->used) ring_unref(r, 0); }
            else ring_unref(r, f->pipe_end == 0);
        }
        return 0;
    }
    memset(f, 0, sizeof(*f));
    return 0;
}

int fd_lseek(struct proc *p, int fd, int offset, int whence, u32 *new_out) {
    struct proc_fd *f = fd_get(p, fd);
    if (!f || f->kind != PFD_FILE) return -1;
    struct fs_stat st;
    if (fs_meta_as(f->name, p->uid, 0, 0, &st) != 0) return -1;
    int base;
    if (whence == 0) base = 0;
    else if (whence == 1) base = (int)f->offset;
    else if (whence == 2) base = (int)st.size;
    else return -1;
    int np = base + offset;
    if (np < 0) return -1;
    f->offset = (u32)np;
    *new_out = f->offset;
    return 0;
}

int fd_pipe(struct proc *p, int *fd0_out, int *fd1_out) {
    struct pring *r = ring_alloc(0, 0);
    if (!r) return -1;
    int fd0 = fd_alloc(p);
    if (fd0 < 0) { ring_free(r); return -1; }
    /* Allocate the second fd before filling either entry, so a
       half-built pair can never leak on table exhaustion. */
    int fd1 = -1;
    for (int i = 0; i < PROC_MAX_FD; i++) {
        if (i != fd0 && !p->fds[i].used) { fd1 = i; break; }
    }
    if (fd1 < 0) { ring_free(r); return -1; }
    memset(&p->fds[fd0], 0, sizeof(struct proc_fd));
    memset(&p->fds[fd1], 0, sizeof(struct proc_fd));
    p->fds[fd0].used = 1; p->fds[fd0].kind = PFD_PIPE;
    p->fds[fd0].pipe_end = 0; p->fds[fd0].ring = r;
    p->fds[fd0].flags = NXTS_O_RDONLY;
    p->fds[fd1].used = 1; p->fds[fd1].kind = PFD_PIPE;
    p->fds[fd1].pipe_end = 1; p->fds[fd1].ring = r;
    p->fds[fd1].flags = NXTS_O_WRONLY;
    r->readers = 1; r->writers = 1;
    *fd0_out = fd0; *fd1_out = fd1;
    return 0;
}

int fd_brk(struct proc *p, u32 new_end, u32 *out) {
    if (p->heap_base == 0) {
        u32 base = (USER_BASE + p->code_pages * 4096u + 4095u) & ~4095u;
        p->heap_base = base;
        p->heap_end = base;
    }
    if (new_end == 0) { *out = p->heap_end; return 0; }
    if (new_end < p->heap_base) return -1;
    if (new_end > p->heap_base + FD_MAX_HEAP) return -1;
    u32 from = (p->heap_end + 4095u) & ~4095u;
    u32 to = (new_end + 4095u) & ~4095u;
    /* Redesign 5: the heap must never grow into a VMA (a VMA
       page mapped over heap bytes would corrupt both). */
    if (to > from && vma_overlaps(p, from, to)) return -1;
    for (u32 page = from; page < to; page += 4096) {
        u32 frame = pmm_alloc_frame();
        if (frame == 0) return -1; /* OOM: break unchanged */
        memset((u8 *)frame, 0, 4096);
        vmm_map_page(p->pd, page, frame, PAGE_RW | PAGE_USER);
    }
    p->heap_end = new_end;
    *out = p->heap_end;
    return 0;
}

int fd_flock(struct proc *p, int fd, u32 op) {
    struct proc_fd *f = fd_get(p, fd);
    if (!f || f->kind != PFD_FILE) return -1;
    u32 nb = op & NXTS_LOCK_NB;
    u32 base = op & ~NXTS_LOCK_NB;
    if (base == NXTS_LOCK_UN) {
        lock_release_fd(f);
        return 0;
    }
    if (base != NXTS_LOCK_SH && base != NXTS_LOCK_EX) return -1;
    /* Idempotent re-lock / already-stronger cases. */
    if (f->lock == 2) return 0; /* already exclusive */
    if (f->lock == 1 && base == NXTS_LOCK_SH) return 0;
    if (f->lock == 1 && base == NXTS_LOCK_EX) return -1; /* no upgrade */
    struct flock_entry *e = lock_get(f->name);
    if (!e) return -1;
    if (base == NXTS_LOCK_EX) {
        if (e->ex_count > 0 || e->sh_count > 0) {
            if (nb) return -1;
            return -2;
        }
        e->ex_pid = p->pid;
        e->ex_count = 1;
        f->lock = 2;
        return 0;
    }
    /* SH */
    if (e->ex_count > 0 && e->ex_pid != p->pid) {
        if (nb) return -1;
        return -2;
    }
    e->sh_count++;
    f->lock = 1;
    return 0;
}

void fd_close_all(struct proc *p) {
    for (int i = 0; i < PROC_MAX_FD; i++) {
        if (p->fds[i].used) fd_close(p, i);
    }
    /* A parked FIFO opener holds no fd but counts as a waiter:
       uncount it, or its phantom count would pair a later
       opener with nobody (whose write then fails with EPIPE).
       Free the ring if it is fully idle now. */
    if (p->pend.op == PEND_OPEN_FIFO) {
        struct pring *r = ring_find_named(p->pend.name);
        if (r) {
            u32 mode = p->pend.flags & 3u;
            if (mode == NXTS_O_RDONLY && r->wait_readers > 0) r->wait_readers--;
            if (mode == NXTS_O_WRONLY && r->wait_writers > 0) r->wait_writers--;
            /* A waiter dying may strand a parked data waiter
               (its retry would now see EOF/EPIPE), so wake the
               ring before possibly freeing it. */
            fd_wake_ring(r);
            fifo_wake_waiters(p->pend.name);
            if (r->readers == 0 && r->writers == 0 &&
                r->wait_readers == 0 && r->wait_writers == 0)
                ring_free(r);
        }
    }
    p->pend.op = PEND_NONE;
    p->pend.ring = 0;
}

int fd_retry_pending(struct proc *p) {
    if (p->pend.op == PEND_NONE) return 1;
    if (p->pd == 0) { p->pend.op = PEND_NONE; return 1; }
    /* User buffers are only addressable under the proc's PD. */
    vmm_enable_paging(p->pd);
    int done = 1;
    u32 res = 0;
    if (p->pend.op == PEND_READ) {
        u32 got = 0;
        int rc = fd_read(p, p->pend.fd, (u8 *)p->pend.buf, p->pend.len, &got);
        if (rc == -2) done = 0;
        else { res = (rc == 0) ? got : (u32)-1; }
    } else if (p->pend.op == PEND_WRITE) {
        u32 got = 0;
        int rc = fd_write(p, p->pend.fd, (const u8 *)p->pend.buf, p->pend.len, &got);
        if (rc == -2) done = 0;
        else { res = (rc == 0) ? got : (u32)-1; }
    } else if (p->pend.op == PEND_OPEN_FIFO) {
        int fd = -1;
        int rc = fifo_open(p, p->pend.name, p->pend.flags, &fd, 1);
        if (rc == -2) done = 0;
        else { res = (rc == 0) ? (u32)fd : (u32)-1; }
    } else if (p->pend.op == PEND_FLOCK) {
        int rc = fd_flock(p, p->pend.fd, p->pend.flags);
        if (rc == -2) done = 0;
        else { res = (rc == 0) ? 0 : (u32)-1; }
    } else {
        done = 1; res = (u32)-1;
    }
    vmm_enable_paging(vmm_kernel_pd());
    if (!done) return 0;
    p->eax = res;
    p->pend.op = PEND_NONE;
    p->pend.ring = 0;
    p->state = PROC_READY;
    return 1;
}
