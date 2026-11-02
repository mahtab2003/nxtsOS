#include "syscall.h"
#include "proc.h"
#include "fd.h"
#include "../mm/vma.h"
#include "../net/sock.h"
#include "console.h"
#include "../mm/vmm.h"
#include "../drivers/pit.h"
#include "../fs/vfs.h"
#include "wm.h"

/* User-pointer validation: a pointer must lie in the process's mapped
   code pages or its single stack page, and the whole [ptr, ptr+len)
   range must stay inside that same region. Anything else returns
   failure instead of faulting the kernel. This is the only way user
   memory is read or written from kernel mode. */
static int valid_user_range(struct proc *p, u32 ptr, u32 len) {
    if (len == 0) return 0;
    u32 code_end = USER_BASE + p->code_pages * 4096;
    int in_code = (ptr >= USER_BASE && ptr < code_end && ptr + len <= code_end);
    int in_stack = (ptr >= USER_STACK_PAGE && ptr < USER_STACK_TOP &&
                    ptr + len <= USER_STACK_TOP);
    /* Deep-core phase D2: the brk heap region. */
    int in_heap = (p->heap_base != 0 && p->heap_end > p->heap_base &&
                   ptr >= p->heap_base && ptr < p->heap_end &&
                   ptr + len <= p->heap_end);
    /* Redesign 5: a demand-paged VMA range is addressable by
       syscalls exactly like code/heap/stack, so a program can
       pass a VMA buffer to read/write/print. */
    int in_vma = vma_contains_range(p, ptr, len);
    /* Overflow guard: ptr+len wrapped. */
    if (ptr + len < ptr) return 0;
    return in_code || in_stack || in_heap || in_vma;
}
static int valid_user_str(struct proc *p, u32 ptr, char *out, u32 out_size) {
    /* Copy a user string into a kernel buffer, NUL-terminated within
       out_size-1 chars, after range validation. */
    if (!valid_user_range(p, ptr, 1)) return 0;
    const char *s = (const char *)ptr;
    for (u32 i = 0; i < out_size - 1; i++) {
        if (!valid_user_range(p, ptr + i, 1)) return 0;
        char c = s[i];
        if (c == 0) { out[i] = 0; return 1; }
        if (c < 32 || c > 126 || c == '/') return 0;
        out[i] = c;
    }
    return 0; /* no terminator in time */
}

/* GUI text/title validation: printable ASCII only, NUL within
   out_size-1, range-checked per byte. Unlike valid_user_str,
   '/' is allowed here (a Calculator display can contain '/'),
   because GUI text is never used as a file path. */
static int valid_user_text(struct proc *p, u32 ptr, char *out, u32 out_size) {
    if (!valid_user_range(p, ptr, 1)) return 0;
    const char *s = (const char *)ptr;
    for (u32 i = 0; i < out_size - 1; i++) {
        if (!valid_user_range(p, ptr + i, 1)) return 0;
        char c = s[i];
        if (c == 0) { out[i] = 0; return 1; }
        if (c < 32 || c > 126) return 0;
        out[i] = c;
    }
    return 0;
}

void syscall_handler(struct regs *r) {
    u32 num = r->eax;
    /* SMP (redesign 4): a syscall from an AP job must resolve to
       the AP's current proc, not the BSP's — and its yield/exit/
       block switch must return to the AP scheduler, not the BSP's. */
    struct proc *p = proc_current_for_cpu();
    if (p == 0) { r->eax = (u32)-1; return; }
    if (num == SYS_PRINT) {
        const char *s = 0;
        /* Reuse the string validation: print string must be in user
           memory and terminate within 256 bytes. */
        if (!valid_user_range(p, r->ebx, 1)) { r->eax = (u32)-1; return; }
        s = (const char *)r->ebx;
        u32 len = 0;
        int ok = 0;
        for (u32 i = 0; i < 256; i++) {
            if (!valid_user_range(p, r->ebx + i, 1)) break;
            if (s[i] == 0) { len = i; ok = 1; break; }
        }
        if (!ok) { r->eax = (u32)-1; return; }
        for (u32 i = 0; i < len; i++) console_putchar(s[i]);
        r->eax = 0;
    } else if (num == SYS_YIELD) {
        proc_save_from_regs(p, r);
        p->state = PROC_READY;
        sched_switch_current(); /* noreturn */
    } else if (num == SYS_EXIT) {
        /* Deep-core phase: the exit code travels in ebx (the
           user _start preserves main's return there). Masked to
           0-255, like a Unix exit status. */
        p->exit_code = r->ebx & 0xFFu;
        p->state = PROC_EXITED;
        sched_switch_current(); /* noreturn */
    } else if (num == SYS_GETPID) {
        r->eax = p->pid;
    } else if (num == SYS_GETUID) {
        r->eax = p->uid;
    } else if (num == SYS_TICKS) {
        r->eax = timer_ticks;
    } else if (num == SYS_READ_FILE) {
        char name[32];
        if (!valid_user_str(p, r->ebx, name, sizeof(name))) { r->eax = (u32)-1; return; }
        if (r->edx == 0 || r->edx > 4096 || !valid_user_range(p, r->ecx, r->edx)) {
            r->eax = (u32)-1; return;
        }
        u8 *buf = (u8 *)r->ecx;
        u32 out_size = 0;
        if (fs_read_as(name, buf, r->edx, &out_size, p->uid) != 0) {
            r->eax = (u32)-1; return;
        }
        r->eax = out_size;
    } else if (num == SYS_WRITE_FILE) {
        char name[32];
        if (!valid_user_str(p, r->ebx, name, sizeof(name))) { r->eax = (u32)-1; return; }
        if (r->edx == 0 || r->edx > 1024 || !valid_user_range(p, r->ecx, r->edx)) {
            r->eax = (u32)-1; return;
        }
        if (fs_write_as(name, (const u8 *)r->ecx, r->edx, p->uid, 0644) != 0) {
            r->eax = (u32)-1; return;
        }
        r->eax = 0;
    } else if (num == SYS_GUI_OPEN) {
        char title[32];
        if (!valid_user_text(p, r->ebx, title, sizeof(title))) { r->eax = (u32)-1; return; }
        s32 x = (s32)r->ecx, y = (s32)r->edx, w = (s32)r->esi, h = (s32)r->edi;
        if (w < 0 || h < 0 || w > 4096 || h > 4096) { r->eax = (u32)-1; return; }
        r->eax = wm_gui_open(title, x, y, w, h, p->pid) == 0 ? 0 : (u32)-1;
    } else if (num == SYS_GUI_RECT) {
        s32 x = (s32)r->ebx, y = (s32)r->ecx, w = (s32)r->edx, h = (s32)r->esi;
        u32 colour = r->edi;
        if (w < 0 || h < 0 || w > 4096 || h > 4096) { r->eax = (u32)-1; return; }
        r->eax = wm_gui_rect(p->pid, x, y, w, h, colour) == 0 ? 0 : (u32)-1;
    } else if (num == SYS_GUI_TEXT) {
        char text[64];
        if (!valid_user_text(p, r->edi, text, sizeof(text))) { r->eax = (u32)-1; return; }
        s32 x = (s32)r->ebx, y = (s32)r->ecx;
        u32 fg = r->edx, bg = r->esi;
        r->eax = wm_gui_text(p->pid, x, y, text, fg, bg) == 0 ? 0 : (u32)-1;
    } else if (num == SYS_GUI_EVENT) {
        if (!valid_user_range(p, r->ebx, 20)) { r->eax = (u32)-1; return; }
        struct gui_event ev;
        if (wm_gui_event(p->pid, &ev) != 0) { r->eax = (u32)-1; return; }
        int *out = (int *)r->ebx;
        out[0] = ev.type; out[1] = ev.x; out[2] = ev.y; out[3] = ev.key; out[4] = ev.button;
        r->eax = 0;
    } else if (num == SYS_GUI_CLOSE) {
        r->eax = wm_gui_close(p->pid) == 0 ? 0 : (u32)-1;
    } else if (num == SYS_OPEN) {
        /* ebx = name, ecx = flags. */
        char name[32];
        if (!valid_user_str(p, r->ebx, name, sizeof(name))) { r->eax = (u32)-1; return; }
        int fd = -1;
        int rc = fd_open(p, name, r->ecx, &fd);
        if (rc == -2) {
            /* FIFO open with no counterpart yet: park the proc;
               the tick/exec loop retries this op on wakeup. */
            p->pend.op = PEND_OPEN_FIFO;
            p->pend.fd = -1;
            p->pend.buf = 0; p->pend.len = 0;
            p->pend.flags = r->ecx;
            p->pend.ring = 0;
            u32 j = 0;
            while (name[j] && j < 31) { p->pend.name[j] = name[j]; j++; }
            p->pend.name[j] = 0;
            proc_save_from_regs(p, r);
            p->state = PROC_BLOCKED;
            sched_switch_current(); /* noreturn */
        }
        r->eax = (rc == 0) ? (u32)fd : (u32)-1;
    } else if (num == SYS_READ) {
        /* ebx = fd, ecx = buf, edx = len (capped to FD_MAX_IO). */
        u32 len = r->edx;
        if (len > FD_MAX_IO) len = FD_MAX_IO;
        if (len == 0) { r->eax = 0; return; }
        if (!valid_user_range(p, r->ecx, len)) { r->eax = (u32)-1; return; }
        u32 done = 0;
        int rc = fd_read(p, (int)r->ebx, (u8 *)r->ecx, len, &done);
        if (rc == -2) {
            p->pend.op = PEND_READ;
            p->pend.fd = (int)r->ebx;
            p->pend.buf = r->ecx; p->pend.len = len;
            p->pend.flags = 0;
            p->pend.name[0] = 0;
            p->pend.ring = p->fds[(int)r->ebx].ring;
            proc_save_from_regs(p, r);
            p->state = PROC_BLOCKED;
            sched_switch_current(); /* noreturn */
        }
        r->eax = (rc == 0) ? done : (u32)-1;
    } else if (num == SYS_WRITE) {
        /* ebx = fd, ecx = buf, edx = len (capped to FD_MAX_IO). */
        u32 len = r->edx;
        if (len > FD_MAX_IO) len = FD_MAX_IO;
        if (len == 0) { r->eax = 0; return; }
        if (!valid_user_range(p, r->ecx, len)) { r->eax = (u32)-1; return; }
        u32 done = 0;
        int rc = fd_write(p, (int)r->ebx, (const u8 *)r->ecx, len, &done);
        if (rc == -2) {
            p->pend.op = PEND_WRITE;
            p->pend.fd = (int)r->ebx;
            p->pend.buf = r->ecx; p->pend.len = len;
            p->pend.flags = 0;
            p->pend.name[0] = 0;
            p->pend.ring = p->fds[(int)r->ebx].ring;
            proc_save_from_regs(p, r);
            p->state = PROC_BLOCKED;
            sched_switch_current(); /* noreturn */
        }
        r->eax = (rc == 0) ? done : (u32)-1;
    } else if (num == SYS_CLOSE) {
        r->eax = fd_close(p, (int)r->ebx) == 0 ? 0 : (u32)-1;
    } else if (num == SYS_LSEEK) {
        /* ebx = fd, ecx = offset (s32), edx = whence. */
        u32 np = 0;
        int rc = fd_lseek(p, (int)r->ebx, (int)r->ecx, (int)r->edx, &np);
        r->eax = (rc == 0) ? np : (u32)-1;
    } else if (num == SYS_PIPE) {
        /* ebx = int[2] out array in user memory. */
        if (!valid_user_range(p, r->ebx, 8)) { r->eax = (u32)-1; return; }
        int fd0 = -1, fd1 = -1;
        if (fd_pipe(p, &fd0, &fd1) != 0) { r->eax = (u32)-1; return; }
        int *out = (int *)r->ebx;
        out[0] = fd0; out[1] = fd1;
        r->eax = 0;
    } else if (num == SYS_VMA_ADD) {
        /* ebx = address, ecx = pages, edx = flags. */
        r->eax = (vma_add(p, r->ebx, r->ecx, r->edx) == 0) ? 0 : (u32)-1;
    } else if (num == SYS_BRK) {
        /* ebx = new break (0 = query). */
        u32 out = 0;
        int rc = fd_brk(p, r->ebx, &out);
        r->eax = (rc == 0) ? out : (u32)-1;
    } else if (num == SYS_FLOCK) {
        /* ebx = fd, ecx = op (LOCK_SH/EX/UN, optionally | LOCK_NB). */
        int rc = fd_flock(p, (int)r->ebx, r->ecx);
        if (rc == -2) {
            p->pend.op = PEND_FLOCK;
            p->pend.fd = (int)r->ebx;
            p->pend.buf = 0; p->pend.len = 0;
            p->pend.flags = r->ecx;
            p->pend.ring = 0;
            u32 j = 0;
            const char *nm = p->fds[(int)r->ebx].name;
            while (nm[j] && j < 31) { p->pend.name[j] = nm[j]; j++; }
            p->pend.name[j] = 0;
            proc_save_from_regs(p, r);
            p->state = PROC_BLOCKED;
            sched_switch_current(); /* noreturn */
        }
        r->eax = (rc == 0) ? 0 : (u32)-1;
    } else if (num == SYS_SOCKET) {
        /* ebx = family (2 = AF_INET only), ecx = type (1 stream, 2 dgram). */
        int st = -1;
        if (r->ebx == SK_AF_INET && r->ecx == 1) st = SK_STREAM;
        else if (r->ebx == SK_AF_INET && r->ecx == 2) st = SK_DGRAM;
        if (st < 0) { r->eax = (u32)-1; return; }
        int sidx = -1, fd = -1;
        if (sock_alloc(st, &sidx) != 0) { r->eax = (u32)-1; return; }
        if (fd_socket(p, sidx, &fd) != 0) { sock_free(sidx); r->eax = (u32)-1; return; }
        r->eax = (u32)fd;
    } else if (num == SYS_BIND) {
        /* ebx = fd, ecx = ip (u32, network byte order), edx = port. */
        int sidx = fd_sock_index(p, (int)r->ebx);
        if (sidx < 0) { r->eax = (u32)-1; return; }
        int rc = sock_bind(sidx, ip_from_u32(r->ecx), (u16)r->edx, p->uid);
        r->eax = (rc == 0) ? 0 : (u32)-1;
    } else if (num == SYS_LISTEN) {
        /* ebx = fd, ecx = backlog. */
        int sidx = fd_sock_index(p, (int)r->ebx);
        if (sidx < 0) { r->eax = (u32)-1; return; }
        int rc = sock_listen(sidx, (int)r->ecx, p->uid);
        r->eax = (rc == 0) ? 0 : (u32)-1;
    } else if (num == SYS_ACCEPT) {
        /* ebx = fd -> new fd, or -1 when nothing is pending
           (poll semantics: the caller retries). */
        int sidx = fd_sock_index(p, (int)r->ebx);
        if (sidx < 0) { r->eax = (u32)-1; return; }
        /* Check fd space BEFORE popping: a failed wrap after
           accept would strand the child (neither queued nor
           owned by any fd). */
        if (!fd_has_free(p)) { r->eax = (u32)-1; return; }
        int child = -1, fd = -1;
        if (sock_accept(sidx, &child) != 0) { r->eax = (u32)-1; return; }
        if (fd_socket(p, child, &fd) != 0) { r->eax = (u32)-1; return; }
        r->eax = (u32)fd;
    } else if (num == SYS_CONNECT) {
        /* ebx = fd, ecx = ip (u32), edx = port. */
        int sidx = fd_sock_index(p, (int)r->ebx);
        if (sidx < 0) { r->eax = (u32)-1; return; }
        int rc = sock_connect(sidx, ip_from_u32(r->ecx), (u16)r->edx);
        r->eax = (rc == 0) ? 0 : (u32)-1;
    } else if (num == SYS_SENDTO) {
        /* ebx = fd, ecx = buf, edx = len, esi = ip (u32), edi = port. */
        u32 len = r->edx;
        if (len == 0) { r->eax = 0; return; }
        if (!valid_user_range(p, r->ecx, len)) { r->eax = (u32)-1; return; }
        int sidx = fd_sock_index(p, (int)r->ebx);
        if (sidx < 0) { r->eax = (u32)-1; return; }
        int rc = sock_udp_send(sidx, ip_from_u32(r->esi), (u16)r->edi,
                               (const u8 *)r->ecx, len);
        r->eax = (rc == 0) ? len : (u32)-1;
    } else if (num == SYS_RECVFROM) {
        /* ebx = fd, ecx = buf, edx = len, esi = out addr (6 bytes:
           ip in network order, then port big-endian). Waits up
           to 500 ticks for a datagram; 0 = timeout. */
        u32 len = r->edx;
        if (len == 0) { r->eax = 0; return; }
        if (!valid_user_range(p, r->ecx, len)) { r->eax = (u32)-1; return; }
        if (!valid_user_range(p, r->esi, 6)) { r->eax = (u32)-1; return; }
        int sidx = fd_sock_index(p, (int)r->ebx);
        if (sidx < 0) { r->eax = (u32)-1; return; }
        ip_t src; u16 sport = 0;
        int n = sock_udp_recv(sidx, (u8 *)r->ecx, len, &src, &sport, 500);
        if (n < 0) { r->eax = (u32)-1; return; }
        if (n > 0) {
            u8 *out = (u8 *)r->esi;
            out[0] = src.b[0]; out[1] = src.b[1]; out[2] = src.b[2]; out[3] = src.b[3];
            out[4] = (u8)(sport >> 8); out[5] = (u8)sport;
        }
        r->eax = (u32)n;
    } else {
        r->eax = (u32)-1;
    }
}
