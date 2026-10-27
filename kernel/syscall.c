#include "syscall.h"
#include "proc.h"
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
    /* Overflow guard: ptr+len wrapped. */
    if (ptr + len < ptr) return 0;
    return in_code || in_stack;
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
    if (current_proc == 0) { r->eax = (u32)-1; return; }
    struct proc *p = current_proc;
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
        sched_switch_asm(); /* noreturn */
    } else if (num == SYS_EXIT) {
        p->state = PROC_EXITED;
        sched_switch_asm(); /* noreturn */
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
    } else {
        r->eax = (u32)-1;
    }
}
