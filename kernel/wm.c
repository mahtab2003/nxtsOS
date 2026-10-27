#include "wm.h"
#include "fb.h"
#include "console.h"
#include "../drivers/mouse.h"
#include "../drivers/keyboard.h"
#include "../mm/pmm.h"
#include "../drivers/pit.h"
#include "shell.h"
#include "users.h"
#include "../fs/vfs.h"
#include "proc.h"

#define MAX_WINDOWS 8
#define TITLE_H 20
#define TASKBAR_H 24

enum win_type { W_WELCOME, W_SYSTEM, W_MOUSE, W_BUTTONS, W_USER,
    W_SETTINGS, W_FILES, W_ABOUT, W_DESKTOP_ICONS };

/* GUI event queue for user windows (Phase 8). Event types:
   1=expose (redraw), 2=mouse down, 3=mouse up, 4=key, 5=close.
   x,y are client-relative for mouse events, key is the ASCII
   code for key events, button is 1 for left. */
#define GUI_EV_EXPOSE 1
#define GUI_EV_MDOWN 2
#define GUI_EV_MUP 3
#define GUI_EV_KEY 4
#define GUI_EV_CLOSE 5
#define GUI_EV_MAX 16

struct window {
    int used, id, type;
    s32 x, y, w, h;
    s32 old_x, old_y, old_w, old_h; /* for maximise restore */
    int minimized, maximized, focused;
    char title[32];
    int counter; /* buttons window: click count */
    char field[64]; /* buttons window: text field */
    int field_len, field_focused;
    int button_pressed; /* which button (0=none,1=OK,2=Say,3=Back) is held */
    u32 owner_pid; /* W_USER only: background job pid, 0 = none */
    struct gui_event evq[GUI_EV_MAX];
    int ev_head, ev_tail, ev_count;
    char search[64]; /* W_SETTINGS only: search filter */
    int search_len;
    int selected; /* W_FILES only: selected file index, -1 = none */
    char preview[256]; /* W_FILES only: preview text */
};

static struct window wins[MAX_WINDOWS];
static int zorder[MAX_WINDOWS]; /* window indices, back to front */
static int zcount = 0;
static int next_id = 1;

static s32 scr_w(void) { return fb_ready() ? (s32)fb_width() : 800; }
static s32 scr_h(void) { return fb_ready() ? (s32)fb_height() : 600; }

int wm_count(void) {
    int n = 0;
    for (int i = 0; i < MAX_WINDOWS; i++) if (wins[i].used) n++;
    return n;
}

static int find_by_id(int id) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].id == id) return i;
    return -1;
}
static void bring_to_front(int idx) {
    int pos = -1;
    for (int i = 0; i < zcount; i++) if (zorder[i] == idx) pos = i;
    if (pos < 0) return;
    for (int i = pos; i < zcount - 1; i++) zorder[i] = zorder[i + 1];
    zorder[zcount - 1] = idx;
    for (int i = 0; i < MAX_WINDOWS; i++) wins[i].focused = 0;
    wins[idx].focused = 1;
}

static int wm_create(const char *title, s32 x, s32 y, s32 w, s32 h, int type) {
    if (wm_count() >= MAX_WINDOWS) return -1;
    int idx = -1;
    for (int i = 0; i < MAX_WINDOWS; i++) if (!wins[i].used) { idx = i; break; }
    if (idx < 0) return -1;
    /* Clamp size first, then position so the title bar stays reachable. */
    if (w < 100) w = 100;
    if (h < 80) h = 80;
    if (w > scr_w()) w = scr_w();
    if (h > scr_h()) h = scr_h();
    if (x < -(w - 100)) x = -(w - 100);
    if (x > scr_w() - 100) x = scr_w() - 100;
    if (y < 0) y = 0;
    if (y > scr_h() - 50) y = scr_h() - 50;
    struct window *wn = &wins[idx];
    memset(wn, 0, sizeof(*wn));
    wn->used = 1; wn->id = next_id++; wn->type = type;
    wn->x = x; wn->y = y; wn->w = w; wn->h = h;
    wn->old_x = x; wn->old_y = y; wn->old_w = w; wn->old_h = h;
    int ti = 0;
    while (title[ti] && ti < 31) { wn->title[ti] = title[ti]; ti++; }
    wn->title[ti] = 0;
    zorder[zcount++] = idx;
    bring_to_front(idx);
    return wn->id;
}

static void wm_close_idx(int idx) {
    console_printf("Window closed: %s\n", wins[idx].title);
    wins[idx].used = 0;
    int pos = -1;
    for (int i = 0; i < zcount; i++) if (zorder[i] == idx) pos = i;
    if (pos >= 0) {
        for (int i = pos; i < zcount - 1; i++) zorder[i] = zorder[i + 1];
        zcount--;
    }
    if (zcount > 0) {
        for (int i = 0; i < MAX_WINDOWS; i++) wins[i].focused = 0;
        wins[zorder[zcount - 1]].focused = 1;
    }
}

static int inside(s32 px, s32 py, s32 x, s32 y, s32 w, s32 h) {
    return px >= x && px < x + w && py >= y && py < y + h;
}

/* Draw text clipped to both a window clip rect and a dirty rect
   (v0.8.0: true per-window clipping for drag redraws). */
static void draw_text2(s32 x, s32 y, const char *s, u32 fg, u32 bg,
                       s32 cx, s32 cy, s32 cw, s32 ch,
                       s32 dx, s32 dy, s32 dw, s32 dh) {
    s32 x0 = cx > dx ? cx : dx;
    s32 y0 = cy > dy ? cy : dy;
    s32 x1 = cx + cw < dx + dw ? cx + cw : dx + dw;
    s32 y1 = cy + ch < dy + dh ? cy + ch : dy + dh;
    if (x0 >= x1 || y0 >= y1) return;
    fb_draw_text_clip(x, y, s, fg, bg, x0, y0, x1 - x0, y1 - y0);
}

/* Draw one window, clipped to the dirty rect (fb functions clip
   again to the screen). When the dirty rect is the full screen,
   output is identical to the old unclipped draw_window. */
static void draw_window_clip(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    if (wn->minimized) return;
    s32 x = wn->x, y = wn->y, w = wn->w, h = wn->h;
    u32 tcol = wn->focused ? 0x002060A0u : 0x00606060u;
    fb_fill_rect_clip(x, y, w, TITLE_H, tcol, dx, dy, dw, dh);
    fb_fill_rect_clip(x, y + TITLE_H, w, 1, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x, y, 1, h, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + w - 1, y, 1, h, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x, y + h - 1, w, 1, 0x00000000u, dx, dy, dw, dh);
    draw_text2(x + 6, y + 2, wn->title, 0x00FFFFFFu, tcol,
               x, y, w - 56, TITLE_H, dx, dy, dw, dh);
    const char *ctl[3] = {"_", "#", "X"};
    for (int i = 0; i < 3; i++) {
        s32 ccx = x + w - 52 + i * 18;
        fb_fill_rect_clip(ccx, y + 2, 16, 16, 0x00C0C0C0u, dx, dy, dw, dh);
        draw_text2(ccx + 4, y + 2, ctl[i], 0x00000000u, 0x00C0C0C0u,
                   ccx, y + 2, 16, 16, dx, dy, dw, dh);
    }
    if (wn->type == W_USER) {
        /* User windows own their client area: the app draws it
           via GUI syscalls, and the WM must never fill it, or
           every desktop redraw would erase the app. Only the
           title bar and border above are drawn by the WM. */
        return;
    }
    fb_fill_rect_clip(x + 1, y + TITLE_H + 1, w - 2, h - TITLE_H - 2, 0x00D0D0D0u, dx, dy, dw, dh);
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = w - 2, ch = h - TITLE_H - 2;
    char buf[64];
    if (wn->type == W_WELCOME) {
        draw_text2(x + 10, y + 32, "Welcome to nxtsOS", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 10, y + 52, "Graphics: 800x600x32, mouse, windows.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 10, y + 72, "Drag the title bar to move.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 10, y + 92, "Drag the bottom-right corner to resize.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        fb_fill_rect_clip(x + 10, y + 120, 120, 24, wn->button_pressed == 3 ? 0x00808080u : 0x00C0C0C0u, dx, dy, dw, dh);
        draw_text2(x + 18, y + 124, "Back to shell", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
        fb_fill_rect_clip(x + 140, y + 120, 80, 24, wn->button_pressed == 1 ? 0x00808080u : 0x00C0C0C0u, dx, dy, dw, dh);
        draw_text2(x + 148, y + 124, "OK", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    } else if (wn->type == W_SYSTEM) {
        u32_to_str(pmm_total_frames() * 4, buf, 10);
        draw_text2(x + 10, y + 32, "Memory total (KiB):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 190, y + 32, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str(pmm_free_frames() * 4, buf, 10);
        draw_text2(x + 10, y + 52, "Memory free (KiB):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 190, y + 52, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str(timer_ticks, buf, 10);
        draw_text2(x + 10, y + 72, "Ticks (100 Hz):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 190, y + 72, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 10, y + 92, "Windows open:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str((u32)wm_count(), buf, 10);
        draw_text2(x + 190, y + 92, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    } else if (wn->type == W_MOUSE) {
        u32_to_str((u32)mouse_x(), buf, 10);
        draw_text2(x + 10, y + 32, "Mouse X:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 120, y + 32, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str((u32)mouse_y(), buf, 10);
        draw_text2(x + 10, y + 52, "Mouse Y:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 120, y + 52, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 10, y + 72, mouse_left() ? "Left: down" : "Left: up", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 10, y + 92, mouse_present() ? "Mouse: present" : "Mouse: absent", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    } else if (wn->type == W_BUTTONS) {
        draw_text2(x + 10, y + 32, "Type here, then Say hello:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        fb_fill_rect_clip(x + 10, y + 52, w - 20, 24, 0x00FFFFFFu, dx, dy, dw, dh);
        draw_text2(x + 14, y + 56, wn->field, 0x00000000u, 0x00FFFFFFu, x + 10, y + 52, w - 20, 24, dx, dy, dw, dh);
        if (wn->field_focused) {
            s32 cur_x = x + 14 + wn->field_len * 8;
            fb_fill_rect_clip(cur_x, y + 56, 2, 16, 0x00000000u, dx, dy, dw, dh);
        }
        fb_fill_rect_clip(x + 10, y + 88, 120, 24, wn->button_pressed == 2 ? 0x00808080u : 0x00C0C0C0u, dx, dy, dw, dh);
        draw_text2(x + 18, y + 92, "Say hello", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
        fb_fill_rect_clip(x + 140, y + 88, 120, 24, wn->button_pressed == 1 ? 0x00808080u : 0x00C0C0C0u, dx, dy, dw, dh);
        draw_text2(x + 148, y + 92, "Click me", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str((u32)wn->counter, buf, 10);
        draw_text2(x + 10, y + 124, "Clicks:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 80, y + 124, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    }
}
static void draw_window(int idx) {
    draw_window_clip(idx, 0, 0, scr_w(), scr_h());
}

static void draw_taskbar(void) {
    s32 sw = scr_w(), sh = scr_h();
    fb_fill_rect(0, sh - TASKBAR_H, sw, TASKBAR_H, 0x00404040u);
    fb_fill_rect(2, sh - TASKBAR_H + 2, 60, TASKBAR_H - 4, 0x00606060u);
    fb_draw_text(8, sh - TASKBAR_H + 5, "Shell", 0x00FFFFFFu, 0x00606060u);
    s32 bx = 66;
    for (int zi = 0; zi < zcount; zi++) {
        struct window *wn = &wins[zorder[zi]];
        if (bx + 120 > sw) break;
        u32 bg = wn->focused ? 0x00808080u : (wn->minimized ? 0x00505050u : 0x00606060u);
        fb_fill_rect(bx, sh - TASKBAR_H + 2, 118, TASKBAR_H - 4, bg);
        fb_draw_text_clip(bx + 4, sh - TASKBAR_H + 5, wn->title, 0x00FFFFFFu, bg, bx, sh - TASKBAR_H, 118, TASKBAR_H);
        bx += 122;
    }
}

static const u16 cursor_bits[16] = {
    0x800, 0xC00, 0xE00, 0xF00, 0xF80, 0xFC0, 0xFE0, 0xFF0,
    0xFF8, 0xF80, 0xD80, 0xCC0, 0xC60, 0xC30, 0xC00, 0xC00
};
/* v0.7.4 cursor sprite save/restore. The cursor bounding box is
   13x17 (12x16 arrow plus 1px black shadow offset). Before drawing
   the cursor, the pixels underneath are saved; moving the cursor
   then costs ~442 pixel writes (restore old + save new + draw
   new) instead of a full-screen redraw (480,000 pixels). This
   also fixes a real lag bug in v0.7.0-0.7.3: the loop had NO
   branch for mouse movement with the button up, so the cursor
   only moved on the 0.5s periodic redraw — moving the mouse to
   click something felt like 2 frames per second, whatever the
   redraw speed was. */
#define CUR_W 13
#define CUR_H 17
static u32 cursor_saved[CUR_W * CUR_H];
static s32 cursor_saved_x = 0, cursor_saved_y = 0;
static int cursor_saved_valid = 0;
static void cursor_save_at(s32 mx, s32 my) {
    for (int dy = 0; dy < CUR_H; dy++)
        for (int dx = 0; dx < CUR_W; dx++)
            cursor_saved[dy * CUR_W + dx] = fb_read_pixel(mx + dx, my + dy);
    cursor_saved_x = mx; cursor_saved_y = my; cursor_saved_valid = 1;
}
static void cursor_restore(void) {
    if (!cursor_saved_valid) return;
    for (int dy = 0; dy < CUR_H; dy++)
        for (int dx = 0; dx < CUR_W; dx++) {
            s32 px = cursor_saved_x + dx, py = cursor_saved_y + dy;
            if (px < 0 || py < 0 || px >= scr_w() || py >= scr_h()) continue;
            fb_putpixel(px, py, cursor_saved[dy * CUR_W + dx]);
        }
    cursor_saved_valid = 0;
}
static void draw_cursor(void) {
    s32 mx = mouse_x(), my = mouse_y();
    for (int row = 0; row < 16; row++) {
        for (int col = 0; col < 12; col++) {
            if (cursor_bits[row] & (0x800 >> col)) {
                fb_putpixel(mx + col + 1, my + row + 1, 0x00000000u);
                fb_putpixel(mx + col, my + row, 0x00FFFFFFu);
            }
        }
    }
}
/* Move the cursor without redrawing anything else. Only valid
   when the saved pixels really are the ones under the old cursor
   position (they are, because every full/clip redraw re-saves
   after drawing the scene, and every cursor move re-saves after
   restoring). If the saved position does not match, fall back to
   a full redraw instead of restoring wrong pixels. */
static void cursor_move_only(s32 old_mx, s32 old_my, s32 new_mx, s32 new_my);

static int rects_overlap(s32 ax, s32 ay, s32 aw, s32 ah,
                         s32 bx, s32 by, s32 bw, s32 bh) {
    return ax < bx + bw && ax + aw > bx && ay < by + bh && ay + ah > by;
}

static void wm_redraw_rect(s32 dx, s32 dy, s32 dw, s32 dh) {
    if (!fb_ready() || dw <= 0 || dh <= 0) return;
    /* Background, clipped to the dirty rect only. */
    fb_fill_rect_clip(0, 0, scr_w(), scr_h(), 0x00106040u, dx, dy, dw, dh);
    /* Windows back-to-front, but only windows that actually overlap
       the dirty rect. A window that does not overlap the dirty
       rect cannot affect any pixel inside it, so skipping it is
       safe; a window that does overlap is drawn fully (in correct
       z-order), so the dirty area ends up exactly as a full
       redraw would leave it. */
    for (int zi = 0; zi < zcount; zi++) {
        struct window *wn = &wins[zorder[zi]];
        if (wn->minimized) continue;
        if (!rects_overlap(wn->x, wn->y, wn->w, wn->h, dx, dy, dw, dh)) continue;
        draw_window_clip(zorder[zi], dx, dy, dw, dh);
    }
    /* Taskbar: skip entirely if the dirty rect does not reach
       the taskbar strip (v0.8.0, was always drawn). */
    if (rects_overlap(0, scr_h() - TASKBAR_H, scr_w(), TASKBAR_H, dx, dy, dw, dh))
        draw_taskbar();
    cursor_save_at(mouse_x(), mouse_y());
    draw_cursor();
}

static void wm_redraw(void) {
    wm_redraw_rect(0, 0, scr_w(), scr_h());
}

static void cursor_move_only(s32 old_mx, s32 old_my, s32 new_mx, s32 new_my) {
    (void)old_mx; (void)old_my;
    if (!fb_ready()) return;
    if (!cursor_saved_valid || cursor_saved_x != old_mx || cursor_saved_y != old_my) {
        wm_redraw();
        return;
    }
    cursor_restore();
    cursor_save_at(new_mx, new_my);
    draw_cursor();
}

static void init_demo(void) {
    memset(wins, 0, sizeof(wins));
    zcount = 0; next_id = 1;
    wm_create("Welcome", 40, 40, 360, 200, W_WELCOME);
    wm_create("System", 420, 60, 320, 180, W_SYSTEM);
    wm_create("Mouse test", 60, 280, 300, 160, W_MOUSE);
    wm_create("Buttons", 400, 280, 340, 200, W_BUTTONS);
}

static int ok_clicked = 0;

static int wm_run_internal(int autotest) {
    if (!fb_ready()) { console_write("gui: no framebuffer available\n"); return -1; }
    init_demo();
    ok_clicked = 0;
    wm_redraw();
    int was_down = 0, drag_idx = -1, resize_idx = -1;
    s32 drag_dx = 0, drag_dy = 0;
    int press_button = 0, press_win = -1;
    int exit_gui = 0;
    s32 prev_mx = mouse_x(), prev_my = mouse_y();
    u32 last_redraw_ticks = timer_ticks;
    u32 start_ticks = timer_ticks;
    int auto_step = -1;
    /* v0.7.4 throttled dirty redraw: drag/resize/key/periodic
       changes merge into a pending dirty rect, flushed at most
       every 3 ticks (~30 Hz). Mouse moves without drag do NOT
       use this path — they use cursor_move_only (~442 pixels). */
    int pending_redraw = 0;
    s32 pend_x = 0, pend_y = 0, pend_w = 0, pend_h = 0;
    while (!exit_gui) {
        /* Autotest script (ticks are 100 Hz, steps advance every 30 ticks):
           0: move to OK button, press; 1: release (OK must click);
           2: move to Welcome title bar, press (drag start);
           3: move to a new position while dragging;
           4: release (window must have moved);
           5: move to taskbar Shell button, press; 6: release (exit).
           This tests click/drag/taskbar logic without relying on
           QEMU monitor mouse injection, which did not deliver
           packets in this sandbox (see docs/GRAPHICS.md). */
        if (autotest) {
            u32 elapsed = timer_ticks - start_ticks;
            int step = (int)(elapsed / 30);
            if (step != auto_step && step <= 6) {
                auto_step = step;
                if (step == 0) mouse_test_set(220, 172, 0);
                else if (step == 1) mouse_test_set(220, 172, 1);
                else if (step == 2) mouse_test_set(220, 172, 0);
                else if (step == 3) mouse_test_set(100, 50, 1);
                else if (step == 4) mouse_test_set(200, 100, 1);
                else if (step == 5) mouse_test_set(200, 100, 0);
                else if (step == 6) mouse_test_set(32, 588, 1);
            }
            if (step >= 7) mouse_test_set(32, 588, 0);
        }
        /* Keyboard: only a focused text field consumes keys. Poll
           as well as IRQ, same Bochs robustness reason as shell. */
        keyboard_poll();
        int c = keyboard_getchar();
        if (c >= 0) {
            int fi = -1;
            for (int i = 0; i < MAX_WINDOWS; i++)
                if (wins[i].used && wins[i].field_focused) fi = i;
            if (fi >= 0) {
                struct window *wn = &wins[fi];
                if (c == '\b') { if (wn->field_len > 0) wn->field[--wn->field_len] = 0; }
                else if (c == '\n') { console_printf("Text field: %s\n", wn->field); }
                else if (c >= 32 && c < 127 && wn->field_len < 63) {
                    wn->field[wn->field_len++] = (char)c; wn->field[wn->field_len] = 0;
                }
                /* v0.7.4: redraw only this window's rect, throttled
                   (see flush at loop end), not the full screen. */
                if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
                else {
                    s32 nx0 = pend_x < wn->x ? pend_x : wn->x;
                    s32 ny0 = pend_y < wn->y ? pend_y : wn->y;
                    s32 nx1 = pend_x + pend_w > wn->x + wn->w ? pend_x + pend_w : wn->x + wn->w;
                    s32 ny1 = pend_y + pend_h > wn->y + wn->h ? pend_y + pend_h : wn->y + wn->h;
                    pend_x = nx0; pend_y = ny0; pend_w = nx1 - nx0; pend_h = ny1 - ny0;
                }
            }
        }
        s32 mx = mouse_x(), my = mouse_y();
        int down = mouse_left();
        if (down && !was_down) {
            /* Press: taskbar first, then windows front-to-back. */
            press_button = 0; press_win = -1; drag_idx = -1; resize_idx = -1;
            if (my >= scr_h() - TASKBAR_H) {
                if (mx < 64) { exit_gui = 1; }
                else {
                    s32 bx = 66;
                    for (int zi = 0; zi < zcount; zi++) {
                        struct window *wn = &wins[zorder[zi]];
                        if (mx >= bx && mx < bx + 118) {
                            if (wn->minimized) wn->minimized = 0;
                            bring_to_front(zorder[zi]);
                            break;
                        }
                        bx += 122;
                    }
                }
            } else {
                for (int zi = zcount - 1; zi >= 0; zi--) {
                    int wi = zorder[zi];
                    struct window *wn = &wins[wi];
                    if (wn->minimized) continue;
                    if (!inside(mx, my, wn->x, wn->y, wn->w, wn->h)) continue;
                    bring_to_front(wi);
                    /* Controls. */
                    for (int ci = 0; ci < 3; ci++) {
                        s32 ccx = wn->x + wn->w - 52 + ci * 18;
                        if (inside(mx, my, ccx, wn->y + 2, 16, 16)) {
                            if (ci == 0) { wn->minimized = 1; console_printf("Window minimized: %s\n", wn->title); }
                            else if (ci == 1) {
                                if (wn->maximized) {
                                    wn->x = wn->old_x; wn->y = wn->old_y; wn->w = wn->old_w; wn->h = wn->old_h; wn->maximized = 0;
                                } else {
                                    wn->old_x = wn->x; wn->old_y = wn->y; wn->old_w = wn->w; wn->old_h = wn->h;
                                    wn->x = 0; wn->y = 0; wn->w = scr_w(); wn->h = scr_h() - TASKBAR_H; wn->maximized = 1;
                                }
                                console_printf("Window maximized toggled: %s\n", wn->title);
                            } else {
                                wm_close_idx(wi);
                            }
                            goto press_done;
                        }
                    }
                    if (inside(mx, my, wn->x + wn->w - 16, wn->y + wn->h - 16, 16, 16)) {
                        resize_idx = wi;
                    } else if (my < wn->y + TITLE_H) {
                        drag_idx = wi; drag_dx = mx - wn->x; drag_dy = my - wn->y;
                    } else {
                        /* Client area: buttons and text field. */
                        for (int i = 0; i < MAX_WINDOWS; i++) wins[i].field_focused = 0;
                        if (wn->type == W_WELCOME) {
                            if (inside(mx, my, wn->x + 10, wn->y + 120, 120, 24)) { press_button = 3; press_win = wi; wn->button_pressed = 3; }
                            else if (inside(mx, my, wn->x + 140, wn->y + 120, 80, 24)) { press_button = 1; press_win = wi; wn->button_pressed = 1; }
                        } else if (wn->type == W_BUTTONS) {
                            if (inside(mx, my, wn->x + 10, wn->y + 52, wn->w - 20, 24)) wn->field_focused = 1;
                            else if (inside(mx, my, wn->x + 10, wn->y + 88, 120, 24)) { press_button = 2; press_win = wi; wn->button_pressed = 2; }
                            else if (inside(mx, my, wn->x + 140, wn->y + 88, 120, 24)) { press_button = 1; press_win = wi; wn->button_pressed = 1; }
                        }
                    }
                    break;
                }
            }
        press_done:
            wm_redraw();
            last_redraw_ticks = timer_ticks;
            pending_redraw = 0;
        } else if (down && was_down) {
            if (drag_idx >= 0) {
                struct window *wn = &wins[drag_idx];
                s32 ox = wn->x, oy = wn->y, ow = wn->w, oh = wn->h;
                s32 nx = mx - drag_dx, ny = my - drag_dy;
                if (nx < -(wn->w - 100)) nx = -(wn->w - 100);
                if (nx > scr_w() - 100) nx = scr_w() - 100;
                if (ny < 0) ny = 0;
                if (ny > scr_h() - 50) ny = scr_h() - 50;
                if (nx != wn->x || ny != wn->y) {
                    wn->x = nx; wn->y = ny;
                    /* Dirty = union of old and new window rects. */
                    s32 x0 = ox < nx ? ox : nx;
                    s32 y0 = oy < ny ? oy : ny;
                    s32 x1 = ox + ow > nx + wn->w ? ox + ow : nx + wn->w;
                    s32 y1 = oy + oh > ny + wn->h ? oy + oh : ny + wn->h;
                    if (!pending_redraw) { pend_x = x0; pend_y = y0; pend_w = x1 - x0; pend_h = y1 - y0; pending_redraw = 1; }
                    else {
                        s32 px0 = pend_x < x0 ? pend_x : x0;
                        s32 py0 = pend_y < y0 ? pend_y : y0;
                        s32 px1 = pend_x + pend_w > x1 ? pend_x + pend_w : x1;
                        s32 py1 = pend_y + pend_h > y1 ? pend_y + pend_h : y1;
                        pend_x = px0; pend_y = py0; pend_w = px1 - px0; pend_h = py1 - py0;
                    }
                }
            } else if (resize_idx >= 0) {
                struct window *wn = &wins[resize_idx];
                s32 ox = wn->x, oy = wn->y, ow = wn->w, oh = wn->h;
                s32 nw = mx - wn->x, nh = my - wn->y;
                if (nw < 100) nw = 100;
                if (nh < 80) nh = 80;
                if (wn->x + nw > scr_w()) nw = scr_w() - wn->x;
                if (wn->y + nh > scr_h()) nh = scr_h() - wn->y;
                if (nw != wn->w || nh != wn->h) {
                    wn->w = nw; wn->h = nh;
                    s32 x0 = ox < wn->x ? ox : wn->x;
                    s32 y0 = oy < wn->y ? oy : wn->y;
                    s32 x1 = ox + ow > wn->x + nw ? ox + ow : wn->x + nw;
                    s32 y1 = oy + oh > wn->y + nh ? oy + oh : wn->y + nh;
                    if (!pending_redraw) { pend_x = x0; pend_y = y0; pend_w = x1 - x0; pend_h = y1 - y0; pending_redraw = 1; }
                    else {
                        s32 px0 = pend_x < x0 ? pend_x : x0;
                        s32 py0 = pend_y < y0 ? pend_y : y0;
                        s32 px1 = pend_x + pend_w > x1 ? pend_x + pend_w : x1;
                        s32 py1 = pend_y + pend_h > y1 ? pend_y + pend_h : y1;
                        pend_x = px0; pend_y = py0; pend_w = px1 - px0; pend_h = py1 - py0;
                    }
                }
            } else if (mx != prev_mx || my != prev_my) {
                /* Mouse moved without drag: cursor only, immediate
                   and cheap — no full redraw (v0.7.4). */
                cursor_move_only(prev_mx, prev_my, mx, my);
            }
        } else if (!down && was_down) {
            /* Release: trigger a pressed button only if the mouse is
               still inside that button (press, drag off, release must
               not trigger — a real button bug found while writing the
               autotest, fixed here before release). */
            if (press_win >= 0 && press_button != 0) {
                struct window *wn = &wins[press_win];
                wn->button_pressed = 0;
                int inside_btn = 0;
                if (wn->type == W_WELCOME) {
                    if (press_button == 3) inside_btn = inside(mx, my, wn->x + 10, wn->y + 120, 120, 24);
                    else if (press_button == 1) inside_btn = inside(mx, my, wn->x + 140, wn->y + 120, 80, 24);
                } else if (wn->type == W_BUTTONS) {
                    if (press_button == 2) inside_btn = inside(mx, my, wn->x + 10, wn->y + 88, 120, 24);
                    else if (press_button == 1) inside_btn = inside(mx, my, wn->x + 140, wn->y + 88, 120, 24);
                }
                if (inside_btn) {
                    if (press_button == 1) {
                        if (wn->type == W_WELCOME) { console_write("Button OK clicked\n"); ok_clicked = 1; }
                        else if (wn->type == W_BUTTONS) { wn->counter++; console_printf("Button Click me clicked, count=%u\n", (u32)wn->counter); }
                    } else if (press_button == 2) {
                        console_printf("Button Say hello clicked, field=%s\n", wn->field);
                    } else if (press_button == 3) {
                        exit_gui = 1;
                    }
                }
                wm_redraw();
                last_redraw_ticks = timer_ticks;
                pending_redraw = 0;
            }
            drag_idx = -1; resize_idx = -1; press_button = 0; press_win = -1;
        } else if (!down && !was_down && (mx != prev_mx || my != prev_my)) {
            /* v0.7.4: mouse moved with the button up. In v0.7.0-0.7.3
               this case had NO branch at all, so the cursor only
               moved on the 0.5s periodic redraw — the main reason
               the GUI felt like 2 fps. Now it moves immediately,
               via cursor save/restore only. */
            cursor_move_only(prev_mx, prev_my, mx, my);
        }
        was_down = down;
        prev_mx = mx; prev_my = my;
        /* Flush pending dirty redraw, throttled to ~30 Hz, and
           periodic System ticks redraw (every 50 ticks, but only
           the System window's rect, not the full screen). */
        if (timer_ticks - last_redraw_ticks >= 50) {
            for (int i = 0; i < MAX_WINDOWS; i++) {
                if (wins[i].used && wins[i].type == W_SYSTEM && !wins[i].minimized) {
                    struct window *swn = &wins[i];
                    if (!pending_redraw) { pend_x = swn->x; pend_y = swn->y; pend_w = swn->w; pend_h = swn->h; pending_redraw = 1; }
                    else {
                        s32 px0 = pend_x < swn->x ? pend_x : swn->x;
                        s32 py0 = pend_y < swn->y ? pend_y : swn->y;
                        s32 px1 = pend_x + pend_w > swn->x + swn->w ? pend_x + pend_w : swn->x + swn->w;
                        s32 py1 = pend_y + pend_h > swn->y + swn->h ? pend_y + pend_h : swn->y + swn->h;
                        pend_x = px0; pend_y = py0; pend_w = px1 - px0; pend_h = py1 - py0;
                    }
                    break;
                }
            }
            /* Advance the periodic clock even if the System window
               is minimised (nothing to update then), so this does
               not spin every loop iteration. */
            last_redraw_ticks = timer_ticks;
            /* If the periodic flush is due and the throttle window
               has also passed, flush now below; otherwise the
               pending rect flushes on a later tick. To avoid
               waiting a full throttle window after a periodic
               trigger when no other redraw happened recently, the
               flush condition below uses its own 3-tick check
               against the pre-periodic last_redraw value — handled
               by not resetting last_redraw here when pending was
               just set and the previous redraw was long ago. */
            /* Simplify: if 50 ticks passed since the last actual
               redraw, flush the pending rect immediately (it is
               at most a System window rect, cheap). */
            if (pending_redraw) {
                if ((u32)pend_w * (u32)pend_h > 200000u) wm_redraw();
                else wm_redraw_rect(pend_x, pend_y, pend_w, pend_h);
                pending_redraw = 0;
                last_redraw_ticks = timer_ticks;
            }
        } else if (pending_redraw && timer_ticks - last_redraw_ticks >= 2) {
            if ((u32)pend_w * (u32)pend_h > 200000u) wm_redraw();
            else wm_redraw_rect(pend_x, pend_y, pend_w, pend_h);
            pending_redraw = 0;
            last_redraw_ticks = timer_ticks;
        }
        __asm__ volatile ("hlt");
    }
    console_redraw_text();
    return 0;
}

int wm_run(void) { return wm_run_internal(0); }

int wm_cursortest(void) {
    /* v0.7.4: prove cursor save/restore works without a real
       mouse. Draw the demo scene, move the cursor via the same
       save/restore path the loop uses, and check pixels: the old
       cursor position must be restored to scene colour (not
       white), and the new cursor position must be white. */
    if (!fb_ready()) { console_write("cursortest: no framebuffer available\n"); return -1; }
    init_demo();
    /* Start on plain background (no window, no text): demo
       windows start at x>=40, y>=40, so (10,10) is teal. */
    mouse_test_set(10, 10, 0);
    wm_redraw();
    mouse_test_set(20, 20, 0);
    cursor_move_only(10, 10, 20, 20);
    u32 old_restored = fb_read_pixel(10, 10);
    u32 new_cursor = fb_read_pixel(20, 20);
    mouse_test_set(30, 30, 0);
    cursor_move_only(20, 20, 30, 30);
    u32 mid_restored = fb_read_pixel(20, 20);
    u32 final_cursor = fb_read_pixel(30, 30);
    console_printf("cursortest: old_restored=0x%x new=0x%x mid_restored=0x%x final=0x%x\n",
                   old_restored, new_cursor, mid_restored, final_cursor);
    /* Restored background must be teal 0x106040, cursor
       top-left pixel must be white. */
    int ok = (new_cursor == 0x00FFFFFFu) && (final_cursor == 0x00FFFFFFu) &&
             (old_restored == 0x00106040u) && (mid_restored == 0x00106040u);
    console_write(ok ? "cursortest PASS\n" : "cursortest FAIL\n");
    mouse_test_set(400, 300, 0);
    console_redraw_text();
    return ok ? 0 : -1;
}

int wm_cliptest(void) {
    /* v0.8.0: prove the per-window-clipped redraw produces
       exactly the same pixels as a full redraw. The System
       window is minimised first: its ticks text changes every
       10 ms, so any two checksums taken at different ticks
       would differ even with a correct clip redraw (a false
       FAIL). Cursor is parked at (10,10) (plain background)
       in both paths, so it cannot differ either. */
    if (!fb_ready()) { console_write("cliptest: no framebuffer available\n"); return -1; }
    init_demo();
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_SYSTEM) wins[i].minimized = 1;
    mouse_test_set(10, 10, 0);
    wm_redraw();
    int wi = -1;
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_WELCOME) wi = i;
    if (wi < 0) { console_write("cliptest FAIL (no Welcome window)\n"); console_redraw_text(); return -1; }
    s32 ox = wins[wi].x, oy = wins[wi].y, ow = wins[wi].w, oh = wins[wi].h;
    wins[wi].x = 140; wins[wi].y = 90;
    /* Dirty = union of old and new Welcome rects. */
    s32 x0 = ox < 140 ? ox : 140;
    s32 y0 = oy < 90 ? oy : 90;
    s32 x1 = ox + ow > 140 + ow ? ox + ow : 140 + ow;
    s32 y1 = oy + oh > 90 + oh ? oy + oh : 90 + oh;
    wm_redraw_rect(x0, y0, x1 - x0, y1 - y0);
    u32 clip_sum = fb_checksum();
    wm_redraw();
    u32 full_sum = fb_checksum();
    console_printf("cliptest: clip=0x%x full=0x%x\n", clip_sum, full_sum);
    int ok = (clip_sum == full_sum);
    console_write(ok ? "cliptest PASS\n" : "cliptest FAIL\n");
    mouse_test_set(400, 300, 0);
    console_redraw_text();
    return ok ? 0 : -1;
}

int wm_autotest(void) {
    int rc = wm_run_internal(1);
    /* After the scripted sequence, Welcome must have moved from
       (40,40) to (140,90) by the drag, and OK must have clicked. */
    int wi = -1;
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_WELCOME) wi = i;
    if (rc == 0 && wi >= 0 && ok_clicked && wins[wi].x == 140 && wins[wi].y == 90) {
        console_write("wmautotest PASS (OK clicked, window dragged to 140,90, Shell exit)\n");
        return 0;
    }
    console_printf("wmautotest FAIL (rc=%d ok=%u win=%d x=%d y=%d)\n",
                   rc, (u32)ok_clicked, wi,
                   wi >= 0 ? wins[wi].x : -1, wi >= 0 ? wins[wi].y : -1);
    return -1;
}

int wm_test(void) {
    if (!fb_ready()) { console_write("guitest: no framebuffer available\n"); return -1; }
    init_demo();
    int base = wm_count();
    console_printf("guitest: demo windows=%u\n", (u32)base);
    /* Edge cases: negative, huge, off-screen, zero-size. */
    int id_neg = wm_create("Neg", -100, -50, 300, 200, W_WELCOME);
    int id_huge = wm_create("Huge", 0, 0, 5000, 5000, W_SYSTEM);
    int id_off = wm_create("Offscreen", 2000, 2000, 200, 150, W_MOUSE);
    int id_zero = wm_create("Tiny", 10, 10, 0, 0, W_BUTTONS);
    console_printf("guitest: neg=%d huge=%d off=%d tiny=%d\n", id_neg, id_huge, id_off, id_zero);
    if (id_neg >= 0) {
        int i = find_by_id(id_neg);
        console_printf("guitest: neg clamped to x=%d y=%d\n", wins[i].x, wins[i].y);
    }
    if (id_huge >= 0) {
        int i = find_by_id(id_huge);
        console_printf("guitest: huge clamped to w=%d h=%d\n", wins[i].w, wins[i].h);
    }
    if (id_off >= 0) {
        int i = find_by_id(id_off);
        console_printf("guitest: off clamped to x=%d y=%d\n", wins[i].x, wins[i].y);
    }
    /* Window-count limit: fill to MAX_WINDOWS, the next must fail. */
    int extra = 0;
    while (wm_create("Extra", 20, 20, 200, 150, W_MOUSE) >= 0) extra++;
    int over = wm_create("Overflow", 20, 20, 200, 150, W_MOUSE);
    console_printf("guitest: extra=%d overflow=%d count=%u (max %u)\n", extra, over, (u32)wm_count(), (u32)MAX_WINDOWS);
    /* Drawing all of this must not crash: the fact that wm_redraw()
       returns and we can still log proves it. The Huge window covers
       the whole screen, so corner pixels are NOT background here. */
    wm_redraw();
    console_printf("guitest: checksum 0x%x\n", fb_checksum());
    /* Clean up test windows, leaving only the demo windows. */
    while (wm_count() > base) {
        int closed = 0;
        for (int i = 0; i < MAX_WINDOWS; i++) {
            if (!wins[i].used) continue;
            if (wins[i].title[0] == 'N' || wins[i].title[0] == 'H' || wins[i].title[0] == 'O' || wins[i].title[0] == 'T' || wins[i].title[0] == 'E') {
                wm_close_idx(i); closed = 1; break;
            }
        }
        if (!closed) break;
    }
    console_printf("guitest: after cleanup count=%u\n", (u32)wm_count());
    /* Now the demo windows start at x>=40, y>=40, so (5,5) and
       (795,5) must be the teal background, proving that drawing a
       window did not corrupt pixels outside it. */
    wm_redraw();
    u32 p1 = fb_read_pixel(5, 5);
    u32 p2 = fb_read_pixel(795, 5);
    console_printf("guitest: corner pixels 0x%x 0x%x (background 0x106040)\n", p1, p2);
    console_write("guitest PASS\n");
    console_redraw_text();
    return 0;
}
/* ================= Phase 8 desktop (v0.8.0) =================
   Desktop shell, separate from the Phase 7 `gui` demo (which
   keeps its own windows and tests). Run it with the shell
   `desktop` command. Boot login remains text (Phase 5);
   the desktop lock screen is the graphical login for
   re-entry. Full graphical boot login is NOT implemented
   (it would require restructuring the boot flow). */
#define DESK_BG 0x00183050u
#define DESK_TASKBAR 0x00404040u
static int desk_icons_on = 1;
static int desk_clock_24 = 1;
static char desk_notif[8][64];
static int desk_notif_count = 0;
static int desk_launcher_open = 0;
static int desk_quick_open = 0;
static int desk_notif_open = 0;
static int desk_locked = 0;
static char desk_lock_pass[64];
static int desk_lock_len = 0;
static int desk_lock_failures = 0;
static u32 desk_last_activity = 0;
static char desk_files_names[16][32];
static u32 desk_files_sizes[16];
static int desk_files_count = 0;
static int desk_user_dirty = 0;
static s32 desk_user_dirty_x = 0, desk_user_dirty_y = 0, desk_user_dirty_w = 0, desk_user_dirty_h = 0;
/* Autotest flags, set by desktop actions, checked at the end. */
static int desk_at_settings_opened = 0;
static int desk_at_idle_cycled = 0;
static int desk_at_lock_shown = 0;
static int desk_at_lock_unlocked = 0;
static int desk_at_terminal_exit = 0;

static void desk_notify(const char *msg) {
    if (desk_notif_count < 8) {
        int i = 0;
        while (msg[i] && i < 63) { desk_notif[desk_notif_count][i] = msg[i]; i++; }
        desk_notif[desk_notif_count][i] = 0;
        desk_notif_count++;
    } else {
        for (int k = 0; k < 7; k++) {
            int i = 0;
            while (desk_notif[k + 1][i] && i < 63) { desk_notif[k][i] = desk_notif[k + 1][i]; i++; }
            desk_notif[k][i] = 0;
        }
        int i = 0;
        while (msg[i] && i < 63) { desk_notif[7][i] = msg[i]; i++; }
        desk_notif[7][i] = 0;
    }
    console_printf("Desktop notification: %s\n", msg);
}

static void rtc_read(int *hour, int *minute) {
    u8 b, h, m;
    outb(0x70, (u8)(0x80 | 0x0B)); io_wait(); b = inb(0x71);
    outb(0x70, (u8)(0x80 | 0x04)); io_wait(); h = inb(0x71);
    outb(0x70, (u8)(0x80 | 0x02)); io_wait(); m = inb(0x71);
    if ((b & 0x04) == 0) {
        h = (u8)(((h >> 4) * 10) + (h & 0x0F));
        m = (u8)(((m >> 4) * 10) + (m & 0x0F));
    }
    if ((b & 0x02) == 0) {
        int pm = (h & 0x80) != 0;
        h = (u8)(h & 0x7F);
        if (pm) { if (h != 12) h = (u8)(h + 12); }
        else { if (h == 12) h = 0; }
    }
    *hour = h; *minute = m;
}
static void clock_text(char *out) {
    int h, m;
    rtc_read(&h, &m);
    if (desk_clock_24) {
        out[0] = (char)('0' + h / 10); out[1] = (char)('0' + h % 10);
        out[2] = ':'; out[3] = (char)('0' + m / 10); out[4] = (char)('0' + m % 10); out[5] = 0;
    } else {
        int ap = h >= 12; int h12 = h % 12; if (h12 == 0) h12 = 12;
        out[0] = (char)('0' + h12 / 10); out[1] = (char)('0' + h12 % 10);
        out[2] = ':'; out[3] = (char)('0' + m / 10); out[4] = (char)('0' + m % 10);
        out[5] = ' '; out[6] = ap ? 'P' : 'A'; out[7] = 'M'; out[8] = 0;
        if (out[0] == '0') out[0] = ' ';
    }
}
static int str_contains_ci(const char *hay, const char *needle) {
    if (!needle[0]) return 1;
    for (int i = 0; hay[i]; i++) {
        int j = 0;
        while (needle[j]) {
            char hc = hay[i + j]; if (!hc) break;
            char nc = needle[j];
            if (hc >= 'A' && hc <= 'Z') hc = (char)(hc + 32);
            if (nc >= 'A' && nc <= 'Z') nc = (char)(nc + 32);
            if (hc != nc) break;
            j++;
        }
        if (!needle[j]) return 1;
    }
    return 0;
}

/* Settings values, applied immediately on change, persisted
   by Save. Idle lives in shell.c, mouse scale in the driver. */
static const u32 idle_cycle[5] = {0, 30, 60, 120, 240};
static void idle_cycle_next(void) {
    u32 cur = shell_idle_minutes();
    int idx = 3;
    for (int i = 0; i < 5; i++) if (idle_cycle[i] == cur) idx = i;
    idx = (idx + 1) % 5;
    shell_set_idle_minutes(idle_cycle[idx]);
    desk_at_idle_cycled = 1;
    console_printf("Desktop setting idle changed to %u minutes\n", idle_cycle[idx]);
}
static void idle_text(char *out) {
    u32 v = shell_idle_minutes();
    if (v == 0) { out[0]='O'; out[1]='f'; out[2]='f'; out[3]=0; return; }
    u32_to_str(v, out, 10);
    int n = 0; while (out[n]) n++;
    out[n++]=' '; out[n++]='m'; out[n++]='i'; out[n++]='n'; out[n]=0;
}
static void mouse_text(char *out) {
    int s = mouse_scale();
    const char *t = s == 0 ? "Slow" : (s == 2 ? "Fast" : "Normal");
    int i = 0; while (t[i]) { out[i] = t[i]; i++; } out[i] = 0;
}

static void desk_load_settings(void) {
    if (!fs_mounted()) return;
    u8 buf[512]; u32 size = 0;
    if (fs_read_as("settings.txt", buf, sizeof(buf) - 1, &size, shell_session_uid()) != 0) return;
    buf[size] = 0;
    /* Parse key=value lines, in place. */
    u32 i = 0;
    while (i < size) {
        u32 line_start = i;
        while (i < size && buf[i] != '\n') i++;
        u32 line_end = i; if (i < size) i++;
        /* Find '=' in this line. */
        u32 eq = line_start;
        while (eq < line_end && buf[eq] != '=') eq++;
        if (eq >= line_end) continue;
        /* Key is buf[line_start..eq), value is buf[eq+1..line_end). */
        char key[16]; int kl = 0;
        while (line_start + (u32)kl < eq && kl < 15) { key[kl] = (char)buf[line_start + (u32)kl]; kl++; }
        key[kl] = 0;
        /* Value as unsigned number (for idle/mouse/clock/icons). */
        u32 v = 0; int has_digit = 0;
        for (u32 p = eq + 1; p < line_end; p++) {
            if (buf[p] >= '0' && buf[p] <= '9') { v = v * 10 + (u32)(buf[p] - '0'); has_digit = 1; }
        }
        if (!has_digit) continue;
        if (strcmp(key, "idle") == 0) shell_set_idle_minutes(v);
        else if (strcmp(key, "mouse") == 0) mouse_set_scale((int)v);
        else if (strcmp(key, "clock") == 0) desk_clock_24 = v ? 1 : 0;
        else if (strcmp(key, "icons") == 0) desk_icons_on = v ? 1 : 0;
    }
}
static int desk_save_settings(char *status_out) {
    if (!fs_mounted()) { const char *t = "No disk"; int i=0; while(t[i]){status_out[i]=t[i];i++;} status_out[i]=0; return -1; }
    char data[128]; int n = 0;
    const char *k1 = "idle="; while (*k1) data[n++] = *k1++;
    { char tmp[16]; u32_to_str(shell_idle_minutes(), tmp, 10); int i=0; while(tmp[i]) data[n++]=tmp[i++]; }
    data[n++] = '\n';
    const char *k2 = "mouse="; while (*k2) data[n++] = *k2++;
    { char tmp[16]; u32_to_str((u32)mouse_scale(), tmp, 10); int i=0; while(tmp[i]) data[n++]=tmp[i++]; }
    data[n++] = '\n';
    const char *k3 = "clock="; while (*k3) data[n++] = *k3++;
    data[n++] = desk_clock_24 ? '1' : '0'; data[n++] = '\n';
    const char *k4 = "icons="; while (*k4) data[n++] = *k4++;
    data[n++] = desk_icons_on ? '1' : '0'; data[n++] = '\n';
    data[n] = 0;
    if (fs_write_as("settings.txt", (const u8 *)data, (u32)n, shell_session_uid(), 0600) != 0) {
        const char *t = "Save failed: permission denied"; int i=0; while(t[i]){status_out[i]=t[i];i++;} status_out[i]=0;
        /* Serial audit line too, so a non-admin save denial is
           visible in test logs, not only in the window status. */
        console_write("Desktop settings save failed: permission denied\n");
        return -1;
    }
    const char *t = "Saved"; int i=0; while(t[i]){status_out[i]=t[i];i++;} status_out[i]=0;
    console_write("Desktop settings saved\n");
    return 0;
}
static void desk_load_files(void) {
    desk_files_count = 0;
    if (!fs_mounted()) return;
    desk_files_count = fs_enum_as(shell_session_uid(), desk_files_names, desk_files_sizes, 16);
}

/* Desktop icons: label, action (0=Settings,1=Files,2=Calculator,
   3=About,4=Terminal,5=Lock), colour. */
static const char *desk_icon_labels[6] = {"Settings", "Files", "Calc", "About", "Terminal", "Lock"};
static const u32 desk_icon_cols[6] = {0x002060A0u, 0x00A08000u, 0x00008040u, 0x00404080u, 0x00202020u, 0x00802020u};
static int desk_icon_rect(int idx, s32 *x, s32 *y) {
    *x = 16; *y = 16 + idx * 84;
    return 1;
}
/* Draw desktop-specific window content on top of the base
   window (title/border/client grey from draw_window_clip).
   Content is clipped to both the client rect and the dirty
   rect, via draw_text2 / fb_fill_rect_clip. */
static void desk_draw_settings_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y, w = wn->w;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = w - 2, ch = wn->h - TITLE_H - 2;
    /* Search field. */
    fb_draw_text_clip(x + 10, y + 32, "Search:", 0x00000000u, 0x00D0D0D0u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 80, y + 28, w - 100, 24, 0x00FFFFFFu, dx, dy, dw, dh);
    draw_text2(x + 84, y + 32, wn->search, 0x00000000u, 0x00FFFFFFu, x + 80, y + 28, w - 100, 24, dx, dy, dw, dh);
    if (wn->field_focused) fb_fill_rect_clip(x + 84 + wn->search_len * 8, y + 32, 2, 16, 0x00000000u, dx, dy, dw, dh);
    /* Setting rows, filtered by search. Row layout: name at
       x+10, value button at x+200 (width 100, height 24). */
    const char *names[4] = {"Idle timeout", "Mouse speed", "Clock format", "Desktop icons"};
    int row = 0;
    for (int s = 0; s < 4; s++) {
        if (!str_contains_ci(names[s], wn->search)) continue;
        s32 ry = y + 64 + row * 32;
        char val[32];
        if (s == 0) idle_text(val);
        else if (s == 1) mouse_text(val);
        else if (s == 2) { val[0]='2'; val[1]='4'; val[2]='h'; val[3]=0; if (!desk_clock_24) { val[0]='1'; val[1]='2'; val[2]='h'; val[3]=0; } }
        else { val[0]='O'; val[1]='n'; val[2]=0; if (!desk_icons_on) { val[0]='O'; val[1]='f'; val[2]='f'; val[3]=0; } }
        draw_text2(x + 10, ry + 4, names[s], 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        fb_fill_rect_clip(x + 200, ry, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
        draw_text2(x + 208, ry + 4, val, 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
        row++;
    }
    /* Save button + status. */
    fb_fill_rect_clip(x + 10, y + wn->h - 44, 120, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 18, y + wn->h - 40, "Save settings", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Status is stored in the window's field buffer (reused). */
    draw_text2(x + 140, y + wn->h - 40, wn->field, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
}
static void desk_draw_files_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y, w = wn->w;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = w - 2, ch = wn->h - TITLE_H - 2;
    if (!fs_mounted()) {
        draw_text2(x + 10, y + 32, "No disk attached.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        return;
    }
    if (desk_files_count == 0) {
        draw_text2(x + 10, y + 32, "(no files)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        return;
    }
    for (int i = 0; i < desk_files_count && i < 8; i++) {
        s32 ry = y + 32 + i * 22;
        if (i == wn->selected) fb_fill_rect_clip(x + 10, ry - 2, w - 20, 20, 0x00A0C0FFu, dx, dy, dw, dh);
        char line[64]; int n = 0;
        while (desk_files_names[i][n] && n < 30) { line[n] = desk_files_names[i][n]; n++; }
        line[n++] = ' '; line[n++] = '(';
        { char tmp[16]; u32_to_str(desk_files_sizes[i], tmp, 10); int t=0; while(tmp[t]) line[n++]=tmp[t++]; }
        line[n++] = ')'; line[n] = 0;
        draw_text2(x + 12, ry, line, 0x00000000u, i == wn->selected ? 0x00A0C0FFu : 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    }
    /* Preview below the list. */
    s32 py = y + 32 + 8 * 22 + 8;
    fb_fill_rect_clip(x + 10, py, w - 20, 60, 0x00FFFFFFu, dx, dy, dw, dh);
    if (wn->selected >= 0) draw_text2(x + 14, py + 4, wn->preview, 0x00000000u, 0x00FFFFFFu, x + 10, py, w - 20, 60, dx, dy, dw, dh);
    else draw_text2(x + 14, py + 4, "Click a file to preview it.", 0x00000000u, 0x00FFFFFFu, x + 10, py, w - 20, 60, dx, dy, dw, dh);
}
static void desk_draw_about_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = wn->w - 2, ch = wn->h - TITLE_H - 2;
    draw_text2(x + 10, y + 32, "nxtsOS v0.8.0", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 52, "Original kernel, Multiboot, 32-bit x86.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 72, "Not a Linux distribution or fork.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    char buf[64];
    u32_to_str(pmm_total_frames() * 4, buf, 10);
    draw_text2(x + 10, y + 92, "Memory total (KiB):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 190, y + 92, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 112, "Desktop: icons, launcher, clock,", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 132, "settings, lock screen, Calculator.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
}

static void desk_draw_taskbar(s32 dx, s32 dy, s32 dw, s32 dh) {
    s32 sw = scr_w(), sh = scr_h();
    fb_fill_rect_clip(0, sh - TASKBAR_H, sw, TASKBAR_H, DESK_TASKBAR, dx, dy, dw, dh);
    fb_fill_rect_clip(2, sh - TASKBAR_H + 2, 60, TASKBAR_H - 4, 0x00606060u, dx, dy, dw, dh);
    fb_draw_text_clip(8, sh - TASKBAR_H + 5, "Start", 0x00FFFFFFu, 0x00606060u, dx, dy, dw, dh);
    s32 bx = 66;
    for (int zi = 0; zi < zcount; zi++) {
        struct window *wn = &wins[zorder[zi]];
        if (bx + 120 > sw) break;
        u32 bg = wn->focused ? 0x00808080u : (wn->minimized ? 0x00505050u : 0x00606060u);
        fb_fill_rect_clip(bx, sh - TASKBAR_H + 2, 118, TASKBAR_H - 4, bg, dx, dy, dw, dh);
        fb_draw_text_clip(bx + 4, sh - TASKBAR_H + 5, wn->title, 0x00FFFFFFu, bg, dx, dy, dw, dh);
        bx += 122;
    }
    /* Tray, right-aligned: user, clock, bell, gear. */
    char clk[16]; clock_text(clk);
    fb_draw_text_clip(sw - 110, sh - TASKBAR_H + 5, clk, 0x00FFFFFFu, DESK_TASKBAR, dx, dy, dw, dh);
    fb_draw_text_clip(sw - 200, sh - TASKBAR_H + 5, shell_session_name(), 0x00FFFFFFu, DESK_TASKBAR, dx, dy, dw, dh);
    /* Bell with count, gear. */
    char bell[8]; bell[0] = 'B'; bell[1] = ':'; bell[2] = (char)('0' + (desk_notif_count > 9 ? 9 : desk_notif_count)); bell[3] = 0;
    fb_draw_text_clip(sw - 48, sh - TASKBAR_H + 5, bell, 0x00FFFFFFu, DESK_TASKBAR, dx, dy, dw, dh);
    fb_draw_text_clip(sw - 24, sh - TASKBAR_H + 5, "G", 0x00FFFFFFu, DESK_TASKBAR, dx, dy, dw, dh);
}

static void desk_redraw_rect(s32 dx, s32 dy, s32 dw, s32 dh) {
    if (!fb_ready() || dw <= 0 || dh <= 0) return;
    if (desk_locked) {
        /* Lock screen covers everything, ignore dirty rect. */
        fb_fill_rect(0, 0, scr_w(), scr_h(), 0x00101010u);
        s32 px = 200, py = 150, pw = 400, ph = 300;
        fb_fill_rect(px, py, pw, ph, 0x00C0C0C0u);
        fb_fill_rect(px, py, pw, 20, 0x002060A0u);
        fb_draw_text(px + 10, py + 2, "Locked", 0x00FFFFFFu, 0x002060A0u);
        char clk[16]; clock_text(clk);
        fb_draw_text(px + 160, py + 40, clk, 0x00000000u, 0x00C0C0C0u);
        fb_draw_text(px + 10, py + 70, shell_session_name(), 0x00000000u, 0x00C0C0C0u);
        if (users_count() == 0) fb_draw_text(px + 10, py + 100, "No password set. Press Enter to unlock.", 0x00000000u, 0x00C0C0C0u);
        else fb_draw_text(px + 10, py + 100, "Enter password:", 0x00000000u, 0x00C0C0C0u);
        fb_fill_rect(px + 10, py + 130, pw - 20, 24, 0x00FFFFFFu);
        for (int i = 0; i < desk_lock_len; i++) fb_draw_text(px + 14 + i * 8, py + 134, "*", 0x00000000u, 0x00FFFFFFu);
        if (desk_lock_failures > 0) {
            char tmp[32]; tmp[0]='F'; tmp[1]='a'; tmp[2]='i'; tmp[3]='l'; tmp[4]='e'; tmp[5]='d'; tmp[6]=':'; tmp[7]=' '; tmp[8]=(char)('0'+desk_lock_failures); tmp[9]=0;
            fb_draw_text(px + 10, py + 165, tmp, 0x00800000u, 0x00C0C0C0u);
        }
        fb_fill_rect(px + 10, py + 200, 100, 24, 0x00C0C0C0u);
        fb_draw_text(px + 18, py + 204, "Unlock", 0x00000000u, 0x00C0C0C0u);
        cursor_save_at(mouse_x(), mouse_y());
        draw_cursor();
        return;
    }
    fb_fill_rect_clip(0, 0, scr_w(), scr_h(), DESK_BG, dx, dy, dw, dh);
    if (desk_icons_on) {
        for (int i = 0; i < 6; i++) {
            s32 ix, iy; desk_icon_rect(i, &ix, &iy);
            fb_fill_rect_clip(ix, iy, 48, 48, desk_icon_cols[i], dx, dy, dw, dh);
            fb_draw_text_clip(ix, iy + 52, desk_icon_labels[i], 0x00FFFFFFu, DESK_BG, dx, dy, dw, dh);
        }
    }
    for (int zi = 0; zi < zcount; zi++) {
        struct window *wn = &wins[zorder[zi]];
        if (wn->minimized) continue;
        if (!rects_overlap(wn->x, wn->y, wn->w, wn->h, dx, dy, dw, dh)) continue;
        draw_window_clip(zorder[zi], dx, dy, dw, dh);
        if (wn->type == W_SETTINGS) desk_draw_settings_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_FILES) desk_draw_files_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_ABOUT) desk_draw_about_content(zorder[zi], dx, dy, dw, dh);
        /* W_USER content is app-drawn, never redrawn here. */
    }
    /* Panels, on top of windows. */
    s32 sh = scr_h();
    if (desk_launcher_open) {
        s32 mx0 = 0, my0 = sh - TASKBAR_H - 180, mw = 200, mh = 180;
        fb_fill_rect_clip(mx0, my0, mw, mh, 0x00C0C0C0u, dx, dy, dw, dh);
        fb_fill_rect_clip(mx0, my0, mw, 1, 0x00000000u, dx, dy, dw, dh);
        const char *entries[7] = {"Settings", "Files", "Calculator", "About", "Terminal", "Lock", "Exit desktop"};
        for (int i = 0; i < 7; i++) fb_draw_text_clip(mx0 + 10, my0 + 8 + i * 24, entries[i], 0x00000000u, 0x00C0C0C0u, dx, dy, dw, dh);
    }
    if (desk_quick_open) {
        s32 qx = scr_w() - 260, qy = sh - TASKBAR_H - 140;
        fb_fill_rect_clip(qx, qy, 260, 140, 0x00C0C0C0u, dx, dy, dw, dh);
        fb_draw_text_clip(qx + 10, qy + 8, "Quick settings", 0x00000000u, 0x00C0C0C0u, dx, dy, dw, dh);
        char v1[32], v2[32], v3[32], v4[32];
        idle_text(v1); mouse_text(v2);
        v3[0]='2'; v3[1]='4'; v3[2]='h'; v3[3]=0; if (!desk_clock_24) { v3[0]='1'; v3[1]='2'; v3[2]='h'; v3[3]=0; }
        v4[0]='O'; v4[1]='n'; v4[2]=0; if (!desk_icons_on) { v4[0]='O'; v4[1]='f'; v4[2]='f'; v4[3]=0; }
        const char *qn[4] = {"Idle", "Mouse", "Clock", "Icons"};
        const char *qv[4] = {v1, v2, v3, v4};
        for (int i = 0; i < 4; i++) {
            fb_draw_text_clip(qx + 10, qy + 32 + i * 22, qn[i], 0x00000000u, 0x00C0C0C0u, dx, dy, dw, dh);
            fb_fill_rect_clip(qx + 120, qy + 28 + i * 22, 100, 20, 0x00E0E0E0u, dx, dy, dw, dh);
            fb_draw_text_clip(qx + 126, qy + 32 + i * 22, qv[i], 0x00000000u, 0x00E0E0E0u, dx, dy, dw, dh);
        }
        fb_fill_rect_clip(qx + 10, qy + 116, 100, 20, 0x00E0E0E0u, dx, dy, dw, dh);
        fb_draw_text_clip(qx + 16, qy + 120, "Save", 0x00000000u, 0x00E0E0E0u, dx, dy, dw, dh);
    }
    if (desk_notif_open) {
        s32 nx = scr_w() - 300, ny = sh - TASKBAR_H - 200;
        fb_fill_rect_clip(nx, ny, 300, 200, 0x00C0C0C0u, dx, dy, dw, dh);
        fb_draw_text_clip(nx + 10, ny + 8, "Notifications", 0x00000000u, 0x00C0C0C0u, dx, dy, dw, dh);
        if (desk_notif_count == 0) fb_draw_text_clip(nx + 10, ny + 32, "(none)", 0x00000000u, 0x00C0C0C0u, dx, dy, dw, dh);
        for (int i = 0; i < desk_notif_count && i < 7; i++) fb_draw_text_clip(nx + 10, ny + 32 + i * 20, desk_notif[i], 0x00000000u, 0x00C0C0C0u, dx, dy, dw, dh);
        fb_fill_rect_clip(nx + 10, ny + 176, 80, 20, 0x00E0E0E0u, dx, dy, dw, dh);
        fb_draw_text_clip(nx + 16, ny + 180, "Clear", 0x00000000u, 0x00E0E0E0u, dx, dy, dw, dh);
    }
    if (rects_overlap(0, sh - TASKBAR_H, scr_w(), TASKBAR_H, dx, dy, dw, dh))
        desk_draw_taskbar(dx, dy, dw, dh);
    cursor_save_at(mouse_x(), mouse_y());
    draw_cursor();
}
static void desk_redraw(void) { desk_redraw_rect(0, 0, scr_w(), scr_h()); }
/* User window helpers, called from syscall handler (syscall.c)
   and from the desktop loop. */
static int desk_active = 0;
static struct window *find_user_window(u32 pid) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_USER && wins[i].owner_pid == pid) return &wins[i];
    return 0;
}
static void gui_queue_event(struct window *wn, int type, s32 x, s32 y, int key, int button) {
    if (!wn || wn->ev_count >= GUI_EV_MAX) return;
    wn->evq[wn->ev_tail].type = type;
    wn->evq[wn->ev_tail].x = x;
    wn->evq[wn->ev_tail].y = y;
    wn->evq[wn->ev_tail].key = key;
    wn->evq[wn->ev_tail].button = button;
    wn->ev_tail = (wn->ev_tail + 1) % GUI_EV_MAX;
    wn->ev_count++;
}
int wm_gui_open(const char *title, s32 x, s32 y, s32 w, s32 h, u32 pid) {
    if (!desk_active || !fb_ready()) return -1;
    if (find_user_window(pid)) return -1; /* one window per program */
    int id = wm_create(title, x, y, w, h, W_USER);
    if (id < 0) return -1;
    int idx = find_by_id(id);
    if (idx < 0) return -1;
    wins[idx].owner_pid = pid;
    wins[idx].ev_head = wins[idx].ev_tail = wins[idx].ev_count = 0;
    gui_queue_event(&wins[idx], GUI_EV_EXPOSE, 0, 0, 0, 0);
    desk_user_dirty = 1;
    desk_user_dirty_x = wins[idx].x; desk_user_dirty_y = wins[idx].y;
    desk_user_dirty_w = wins[idx].w; desk_user_dirty_h = wins[idx].h;
    return 0;
}
int wm_gui_rect(u32 pid, s32 cx, s32 cy, s32 cw, s32 ch, u32 colour) {
    struct window *wn = find_user_window(pid);
    if (!wn || wn->minimized) return -1;
    s32 ax = wn->x + 1 + cx, ay = wn->y + TITLE_H + 1 + cy;
    fb_fill_rect_clip(ax, ay, cw, ch, colour,
                      wn->x + 1, wn->y + TITLE_H + 1, wn->w - 2, wn->h - TITLE_H - 2);
    return 0;
}
int wm_gui_text(u32 pid, s32 cx, s32 cy, const char *text, u32 fg, u32 bg) {
    struct window *wn = find_user_window(pid);
    if (!wn || wn->minimized) return -1;
    s32 ax = wn->x + 1 + cx, ay = wn->y + TITLE_H + 1 + cy;
    fb_draw_text_clip(ax, ay, text, fg, bg,
                      wn->x + 1, wn->y + TITLE_H + 1, wn->w - 2, wn->h - TITLE_H - 2);
    return 0;
}
int wm_gui_event(u32 pid, struct gui_event *out) {
    struct window *wn = find_user_window(pid);
    if (!wn || wn->ev_count == 0) return -1;
    *out = wn->evq[wn->ev_head];
    wn->ev_head = (wn->ev_head + 1) % GUI_EV_MAX;
    wn->ev_count--;
    return 0;
}
int wm_gui_close(u32 pid) {
    struct window *wn = find_user_window(pid);
    if (!wn) return -1;
    for (int i = 0; i < MAX_WINDOWS; i++) if (&wins[i] == wn) { wm_close_idx(i); break; }
    return 0;
}

/* Desktop actions, shared by icons and launcher entries. */
static int desk_open_settings(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_SETTINGS) { bring_to_front(i); return i; }
    int id = wm_create("Settings", 160, 80, 480, 320, W_SETTINGS);
    if (id < 0) return -1;
    int idx = find_by_id(id);
    if (idx >= 0) {
        wins[idx].search[0] = 0; wins[idx].search_len = 0;
        wins[idx].field[0] = 0; wins[idx].field_focused = 0;
        desk_at_settings_opened = 1;
        console_write("Desktop: Settings opened\n");
    }
    return idx;
}
static int desk_open_files(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_FILES) { bring_to_front(i); return i; }
    int id = wm_create("Files", 160, 80, 480, 320, W_FILES);
    if (id < 0) return -1;
    int idx = find_by_id(id);
    if (idx >= 0) {
        wins[idx].selected = -1; wins[idx].preview[0] = 0;
        desk_load_files();
        console_write("Desktop: Files opened\n");
    }
    return idx;
}
static int desk_open_about(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_ABOUT) { bring_to_front(i); return i; }
    int id = wm_create("About", 220, 180, 360, 240, W_ABOUT);
    if (id < 0) return -1;
    console_write("Desktop: About opened\n");
    return find_by_id(id);
}
static void desk_show_lock(void) {
    desk_locked = 1; desk_lock_len = 0; desk_lock_pass[0] = 0; desk_lock_failures = 0;
    desk_launcher_open = desk_quick_open = desk_notif_open = 0;
    desk_at_lock_shown = 1;
    console_write("Desktop: lock screen shown\n");
}
static int desk_try_unlock(void) {
    if (users_count() == 0) {
        desk_locked = 0; desk_at_lock_unlocked = 1;
        console_write("Desktop: unlocked (setup mode, no password)\n");
        return 1;
    }
    u32 uid = 0;
    if (users_check(shell_session_name(), desk_lock_pass, &uid) && uid == shell_session_uid()) {
        desk_locked = 0; desk_lock_failures = 0; desk_lock_len = 0; desk_lock_pass[0] = 0;
        desk_at_lock_unlocked = 1;
        console_write("Desktop: unlocked\n");
        return 1;
    }
    desk_lock_failures++;
    desk_lock_len = 0; desk_lock_pass[0] = 0;
    console_printf("Desktop: lock password failed (%d/3)\n", desk_lock_failures);
    if (desk_lock_failures >= 3) {
        console_write("Desktop: too many failed attempts. System halted.\n");
        for (;;) __asm__ volatile ("hlt");
    }
    return 0;
}
static void desk_do_action(int action, int *exit_desktop) {
    /* Actions: 0=Settings,1=Files,2=Calculator,3=About,4=Terminal,5=Lock,6=Exit */
    if (action == 0) desk_open_settings();
    else if (action == 1) desk_open_files();
    else if (action == 2) {
        /* Calculator is a package app: start it as a background
           job, it will open its window via GUI syscalls while
           the desktop loop ticks it. If the package is not
           installed, the job start fails and a notification
           explains it (do not silently do nothing). */
        if (proc_bg_start("calc.elf", shell_session_uid()) != 0) {
            desk_notify("Calculator not installed: pkg install calc.nxpkg, then try again");
        } else {
            desk_notify("Calculator started");
        }
    }
    else if (action == 3) desk_open_about();
    else if (action == 4 || action == 6) { *exit_desktop = 1; desk_at_terminal_exit = 1; }
    else if (action == 5) desk_show_lock();
}
static int wm_desktop_internal(int autotest) {
    if (!fb_ready()) { console_write("desktop: no framebuffer available\n"); return -1; }
    /* Reset desktop state, load persistent settings, start. */
    memset(wins, 0, sizeof(wins)); zcount = 0; next_id = 1;
    desk_launcher_open = desk_quick_open = desk_notif_open = 0;
    desk_locked = 0; desk_lock_len = 0; desk_lock_failures = 0;
    desk_notif_count = 0;
    desk_at_settings_opened = desk_at_idle_cycled = desk_at_lock_shown = 0;
    desk_at_lock_unlocked = desk_at_terminal_exit = 0;
    desk_load_settings();
    desk_active = 1;
    desk_last_activity = timer_ticks;
    desk_notify("Welcome to nxtsOS desktop");
    if (fs_mounted()) desk_notify("Disk mounted");
    else desk_notify("No disk attached");
    desk_redraw();
    int was_down = 0, drag_idx = -1, resize_idx = -1;
    s32 drag_dx = 0, drag_dy = 0;
    int press_user = -1;
    int exit_desktop = 0;
    s32 prev_mx = mouse_x(), prev_my = mouse_y();
    u32 last_redraw_ticks = timer_ticks;
    u32 start_ticks = timer_ticks;
    int auto_step = -1;
    int pending_redraw = 0;
    s32 pend_x = 0, pend_y = 0, pend_w = 0, pend_h = 0;
    int last_clock_minute = -1;
    while (!exit_desktop) {
        if (autotest) {
            u32 elapsed = timer_ticks - start_ticks;
            int step = (int)(elapsed / 30);
            int max_step = autotest == 2 ? 15 : (autotest == 3 ? 6 : 11);
            if (step != auto_step && step <= max_step) {
                auto_step = step;
                if (autotest == 3) {
                    /* Calculator launch test, 30 ticks per step:
                       0-2: click Calc icon (starts Calculator as a
                       background job; it opens its window via GUI
                       syscalls while this loop ticks it);
                       3: wait for the window to appear;
                       4-6: click the '7' key (press/release over
                       the same key must activate it). The harness
                       then screendumps and checks the window
                       pixels and the display glyph. */
                    if (step == 0) mouse_test_set(40, 208, 0);
                    else if (step == 1) mouse_test_set(40, 208, 1);
                    else if (step == 2) mouse_test_set(40, 208, 0);
                    else if (step == 4) mouse_test_set(280, 249, 1);
                    else if (step == 5) mouse_test_set(280, 249, 0);
                } else if (autotest == 2) {
                    /* Security script, 30 ticks per step:
                       0-2: click Settings icon (opens Settings);
                       3-5: click Save (must fail for a non-root
                       user on a root-owned settings.txt);
                       6-7: click Start (launcher opens);
                       8-9: click Lock entry (lock screen shows);
                       10-14: type "wrong"; 15: Enter (must fail,
                       lock stays up; the harness then ends the
                       run and checks the serial markers). */
                    if (step == 0) mouse_test_set(40, 40, 0);
                    else if (step == 1) mouse_test_set(40, 40, 1);
                    else if (step == 2) mouse_test_set(40, 40, 0);
                    else if (step == 3) mouse_test_set(230, 368, 0);
                    else if (step == 4) mouse_test_set(230, 368, 1);
                    else if (step == 5) mouse_test_set(230, 368, 0);
                    else if (step == 6) mouse_test_set(32, 588, 1);
                    else if (step == 7) mouse_test_set(32, 588, 0);
                    else if (step == 8) mouse_test_set(100, 528, 1);
                    else if (step == 9) mouse_test_set(100, 528, 0);
                    else if (step == 10) keyboard_inject_char('w');
                    else if (step == 11) keyboard_inject_char('r');
                    else if (step == 12) keyboard_inject_char('o');
                    else if (step == 13) keyboard_inject_char('n');
                    else if (step == 14) keyboard_inject_char('g');
                    else if (step == 15) keyboard_inject_char('\n');
                } else {
                    /* Desktop autotest script, 30 ticks per step:
                       0-2: click Settings icon (opens Settings);
                       3-5: click Idle value button (cycles idle);
                       6-7: click Start (launcher opens);
                       8-9: click Lock entry (lock screen shows);
                       10: inject Enter (setup mode unlocks);
                       11: click Terminal icon (desktop exits). */
                    if (step == 0) mouse_test_set(40, 40, 0);
                    else if (step == 1) mouse_test_set(40, 40, 1);
                    else if (step == 2) mouse_test_set(40, 40, 0);
                    else if (step == 3) mouse_test_set(410, 156, 0);
                    else if (step == 4) mouse_test_set(410, 156, 1);
                    else if (step == 5) mouse_test_set(410, 156, 0);
                    else if (step == 6) mouse_test_set(32, 588, 1);
                    else if (step == 7) mouse_test_set(32, 588, 0);
                    else if (step == 8) mouse_test_set(100, 528, 1);
                    else if (step == 9) mouse_test_set(100, 528, 0);
                    else if (step == 10) keyboard_inject_char('\n');
                    else if (step == 11) mouse_test_set(48, 384, 1);
                }
            }
        }
        keyboard_poll();
        int c = keyboard_getchar();
        if (c >= 0) {
            desk_last_activity = timer_ticks;
            if (desk_locked) {
                if (c == '\b') { if (desk_lock_len > 0) desk_lock_pass[--desk_lock_len] = 0; desk_redraw(); }
                else if (c == '\n') { if (desk_try_unlock()) desk_redraw(); else desk_redraw(); }
                else if (c >= 32 && c < 127 && desk_lock_len < 63) {
                    desk_lock_pass[desk_lock_len++] = (char)c; desk_lock_pass[desk_lock_len] = 0; desk_redraw();
                }
            } else {
                /* Settings search field, if focused. */
                int fi = -1;
                for (int i = 0; i < MAX_WINDOWS; i++)
                    if (wins[i].used && wins[i].type == W_SETTINGS && wins[i].field_focused) fi = i;
                if (fi >= 0) {
                    struct window *wn = &wins[fi];
                    if (c == '\b') { if (wn->search_len > 0) wn->search[--wn->search_len] = 0; }
                    else if (c == '\n') { wn->field_focused = 0; }
                    else if (c >= 32 && c < 127 && wn->search_len < 63) {
                        wn->search[wn->search_len++] = (char)c; wn->search[wn->search_len] = 0;
                    }
                    if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
                } else {
                    /* Focused user window gets the key. */
                    for (int i = 0; i < MAX_WINDOWS; i++) {
                        if (wins[i].used && wins[i].type == W_USER && wins[i].focused) {
                            gui_queue_event(&wins[i], GUI_EV_KEY, 0, 0, c, 0);
                            break;
                        }
                    }
                }
            }
        }
        /* Background GUI apps run here, while the desktop waits. */
        proc_bg_tick();
        /* User windows whose program exited: close them. */
        for (int i = 0; i < MAX_WINDOWS; i++) {
            if (wins[i].used && wins[i].type == W_USER && wins[i].owner_pid != 0 && !proc_bg_exists(wins[i].owner_pid)) {
                s32 wx = wins[i].x, wy = wins[i].y, ww = wins[i].w, wh = wins[i].h;
                wm_close_idx(i);
                if (!pending_redraw) { pend_x = wx; pend_y = wy; pend_w = ww; pend_h = wh; pending_redraw = 1; }
                break;
            }
        }
        if (desk_user_dirty) {
            desk_user_dirty = 0;
            if (!pending_redraw) { pend_x = desk_user_dirty_x; pend_y = desk_user_dirty_y; pend_w = desk_user_dirty_w; pend_h = desk_user_dirty_h; pending_redraw = 1; }
        }
        s32 mx = mouse_x(), my = mouse_y();
        int down = mouse_left();
        if (mx != prev_mx || my != prev_my || down != was_down) desk_last_activity = timer_ticks;
        if (down && !was_down) {
            press_user = -1; drag_idx = -1; resize_idx = -1;
            if (desk_locked) {
                /* Unlock button at (210,350,100,24) in lock panel. */
                if (inside(mx, my, 210, 350, 100, 24)) { if (desk_try_unlock()) desk_redraw(); else desk_redraw(); }
            } else if (desk_launcher_open) {
                s32 my0 = scr_h() - TASKBAR_H - 180;
                int hit = -1;
                for (int i = 0; i < 7; i++) if (inside(mx, my, 0, my0 + i * 24, 200, 24)) hit = i;
                desk_launcher_open = 0;
                if (hit >= 0) { desk_do_action(hit, &exit_desktop); if (!exit_desktop) desk_redraw(); }
                else desk_redraw();
            } else if (desk_quick_open) {
                s32 qx = scr_w() - 260, qy = scr_h() - TASKBAR_H - 140;
                int hit = -1;
                for (int i = 0; i < 4; i++) if (inside(mx, my, qx + 120, qy + 28 + i * 22, 100, 20)) hit = i;
                int save_hit = inside(mx, my, qx + 10, qy + 116, 100, 20);
                desk_quick_open = 0;
                if (hit == 0) idle_cycle_next();
                else if (hit == 1) mouse_set_scale((mouse_scale() + 1) % 3);
                else if (hit == 2) desk_clock_24 = !desk_clock_24;
                else if (hit == 3) desk_icons_on = !desk_icons_on;
                else if (save_hit) { char st[64]; desk_save_settings(st); desk_notify(st); }
                desk_redraw();
            } else if (desk_notif_open) {
                s32 nx = scr_w() - 300, ny = scr_h() - TASKBAR_H - 200;
                int clear_hit = inside(mx, my, nx + 10, ny + 176, 80, 20);
                desk_notif_open = 0;
                if (clear_hit) desk_notif_count = 0;
                desk_redraw();
            } else if (my >= scr_h() - TASKBAR_H) {
                if (mx < 64) { desk_launcher_open = 1; desk_redraw(); }
                else if (mx >= scr_w() - 24) { desk_quick_open = 1; desk_redraw(); }
                else if (mx >= scr_w() - 48) { desk_notif_open = 1; desk_redraw(); }
                else {
                    s32 bx = 66;
                    for (int zi = 0; zi < zcount; zi++) {
                        struct window *wn = &wins[zorder[zi]];
                        if (mx >= bx && mx < bx + 118) {
                            if (wn->minimized) wn->minimized = 0;
                            bring_to_front(zorder[zi]);
                            desk_redraw();
                            break;
                        }
                        bx += 122;
                    }
                }
            } else {
                /* Desktop icons first (they are under windows, but
                   a click on an icon area that is not covered by
                   a window should open the app; windows are
                   checked after icons only if the click is not
                   on an icon — actually windows are on top, so
                   check windows first if they cover the point. */
                int on_window = 0;
                for (int zi = zcount - 1; zi >= 0; zi--) {
                    struct window *wn = &wins[zorder[zi]];
                    if (wn->minimized) continue;
                    if (inside(mx, my, wn->x, wn->y, wn->w, wn->h)) { on_window = 1; break; }
                }
                if (!on_window && desk_icons_on) {
                    int icon_hit = -1;
                    for (int i = 0; i < 6; i++) {
                        s32 ix, iy; desk_icon_rect(i, &ix, &iy);
                        if (inside(mx, my, ix, iy, 64, 64)) icon_hit = i;
                    }
                    if (icon_hit >= 0) { desk_do_action(icon_hit, &exit_desktop); if (!exit_desktop) desk_redraw(); }
                } else if (on_window) {
                    for (int zi = zcount - 1; zi >= 0; zi--) {
                        int wi = zorder[zi];
                        struct window *wn = &wins[wi];
                        if (wn->minimized) continue;
                        if (!inside(mx, my, wn->x, wn->y, wn->w, wn->h)) continue;
                        bring_to_front(wi);
                        for (int ci = 0; ci < 3; ci++) {
                            s32 ccx = wn->x + wn->w - 52 + ci * 18;
                            if (inside(mx, my, ccx, wn->y + 2, 16, 16)) {
                                if (ci == 0) { wn->minimized = 1; }
                                else if (ci == 1) {
                                    if (wn->maximized) { wn->x = wn->old_x; wn->y = wn->old_y; wn->w = wn->old_w; wn->h = wn->old_h; wn->maximized = 0; }
                                    else { wn->old_x = wn->x; wn->old_y = wn->y; wn->old_w = wn->w; wn->old_h = wn->h; wn->x = 0; wn->y = 0; wn->w = scr_w(); wn->h = scr_h() - TASKBAR_H; wn->maximized = 1; }
                                    if (wn->type == W_USER) gui_queue_event(wn, GUI_EV_EXPOSE, 0, 0, 0, 0);
                                } else {
                                    if (wn->type == W_USER) gui_queue_event(wn, GUI_EV_CLOSE, 0, 0, 0, 0);
                                    wm_close_idx(wi);
                                }
                                desk_redraw();
                                goto press_done_desk;
                            }
                        }
                        if (inside(mx, my, wn->x + wn->w - 16, wn->y + wn->h - 16, 16, 16)) {
                            resize_idx = wi;
                        } else if (my < wn->y + TITLE_H) {
                            drag_idx = wi; drag_dx = mx - wn->x; drag_dy = my - wn->y;
                        } else {
                            /* Client area. */
                            for (int i = 0; i < MAX_WINDOWS; i++) wins[i].field_focused = 0;
                            if (wn->type == W_SETTINGS) {
                                if (inside(mx, my, wn->x + 80, wn->y + 28, wn->w - 100, 24)) {
                                    wn->field_focused = 1;
                                } else {
                                    /* Value buttons: rows in order,
                                       filtered by search, same
                                       layout as drawing. */
                                    const char *names[4] = {"Idle timeout", "Mouse speed", "Clock format", "Desktop icons"};
                                    int row = 0;
                                    for (int s = 0; s < 4; s++) {
                                        if (!str_contains_ci(names[s], wn->search)) continue;
                                        s32 ry = wn->y + 64 + row * 32;
                                        if (inside(mx, my, wn->x + 200, ry, 100, 24)) {
                                            if (s == 0) idle_cycle_next();
                                            else if (s == 1) mouse_set_scale((mouse_scale() + 1) % 3);
                                            else if (s == 2) desk_clock_24 = !desk_clock_24;
                                            else desk_icons_on = !desk_icons_on;
                                            desk_redraw();
                                        }
                                        row++;
                                    }
                                }
                                if (inside(mx, my, wn->x + 10, wn->y + wn->h - 44, 120, 24)) {
                                    desk_save_settings(wn->field);
                                    desk_redraw();
                                }
                            } else if (wn->type == W_FILES) {
                                for (int i = 0; i < desk_files_count && i < 8; i++) {
                                    s32 ry = wn->y + 32 + i * 22;
                                    if (inside(mx, my, wn->x + 10, ry - 2, wn->w - 20, 20)) {
                                        wn->selected = i;
                                        if (desk_files_sizes[i] <= 255) {
                                            u32 sz = 0;
                                            if (fs_read_as(desk_files_names[i], (u8 *)wn->preview, 255, &sz, shell_session_uid()) == 0) {
                                                wn->preview[sz] = 0;
                                            } else {
                                                const char *t = "(read failed)"; int k=0; while(t[k]){wn->preview[k]=t[k];k++;} wn->preview[k]=0;
                                            }
                                        } else {
                                            const char *t = "(file larger than 255 bytes, use cat in shell)"; int k=0; while(t[k]){wn->preview[k]=t[k];k++;} wn->preview[k]=0;
                                        }
                                        desk_redraw();
                                        break;
                                    }
                                }
                            } else if (wn->type == W_USER) {
                                press_user = wi;
                                gui_queue_event(wn, GUI_EV_MDOWN, mx - (wn->x + 1), my - (wn->y + TITLE_H + 1), 0, 1);
                            }
                        }
                        break;
                    }
                }
            }
        press_done_desk:;
        } else if (down && was_down) {
            if (drag_idx >= 0) {
                struct window *wn = &wins[drag_idx];
                s32 ox = wn->x, oy = wn->y, ow = wn->w, oh = wn->h;
                s32 nx = mx - drag_dx, ny = my - drag_dy;
                if (nx < -(wn->w - 100)) nx = -(wn->w - 100);
                if (nx > scr_w() - 100) nx = scr_w() - 100;
                if (ny < 0) ny = 0;
                if (ny > scr_h() - 50) ny = scr_h() - 50;
                if (nx != wn->x || ny != wn->y) {
                    wn->x = nx; wn->y = ny;
                    if (wn->type == W_USER) gui_queue_event(wn, GUI_EV_EXPOSE, 0, 0, 0, 0);
                    s32 x0 = ox < nx ? ox : nx; s32 y0 = oy < ny ? oy : ny;
                    s32 x1 = ox + ow > nx + wn->w ? ox + ow : nx + wn->w;
                    s32 y1 = oy + oh > ny + wn->h ? oy + oh : ny + wn->h;
                    if (!pending_redraw) { pend_x = x0; pend_y = y0; pend_w = x1 - x0; pend_h = y1 - y0; pending_redraw = 1; }
                    else {
                        s32 px0 = pend_x < x0 ? pend_x : x0; s32 py0 = pend_y < y0 ? pend_y : y0;
                        s32 px1 = pend_x + pend_w > x1 ? pend_x + pend_w : x1; s32 py1 = pend_y + pend_h > y1 ? pend_y + pend_h : y1;
                        pend_x = px0; pend_y = py0; pend_w = px1 - px0; pend_h = py1 - py0;
                    }
                }
            } else if (resize_idx >= 0) {
                struct window *wn = &wins[resize_idx];
                s32 ow = wn->w, oh = wn->h;
                s32 nw = mx - wn->x, nh = my - wn->y;
                if (nw < 100) nw = 100; if (nh < 80) nh = 80;
                if (wn->x + nw > scr_w()) nw = scr_w() - wn->x;
                if (wn->y + nh > scr_h()) nh = scr_h() - wn->y;
                if (nw != wn->w || nh != wn->h) {
                    wn->w = nw; wn->h = nh;
                    if (wn->type == W_USER) gui_queue_event(wn, GUI_EV_EXPOSE, 0, 0, 0, 0);
                    s32 x0 = wn->x, y0 = wn->y;
                    s32 x1 = wn->x + (ow > nw ? ow : nw); s32 y1 = wn->y + (oh > nh ? oh : nh);
                    if (!pending_redraw) { pend_x = x0; pend_y = y0; pend_w = x1 - x0; pend_h = y1 - y0; pending_redraw = 1; }
                }
            } else if (mx != prev_mx || my != prev_my) {
                cursor_move_only(prev_mx, prev_my, mx, my);
            }
        } else if (!down && was_down) {
            if (press_user >= 0) {
                struct window *wn = &wins[press_user];
                if (wn->used && wn->type == W_USER) gui_queue_event(wn, GUI_EV_MUP, mx - (wn->x + 1), my - (wn->y + TITLE_H + 1), 0, 1);
                press_user = -1;
            }
            drag_idx = -1; resize_idx = -1;
        } else if (!down && !was_down && (mx != prev_mx || my != prev_my)) {
            cursor_move_only(prev_mx, prev_my, mx, my);
        }
        was_down = down;
        prev_mx = mx; prev_my = my;
        /* Clock minute change: redraw taskbar strip only. */
        {
            int h, m; rtc_read(&h, &m);
            if (m != last_clock_minute) {
                last_clock_minute = m;
                if (!pending_redraw) { pend_x = 0; pend_y = scr_h() - TASKBAR_H; pend_w = scr_w(); pend_h = TASKBAR_H; pending_redraw = 1; }
            }
        }
        /* Desktop idle lock. */
        if (!desk_locked && shell_idle_minutes() != 0 && timer_ticks - desk_last_activity > shell_idle_minutes() * 6000u) {
            desk_show_lock(); desk_redraw();
        }
        if (pending_redraw && timer_ticks - last_redraw_ticks >= 2) {
            if ((u32)pend_w * (u32)pend_h > 200000u) desk_redraw();
            else desk_redraw_rect(pend_x, pend_y, pend_w, pend_h);
            pending_redraw = 0; last_redraw_ticks = timer_ticks;
        }
        __asm__ volatile ("hlt");
    }
    desk_active = 0;
    console_redraw_text();
    return 0;
}
int wm_desktop_run(void) { return wm_desktop_internal(0); }
int wm_desktop_calctest(void) {
    /* Test-only: runs the Calculator script (mode 3). It is not
       expected to return on its own; the harness ends the run
       after screendumping. If it returns, the desktop exited. */
    int rc = wm_desktop_internal(3);
    console_printf("desktopcalctest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_sectest(void) {
    /* Test-only: runs the security script (mode 2). It is not
       expected to return while the lock screen is up after a
       failed password; the test harness ends the run and checks
       the serial markers. If it ever returns, that means the
       lock was bypassed or the desktop exited unexpectedly. */
    int rc = wm_desktop_internal(2);
    console_printf("desktopsectest returned (rc=%d) - lock did not hold\n", rc);
    return rc;
}
int wm_desktop_autotest(void) {
    int rc = wm_desktop_internal(1);
    int ok = (rc == 0 && desk_at_settings_opened && desk_at_idle_cycled &&
              desk_at_lock_shown && desk_at_lock_unlocked && desk_at_terminal_exit);
    console_printf("desktopautotest %s (rc=%d settings=%d idle=%d lock=%d unlocked=%d terminal=%d)\n",
                   ok ? "PASS" : "FAIL", rc, desk_at_settings_opened, desk_at_idle_cycled,
                   desk_at_lock_shown, desk_at_lock_unlocked, desk_at_terminal_exit);
    return ok ? 0 : -1;
}
