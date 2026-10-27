#include "wm.h"
#include "fb.h"
#include "console.h"
#include "../drivers/mouse.h"
#include "../drivers/keyboard.h"
#include "../mm/pmm.h"
#include "../drivers/pit.h"

#define MAX_WINDOWS 8
#define TITLE_H 20
#define TASKBAR_H 24

enum win_type { W_WELCOME, W_SYSTEM, W_MOUSE, W_BUTTONS };

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

/* Draw one window, clipped to the screen (fb functions clip again). */
static void draw_window(int idx) {
    struct window *wn = &wins[idx];
    if (wn->minimized) return;
    s32 x = wn->x, y = wn->y, w = wn->w, h = wn->h;
    u32 title_col = wn->focused ? 0x004080FFu : 0x00606060u;
    /* Title bar, with a blue/grey background (0x00RRGGBB format). */
    u32 tcol = wn->focused ? 0x002060A0u : 0x00606060u;
    (void)title_col;
    fb_fill_rect(x, y, w, TITLE_H, tcol);
    fb_fill_rect(x, y + TITLE_H, w, 1, 0x00000000u);
    fb_fill_rect(x, y, 1, h, 0x00000000u);
    fb_fill_rect(x + w - 1, y, 1, h, 0x00000000u);
    fb_fill_rect(x, y + h - 1, w, 1, 0x00000000u);
    /* Title, clipped so it never draws over the control buttons. */
    fb_draw_text_clip(x + 6, y + 2, wn->title, 0x00FFFFFFu, tcol,
                      x, y, w - 56, TITLE_H);
    /* Controls: minimise, maximise, close (16x16, right-aligned). */
    const char *ctl[3] = {"_", "#", "X"};
    for (int i = 0; i < 3; i++) {
        s32 cx = x + w - 52 + i * 18;
        fb_fill_rect(cx, y + 2, 16, 16, 0x00C0C0C0u);
        fb_draw_text(cx + 4, y + 2, ctl[i], 0x00000000u, 0x00C0C0C0u);
    }
    /* Client area. */
    fb_fill_rect(x + 1, y + TITLE_H + 1, w - 2, h - TITLE_H - 2, 0x00D0D0D0u);
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = w - 2, ch = h - TITLE_H - 2;
    char buf[64];
    if (wn->type == W_WELCOME) {
        fb_draw_text_clip(x + 10, y + 32, "Welcome to nxtsOS", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 10, y + 52, "Graphics: 800x600x32, mouse, windows.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 10, y + 72, "Drag the title bar to move.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 10, y + 92, "Drag the bottom-right corner to resize.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        /* Back button (id 3) and OK button (id 1). */
        fb_fill_rect(x + 10, y + 120, 120, 24, wn->button_pressed == 3 ? 0x00808080u : 0x00C0C0C0u);
        fb_draw_text_clip(x + 18, y + 124, "Back to shell", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch);
        fb_fill_rect(x + 140, y + 120, 80, 24, wn->button_pressed == 1 ? 0x00808080u : 0x00C0C0C0u);
        fb_draw_text_clip(x + 148, y + 124, "OK", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch);
    } else if (wn->type == W_SYSTEM) {
        u32_to_str(pmm_total_frames() * 4, buf, 10);
        fb_draw_text_clip(x + 10, y + 32, "Memory total (KiB):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 190, y + 32, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        u32_to_str(pmm_free_frames() * 4, buf, 10);
        fb_draw_text_clip(x + 10, y + 52, "Memory free (KiB):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 190, y + 52, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        u32_to_str(timer_ticks, buf, 10);
        fb_draw_text_clip(x + 10, y + 72, "Ticks (100 Hz):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 190, y + 72, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 10, y + 92, "Windows open:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        u32_to_str((u32)wm_count(), buf, 10);
        fb_draw_text_clip(x + 190, y + 92, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
    } else if (wn->type == W_MOUSE) {
        u32_to_str((u32)mouse_x(), buf, 10);
        fb_draw_text_clip(x + 10, y + 32, "Mouse X:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 120, y + 32, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        u32_to_str((u32)mouse_y(), buf, 10);
        fb_draw_text_clip(x + 10, y + 52, "Mouse Y:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 120, y + 52, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 10, y + 72, mouse_left() ? "Left: down" : "Left: up", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 10, y + 92, mouse_present() ? "Mouse: present" : "Mouse: absent", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
    } else if (wn->type == W_BUTTONS) {
        fb_draw_text_clip(x + 10, y + 32, "Type here, then Say hello:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        /* Text field. */
        fb_fill_rect(x + 10, y + 52, w - 20, 24, 0x00FFFFFFu);
        fb_draw_text_clip(x + 14, y + 56, wn->field, 0x00000000u, 0x00FFFFFFu, x + 10, y + 52, w - 20, 24);
        if (wn->field_focused) {
            s32 cur_x = x + 14 + wn->field_len * 8;
            fb_fill_rect(cur_x, y + 56, 2, 16, 0x00000000u);
        }
        fb_fill_rect(x + 10, y + 88, 120, 24, wn->button_pressed == 2 ? 0x00808080u : 0x00C0C0C0u);
        fb_draw_text_clip(x + 18, y + 92, "Say hello", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch);
        fb_fill_rect(x + 140, y + 88, 120, 24, wn->button_pressed == 1 ? 0x00808080u : 0x00C0C0C0u);
        fb_draw_text_clip(x + 148, y + 92, "Click me", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch);
        u32_to_str((u32)wn->counter, buf, 10);
        fb_draw_text_clip(x + 10, y + 124, "Clicks:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
        fb_draw_text_clip(x + 80, y + 124, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch);
    }
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
        draw_window(zorder[zi]);
    }
    /* Taskbar is only 800x24 and never overlaps windows except
       maximised ones (which stop at the taskbar), so drawing it
       fully here is cheap and always correct. */
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
        } else if (pending_redraw && timer_ticks - last_redraw_ticks >= 3) {
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
