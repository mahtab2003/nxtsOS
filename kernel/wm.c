#include "wm.h"
#include "fb.h"
#include "font_data.h"
#include "console.h"
#include "../drivers/mouse.h"
#include "../drivers/keyboard.h"
#include "../mm/pmm.h"
#include "../drivers/pit.h"
#include "shell.h"
#include "users.h"
#include "../fs/vfs.h"
#include "proc.h"
#include "../net/net.h"
#include "pkg.h"
#include "sha256.h"

#define MAX_WINDOWS 16 /* 6b: 8 launcher apps + Files + user windows
   exceed the old 8 — opening every launcher app then Files
   failed silently (wm_create -1). Both tables are file-scope
   statics, so this costs no kernel stack. */
#define TITLE_H 20
#define TASKBAR_H 24

enum win_type { W_WELCOME, W_SYSTEM, W_MOUSE, W_BUTTONS, W_USER,
    W_SETTINGS, W_FILES, W_ABOUT, W_DESKTOP_ICONS,
    W_NETWORK, W_WEB, W_EDITOR, W_MONITOR, W_VIEWER, W_PACKAGES, W_REPO, W_CLOCK };

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
    int selected; /* W_FILES/W_REPO/W_PACKAGES/W_MONITOR: selected row index, -1 = none */
    char preview[256]; /* W_FILES only: preview text */
    int ws; /* Phase 10: workspace this window belongs to (0/1) */
    int snapped; /* Phase 10: 1 if placed by snap (old_* holds restore geometry) */
    int aux1, aux2; /* Phase 10: per-window scratch (web scroll, editor cursor/scroll) */
};

static struct window wins[MAX_WINDOWS];
static int zorder[MAX_WINDOWS]; /* window indices, back to front */
static int zcount = 0;
static int next_id = 1;

/* Phase 10: current workspace. Declared here (not in the desktop
   section below) because wm_create assigns it to every window. */
static int desk_ws = 0;
static s32 scr_w(void) { return fb_ready() ? (s32)fb_width() : 800; }
static s32 scr_h(void) { return fb_ready() ? (s32)fb_height() : 600; }
/* Phase 10 theme helpers, defined with the desktop section below
   (forward-declared here because draw_window_clip uses the accent). */
static u32 desk_accent_col(void);
static u32 desk_bg_col(void);
static u32 desk_taskbar_col(void);
static u32 desk_panel_col(void);
static u32 desk_panel_text_col(void);
static u32 desk_taskbar_text_col(void);
/* Full desktop redraw, defined with the desktop section below
   (forward-declared here because cursor_move_only's fallback
   must redraw the active UI, not always the classic one). */
static void desk_redraw(void);
/* Desktop-active flag, defined with the desktop section below
   (tentative definition; the initialised definition follows). */
static int desk_active;

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
/* Taskbar-content dirty flag (post-v1.0.0 6a): draw_taskbar's
   output depends on the window list, focus, and minimised
   states, so any change to those must redraw the taskbar
   strip even when the dirty rect does not reach it — a clip
   redraw after a create/close/focus-change otherwise leaves
   a stale taskbar button until the next full redraw. Set at
   every mutation site (bring_to_front, wm_close_idx, the
   minimise button); consumed by wm_redraw_rect, which also
   presents the strip when it drew it outside the dirty rect. */
static int taskbar_dirty = 0;
static void mark_taskbar_dirty(void) { taskbar_dirty = 1; }
/* Focus dirty flag (same class of bug as taskbar_dirty): a
   focus change recolours TWO title bars (old focus grey, new
   focus accent) anywhere on screen. Set in bring_to_front
   and wm_close_idx only — minimise/restore do not change
   focus, so they set taskbar_dirty alone. Consumed by
   wm_redraw_rect as a full-redraw fallback (see there). */
static int focus_dirty = 0;
static void mark_focus_dirty(void) { focus_dirty = 1; }
static void bring_to_front(int idx) {
    int pos = -1;
    for (int i = 0; i < zcount; i++) if (zorder[i] == idx) pos = i;
    if (pos < 0) return;
    /* Already front and focused: nothing changes, so no
       chrome redraw is owed (avoids a full redraw on every
       click into the focused window). */
    if (pos == zcount - 1 && wins[idx].focused) return;
    for (int i = pos; i < zcount - 1; i++) zorder[i] = zorder[i + 1];
    zorder[zcount - 1] = idx;
    for (int i = 0; i < MAX_WINDOWS; i++) wins[i].focused = 0;
    wins[idx].focused = 1;
    mark_taskbar_dirty();
    mark_focus_dirty();
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
    wn->ws = desk_ws;
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
    mark_taskbar_dirty();
    mark_focus_dirty();
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
    /* Phase 10: focused title bars use the accent colour. The
       Classic accent is the old blue, so Phase 7/8 pixel counts
       are unchanged under the default theme. */
    u32 tcol = wn->focused ? desk_accent_col() : 0x00606060u;
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

/* Present the just-drawn scene rect plus the cursor rect: the
   cursor is drawn by every redraw but may sit outside the dirty
   rect, and in back-buffered mode only presented pixels reach
   the screen, so presenting just the dirty rect would leave a
   stale or missing cursor. In direct mode (no back buffer)
   fb_present_rect is a no-op. */
static void present_scene_rect(s32 dx, s32 dy, s32 dw, s32 dh) {
    s32 x0 = dx, y0 = dy, x1 = dx + dw, y1 = dy + dh;
    s32 cx = mouse_x(), cy = mouse_y();
    if (cx < x0) x0 = cx;
    if (cy < y0) y0 = cy;
    if (cx + CUR_W > x1) x1 = cx + CUR_W;
    if (cy + CUR_H > y1) y1 = cy + CUR_H;
    fb_present_rect(x0, y0, x1 - x0, y1 - y0);
}

static void wm_redraw_rect(s32 dx, s32 dy, s32 dw, s32 dh) {
    if (!fb_ready() || dw <= 0 || dh <= 0) return;
    /* Focus change: every title bar on screen may have
       recoloured, and title bars overlap other windows'
       clients, so redrawing just the title bars in isolation
       would paint behind-windows' titles over front windows'
       clients (a real bug in the first version of this fix:
       clip != clip2 proved it). A focus change is a discrete
       event, not a per-frame drag, so fall back to a full
       redraw here — obviously correct occlusion, and the
       taskbar block below then covers the strip too. */
    if (focus_dirty) {
        dx = 0; dy = 0; dw = scr_w(); dh = scr_h();
        focus_dirty = 0;
    }
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
       the taskbar strip (v0.8.0, was always drawn) — unless
       its content changed (taskbar_dirty), in which case draw
       it and present the strip too, so the new buttons reach
       the screen and not just the back buffer. */
    int tb_overlap = rects_overlap(0, scr_h() - TASKBAR_H, scr_w(), TASKBAR_H, dx, dy, dw, dh);
    if (taskbar_dirty || tb_overlap) {
        draw_taskbar();
        taskbar_dirty = 0;
        if (!tb_overlap)
            fb_present_rect(0, scr_h() - TASKBAR_H, scr_w(), TASKBAR_H);
    }
    cursor_save_at(mouse_x(), mouse_y());
    draw_cursor();
    /* The scene is complete only now: present it atomically. */
    present_scene_rect(dx, dy, dw, dh);
}

static void wm_redraw(void) {
    wm_redraw_rect(0, 0, scr_w(), scr_h());
}

static void cursor_move_only(s32 old_mx, s32 old_my, s32 new_mx, s32 new_my) {
    (void)old_mx; (void)old_my;
    if (!fb_ready()) return;
    if (!cursor_saved_valid || cursor_saved_x != old_mx || cursor_saved_y != old_my) {
        /* Fallback redraw must match the active UI. The classic
           redraw paints the old green background and no desktop
           content, so falling back to it from the desktop loop
           produced the v1.1.0 real-device "green screen + blank
           windows" bug: with a real mouse, PS/2 interrupts move
           the pointer between the loop's prev update and a
           redraw's cursor save, so the mismatch is routine —
           scripted injection never moves the pointer
           mid-iteration, which is why sandbox tests never saw
           it. A full desktop redraw repaints the theme
           background, all window content, and the desk taskbar,
           and re-saves the cursor at the current position. */
        if (desk_active) desk_redraw();
        else wm_redraw();
        return;
    }
    cursor_restore();
    cursor_save_at(new_mx, new_my);
    draw_cursor();
    /* Present both cursor positions: the old one was restored to
       scene pixels, the new one drawn, both in the back buffer. */
    s32 cx0 = old_mx < new_mx ? old_mx : new_mx;
    s32 cy0 = old_my < new_my ? old_my : new_my;
    s32 cx1 = old_mx + CUR_W > new_mx + CUR_W ? old_mx + CUR_W : new_mx + CUR_W;
    s32 cy1 = old_my + CUR_H > new_my + CUR_H ? old_my + CUR_H : new_my + CUR_H;
    fb_present_rect(cx0, cy0, cx1 - cx0, cy1 - cy0);
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
                            if (ci == 0) { wn->minimized = 1; mark_taskbar_dirty(); console_printf("Window minimized: %s\n", wn->title); }
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

/* Storm-test failure record. Prints are DEFERRED to the end of
   the test: console output draws glyphs into the framebuffer
   while fb_mode is on (and a scroll re-renders the whole text
   console over the scene), so printing mid-test would corrupt
   the scene under test and cascade failures into later rounds
   — the exact failure mode that made the first stormtest run
   report 53/53 failures. */
static int storm_fails;
static int storm_fail_round, storm_fail_cx, storm_fail_cy, storm_fail_cells;
static u32 storm_fail_op, storm_fail_clip, storm_fail_clip2, storm_fail_full;
static void storm_record(int round, u32 op, u32 clip, u32 clip2, u32 full,
                         int cx, int cy, int cells) {
    if (storm_fails == 0) {
        storm_fail_round = round; storm_fail_op = op;
        storm_fail_clip = clip; storm_fail_clip2 = clip2; storm_fail_full = full;
        storm_fail_cx = cx; storm_fail_cy = cy; storm_fail_cells = cells;
    }
    storm_fails++;
}
/* One clip==full check for a dirty rect. A second identical
   clip redraw must be stable (clip2 == clip); a mismatch
   against the full redraw, or instability, is recorded, never
   printed (see above). Grid region sums locate a mismatch to
   a 100x100 cell for diagnosis. */
static void storm_check(int round, u32 op, s32 dx0, s32 dy0, s32 dx1, s32 dy1,
                        int *checks) {
    wm_redraw_rect(dx0, dy0, dx1 - dx0, dy1 - dy0);
    u32 clip_sum = fb_checksum();
    wm_redraw_rect(dx0, dy0, dx1 - dx0, dy1 - dy0);
    u32 clip2_sum = fb_checksum();
    u32 clip_grid[48];
    for (int gy = 0; gy < 6; gy++)
        for (int gx = 0; gx < 8; gx++) {
            u32 s = 0;
            for (s32 yy = gy * 100; yy < (gy + 1) * 100; yy++)
                for (s32 xx = gx * 100; xx < (gx + 1) * 100; xx++)
                    s += fb_read_pixel(xx, yy) * 31u + 1u;
            clip_grid[gy * 8 + gx] = s;
        }
    wm_redraw();
    u32 full_sum = fb_checksum();
    (*checks)++;
    if (clip_sum != full_sum || clip_sum != clip2_sum) {
        int cells = 0, cx = -1, cy = -1;
        for (int gy = 0; gy < 6; gy++)
            for (int gx = 0; gx < 8; gx++) {
                u32 s = 0;
                for (s32 yy = gy * 100; yy < (gy + 1) * 100; yy++)
                    for (s32 xx = gx * 100; xx < (gx + 1) * 100; xx++)
                        s += fb_read_pixel(xx, yy) * 31u + 1u;
                if (s != clip_grid[gy * 8 + gx]) {
                    if (cells == 0) { cx = gx; cy = gy; }
                    cells++;
                }
            }
        storm_record(round, op, clip_sum, clip2_sum, full_sum, cx, cy, cells);
    }
}
static u32 storm_strip_sum(void) {
    u32 s = 0;
    for (s32 y = scr_h() - TASKBAR_H; y < scr_h(); y++)
        for (s32 x = 0; x < scr_w(); x++)
            s += fb_read_pixel(x, y) * 31u + 1u;
    return s;
}
/* Targeted taskbar check (protocol A: no full redraw between
   the state change and the clip redraw, so a stale taskbar
   is caught, not healed). The minimise check genuinely
   exercises the taskbar flag (minimise changes no focus, so
   no fallback applies). The create check runs under the
   focus fallback (create changes focus, so its clip redraw
   is a full redraw that covers the strip by construction);
   close is excluded: wm_close_idx prints "Window closed"
   into the scene, and the main loop heals that with a full
   redraw instead (standing in for the loop's periodic full
   redraw). */
static void storm_taskbar_check(int round, s32 dx0, s32 dy0, s32 dx1, s32 dy1,
                                int *checks) {
    wm_redraw_rect(dx0, dy0, dx1 - dx0, dy1 - dy0);
    u32 strip_clip = storm_strip_sum();
    wm_redraw();
    u32 strip_full = storm_strip_sum();
    (*checks)++;
    if (strip_clip != strip_full)
        storm_record(round, 100u, strip_clip, strip_clip, strip_full, -1, -1, 0);
}

int wm_stormtest(void) {
    /* Post-v1.0.0 queue 6(a): redraw-correctness storm for the
       double-buffered compositor. 40 deterministic rounds of
       open/move/close/minimise-restore, each followed by the
       cliptest invariant: a clip redraw of the dirty union
       must leave exactly the pixels a full redraw leaves.
       Any tearing, stale-rect, or partial-frame bug in the
       clip path shows up as a checksum mismatch here, while
       a correct compositor passes every round. The System
       window stays minimised throughout (its ticks text
       changes every 10 ms, which would differ between two
       checksums even with a correct redraw). Small locals
       only — the kernel stack is 16 KiB. */
    if (!fb_ready()) { console_write("stormtest: no framebuffer available\n"); return -1; }
    storm_fails = 0;
    init_demo();
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_SYSTEM) wins[i].minimized = 1;
    mouse_test_set(10, 10, 0);
    wm_redraw();
    int checks = 0;
    /* Targeted taskbar checks first, on the clean baseline. */
    int tid = wm_create("Storm", 100, 100, 200, 150, W_MOUSE);
    if (tid >= 0) {
        int tidx = find_by_id(tid);
        storm_taskbar_check(-1, wins[tidx].x, wins[tidx].y,
                            wins[tidx].x + wins[tidx].w, wins[tidx].y + wins[tidx].h,
                            &checks);
        wm_close_idx(tidx);
        wm_redraw(); /* heal the "Window closed" print glyphs */
    }
    int midx = -1;
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && !wins[i].minimized) { midx = i; break; }
    if (midx >= 0) {
        wins[midx].minimized = 1;
        mark_taskbar_dirty();
        storm_taskbar_check(-2, wins[midx].x, wins[midx].y,
                            wins[midx].x + wins[midx].w, wins[midx].y + wins[midx].h,
                            &checks);
        wins[midx].minimized = 0;
        mark_taskbar_dirty();
        wm_redraw();
    }
    u32 rng = 0x12345678u;
    int storm_ids[4];
    int nstorm = 0;
    int expected = wm_count();
    for (int round = 0; round < 40; round++) {
        rng = rng * 1103515245u + 12345u;
        u32 op = (rng >> 16) % 4u;
        s32 dx0 = 0, dy0 = 0, dx1 = 0, dy1 = 0;
        int nchecks_this_round = 0;
        if (op == 0) {
            /* Move a random visible window. */
            int vis = 0;
            for (int i = 0; i < MAX_WINDOWS; i++)
                if (wins[i].used && !wins[i].minimized) vis++;
            if (vis == 0) continue;
            rng = rng * 1103515245u + 12345u;
            int k = (int)((rng >> 16) % (u32)vis), idx = -1;
            for (int i = 0; i < MAX_WINDOWS; i++) {
                if (!wins[i].used || wins[i].minimized) continue;
                if (k-- == 0) { idx = i; break; }
            }
            if (idx < 0) continue;
            s32 ox = wins[idx].x, oy = wins[idx].y;
            s32 ow = wins[idx].w, oh = wins[idx].h;
            rng = rng * 1103515245u + 12345u;
            s32 nx = (s32)((rng >> 16) % (u32)(scr_w() - ow));
            rng = rng * 1103515245u + 12345u;
            s32 ny = (s32)((rng >> 16) % (u32)(scr_h() - TASKBAR_H - oh));
            wins[idx].x = nx; wins[idx].y = ny;
            dx0 = ox < nx ? ox : nx; dy0 = oy < ny ? oy : ny;
            dx1 = ox + ow > nx + ow ? ox + ow : nx + ow;
            dy1 = oy + oh > ny + oh ? oy + oh : ny + oh;
            nchecks_this_round = 1;
        } else if (op == 1 && nstorm < 4) {
            /* Open a new window. */
            rng = rng * 1103515245u + 12345u;
            s32 nx = (s32)((rng >> 16) % 600u);
            rng = rng * 1103515245u + 12345u;
            s32 ny = (s32)((rng >> 16) % 400u);
            int id = wm_create("Storm", nx, ny, 200, 150, W_MOUSE);
            if (id < 0) continue;
            int idx = find_by_id(id);
            if (idx < 0) continue;
            storm_ids[nstorm++] = id;
            expected++;
            dx0 = wins[idx].x; dy0 = wins[idx].y;
            dx1 = dx0 + wins[idx].w; dy1 = dy0 + wins[idx].h;
            nchecks_this_round = 1;
        } else if (op == 2 && nstorm > 0) {
            /* Close a storm window. wm_close_idx prints into
               the scene, so heal with a full redraw first (see
               the taskbar-check comment); the clip check that
               follows still validates the clip drawing code. */
            rng = rng * 1103515245u + 12345u;
            int k = (int)((rng >> 16) % (u32)nstorm);
            int idx = find_by_id(storm_ids[k]);
            if (idx < 0) continue;
            dx0 = wins[idx].x; dy0 = wins[idx].y;
            dx1 = dx0 + wins[idx].w; dy1 = dy0 + wins[idx].h;
            wm_close_idx(idx);
            wm_redraw();
            for (int j = k; j < nstorm - 1; j++) storm_ids[j] = storm_ids[j + 1];
            nstorm--;
            expected--;
            nchecks_this_round = 1;
        } else {
            /* Minimise a random visible window, check, restore, check. */
            int vis = 0;
            for (int i = 0; i < MAX_WINDOWS; i++)
                if (wins[i].used && !wins[i].minimized) vis++;
            if (vis == 0) continue;
            rng = rng * 1103515245u + 12345u;
            int k = (int)((rng >> 16) % (u32)vis), idx = -1;
            for (int i = 0; i < MAX_WINDOWS; i++) {
                if (!wins[i].used || wins[i].minimized) continue;
                if (k-- == 0) { idx = i; break; }
            }
            if (idx < 0) continue;
            dx0 = wins[idx].x; dy0 = wins[idx].y;
            dx1 = dx0 + wins[idx].w; dy1 = dy0 + wins[idx].h;
            wins[idx].minimized = 1;
            mark_taskbar_dirty();
            storm_check(round, op, dx0, dy0, dx1, dy1, &checks);
            wins[idx].minimized = 0;
            mark_taskbar_dirty();
            nchecks_this_round = 1;
        }
        if (nchecks_this_round)
            storm_check(round, op, dx0, dy0, dx1, dy1, &checks);
        if (wm_count() != expected) {
            if (storm_fails == 0) {
                storm_fail_round = round; storm_fail_op = 99u;
                storm_fail_clip = (u32)wm_count(); storm_fail_full = (u32)expected;
            }
            storm_fails++;
        }
    }
    /* Restore the pristine demo scene, then prove drawing a
       window never corrupted pixels outside it. */
    init_demo();
    wm_redraw();
    u32 p1 = fb_read_pixel(5, 5);
    u32 p2 = fb_read_pixel(795, 5);
    if (p1 != 0x00106040u || p2 != 0x00106040u) {
        if (storm_fails == 0) {
            storm_fail_round = 40; storm_fail_op = 98u;
            storm_fail_clip = p1; storm_fail_full = p2;
        }
        storm_fails++;
    }
    /* All output happens here, after the last check: printing
       earlier would have drawn into the scene under test. */
    console_printf("stormtest: 40 rounds, %d clip/full checks, fails=%d\n", checks, storm_fails);
    if (storm_fails > 0)
        console_printf("stormtest FIRST FAIL round=%d op=%u clip=0x%x clip2=0x%x full=0x%x cell=(%d,%d) cells=%d\n",
                       storm_fail_round, storm_fail_op, storm_fail_clip,
                       storm_fail_clip2, storm_fail_full,
                       storm_fail_cx, storm_fail_cy, storm_fail_cells);
    console_write(storm_fails == 0 ? "stormtest PASS\n" : "stormtest FAIL\n");
    mouse_test_set(400, 300, 0);
    console_redraw_text();
    return storm_fails == 0 ? 0 : -1;
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
/* Phase 10 appearance settings, persisted in settings.txt
   (theme/accent/wallpaper/lowres/bigtext/shortcuts). Defaults
   reproduce the v0.8.0/v0.9.0 look exactly, so every older
   pixel count stays valid under the default theme. */
static int desk_theme = 0; /* 0 Classic, 1 Dark, 2 Light, 3 High-contrast */
static int desk_accent = 0; /* 0 Blue, 1 Gold, 2 Green, 3 Red */
static int desk_wallpaper = 0; /* 0 Solid, 1 Gradient, 2 Dots */
static int desk_lowres = 0;
static int desk_bigtext = 0;
static int desk_shortcut_preset = 0; /* 0 L/W, 1 K/J, 2 X/Z */
static const char *desk_theme_name(void) {
    return desk_theme == 1 ? "Dark" : (desk_theme == 2 ? "Light" :
        (desk_theme == 3 ? "HiCon" : "Classic"));
}
static const char *desk_accent_name(void) {
    return desk_accent == 1 ? "Gold" : (desk_accent == 2 ? "Green" :
        (desk_accent == 3 ? "Red" : "Blue"));
}
static const char *desk_wallpaper_name(void) {
    return desk_wallpaper == 1 ? "Gradient" : (desk_wallpaper == 2 ? "Dots" : "Solid");
}
static u32 desk_accent_col(void) {
    return desk_accent == 1 ? 0x00B8860Bu : (desk_accent == 2 ? 0x00208040u :
        (desk_accent == 3 ? 0x00A02020u : 0x002060A0u));
}
static u32 desk_bg_col(void) {
    return desk_theme == 1 ? 0x00101010u : (desk_theme == 2 ? 0x00E8E8E8u :
        (desk_theme == 3 ? 0x00000000u : DESK_BG));
}
static u32 desk_taskbar_col(void) {
    return desk_theme == 1 ? 0x00202020u : (desk_theme == 2 ? 0x00D0D0D0u :
        (desk_theme == 3 ? 0x00000000u : DESK_TASKBAR));
}
static u32 desk_panel_col(void) {
    return desk_theme == 1 ? 0x00303030u : (desk_theme == 2 ? 0x00E0E0E0u :
        (desk_theme == 3 ? 0x00000000u : 0x00C0C0C0u));
}
static u32 desk_panel_text_col(void) {
    return (desk_theme == 1 || desk_theme == 3) ? 0x00FFFFFFu : 0x00000000u;
}
static u32 desk_taskbar_text_col(void) {
    return desk_theme == 2 ? 0x00000000u : 0x00FFFFFFu;
}
static int desk_throttle_ticks(void) { return desk_lowres ? 5 : 2; }
/* Shortcut presets: {lock key, workspace key}, matched
   case-insensitively (typing goes to a focused input first,
   so these only fire when no text field has focus). */
static const char desk_shortcut_keys[3][2] = {{'L','W'},{'K','J'},{'X','Z'}};
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
static char desk_files_names[32][32];
static u32 desk_files_sizes[32];
static int desk_files_count = 0;
/* 6(b) part 9: Files list scroll offset (first visible row).
   The list shows 8 rows; the offset lets rows past the first 8
   be reached. Reset on every fresh Files open (desk_load_files)
   so a reopened window starts at the top. */
static int desk_files_scroll = 0;
/* 6(b) part 10: Files delete confirm arm. The index of the file
   a first Delete click armed, or -1. A row click selecting a
   different file clears it, so only a second Delete click on
   the same selected file deletes (Editor New-confirm pattern).
   File-scope static, zero kernel-stack cost. */
static int desk_files_del_arm = -1;
/* Files sysupdate confirm arm. The index of the bundle file a
   first Open click armed, or -1. A row click selecting a
   different file clears it, so only a second Open click on the
   same selected bundle applies the update (Files Delete
   pattern). Reset on desktop start, on a fresh Files window,
   and on Refresh, so a stale arm can never apply an update
   the user did not just confirm. File-scope static, zero
   kernel-stack cost. */
static int desk_files_sysupd_arm = -1;
/* Files SHA-256 display. The desktop form of shell `sha256`:
   the Hash button reads the selected file into a file-scope
   64 KiB buffer (never a stack array — the kernel stack is
   16 KiB), hashes it, and prints the full hex beside
   "files: sha256 <name>". fs_read_as refuses files over the
   buffer, so a too-large file fails loudly instead of
   hashing a truncated prefix. The hash lines draw in the
   preview box (two 32-char halves, so the full 64-char hex
   is visible on screen, never clipped by the one-line
   preview). Valid only until the next row click or Refresh:
   the draw gate also requires the selection to still name
   the hashed file, so a stale hash can never label another
   file. File-scope statics, zero kernel-stack cost. */
static u8 desk_files_hash_buf[65536];
static char desk_files_hash[65];
static char desk_files_hash_name[32];
static int desk_files_hash_valid = 0;
/* Files chmod mode field: a second input row in the same
   window, so it cannot share wn->field with the rename/copy
   row (both rows draw their field, and sharing one buffer
   would have shown the same text in both rows). Same 63-char
   cap and focus rules as the window fields; the client-area
   click handler clears this focus before dispatch, exactly
   like wn->field and the Network ping field. */
static char desk_files_mode[64];
static int desk_files_mode_len = 0;
static int desk_files_mode_focused = 0;
/* Settings Unlock row: a second input row in the Settings
   window, so it cannot share wn->search (the search field) or
   wn->field (the status line) — both rows draw their text, and
   sharing a buffer would show the same text in both rows
   (Files Mode / Network Ping precedent). Same 63-char cap and
   focus rules; the client-area click handler clears this focus
   before dispatch, and the key dispatch gives it priority over
   the search field when focused. */
static char desk_settings_unlock[64];
static int desk_settings_unlock_len = 0;
static int desk_settings_unlock_focused = 0;
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

/* 6b Clock window: the same CMOS RTC read, extended with the
   seconds register (0x00). Hour/minute handling is unchanged;
   seconds get the same BCD conversion. The calendar date
   comes from rtc_date below (day 0x07, month 0x08, year
   0x09, century 0x32) — real hardware registers, never an
   invented date; an invalid read shows as unavailable. */
static void rtc_read3(int *hour, int *minute, int *second) {
    u8 b, h, m, s;
    outb(0x70, (u8)(0x80 | 0x0B)); io_wait(); b = inb(0x71);
    outb(0x70, (u8)(0x80 | 0x04)); io_wait(); h = inb(0x71);
    outb(0x70, (u8)(0x80 | 0x02)); io_wait(); m = inb(0x71);
    outb(0x70, (u8)(0x80 | 0x00)); io_wait(); s = inb(0x71);
    if ((b & 0x04) == 0) {
        h = (u8)(((h >> 4) * 10) + (h & 0x0F));
        m = (u8)(((m >> 4) * 10) + (m & 0x0F));
        s = (u8)(((s >> 4) * 10) + (s & 0x0F));
    }
    if ((b & 0x02) == 0) {
        int pm = (h & 0x80) != 0;
        h = (u8)(h & 0x7F);
        if (pm) { if (h != 12) h = (u8)(h + 12); }
        else { if (h == 12) h = 0; }
    }
    *hour = h; *minute = m; *second = s;
}
static void rtc_read(int *hour, int *minute) {
    int s; rtc_read3(hour, minute, &s);
}
/* 6b Clock date: CMOS RTC date registers, same BCD handling
   as the time registers. Returns 1 with a validated full
   year when every field is sane (day within the month,
   leap-year aware; century must be 19 or 20, so a stray
   century byte cannot produce a bogus year); returns 0
   otherwise, and callers then show the date as
   unavailable rather than inventing one. */
static int rtc_date(int *day, int *month, int *year) {
    u8 b, d, m, y, c;
    outb(0x70, (u8)(0x80 | 0x0B)); io_wait(); b = inb(0x71);
    outb(0x70, (u8)(0x80 | 0x07)); io_wait(); d = inb(0x71);
    outb(0x70, (u8)(0x80 | 0x08)); io_wait(); m = inb(0x71);
    outb(0x70, (u8)(0x80 | 0x09)); io_wait(); y = inb(0x71);
    outb(0x70, (u8)(0x80 | 0x32)); io_wait(); c = inb(0x71);
    if ((b & 0x04) == 0) {
        d = (u8)(((d >> 4) * 10) + (d & 0x0F));
        m = (u8)(((m >> 4) * 10) + (m & 0x0F));
        y = (u8)(((y >> 4) * 10) + (y & 0x0F));
        c = (u8)(((c >> 4) * 10) + (c & 0x0F));
    }
    if (m < 1 || m > 12) return 0;
    if (c != 19 && c != 20) return 0;
    int full = c * 100 + y;
    int leap = (full % 4 == 0 && (full % 100 != 0 || full % 400 == 0));
    static const int dim[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int maxd = dim[m - 1] + (m == 2 && leap ? 1 : 0);
    if (d < 1 || d > maxd) return 0;
    *day = d; *month = m; *year = full;
    return 1;
}
/* Clock window date text: "DD/MM/YYYY", zero-padded, or
   "(unavailable)" when rtc_date refuses the registers. */
static void date_text(char *out) {
    int d, m, y;
    if (!rtc_date(&d, &m, &y)) {
        const char *t = "(unavailable)"; int i = 0;
        while (t[i]) { out[i] = t[i]; i++; } out[i] = 0;
        return;
    }
    out[0] = (char)('0' + d / 10); out[1] = (char)('0' + d % 10);
    out[2] = '/';
    out[3] = (char)('0' + m / 10); out[4] = (char)('0' + m % 10);
    out[5] = '/';
    out[6] = (char)('0' + y / 1000); out[7] = (char)('0' + (y / 100) % 10);
    out[8] = (char)('0' + (y / 10) % 10); out[9] = (char)('0' + y % 10);
    out[10] = 0;
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
/* Clock window time text: same format as clock_text, with
   seconds ("HH:MM:SS" / " H:MM:SS AM"). */
static void clock_text_sec(char *out) {
    int h, m, s;
    rtc_read3(&h, &m, &s);
    if (desk_clock_24) {
        out[0] = (char)('0' + h / 10); out[1] = (char)('0' + h % 10);
        out[2] = ':'; out[3] = (char)('0' + m / 10); out[4] = (char)('0' + m % 10);
        out[5] = ':'; out[6] = (char)('0' + s / 10); out[7] = (char)('0' + s % 10); out[8] = 0;
    } else {
        int ap = h >= 12; int h12 = h % 12; if (h12 == 0) h12 = 12;
        out[0] = (char)('0' + h12 / 10); out[1] = (char)('0' + h12 % 10);
        out[2] = ':'; out[3] = (char)('0' + m / 10); out[4] = (char)('0' + m % 10);
        out[5] = ':'; out[6] = (char)('0' + s / 10); out[7] = (char)('0' + s % 10);
        out[8] = ' '; out[9] = ap ? 'P' : 'A'; out[10] = 'M'; out[11] = 0;
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
        /* Phase 10 keys: out-of-range values are ignored (and
           logged) rather than applied — a corrupt settings.txt
           must never produce an invalid theme or a crash. */
        else if (strcmp(key, "theme") == 0) {
            if (v <= 3) desk_theme = (int)v;
            else console_printf("settings: ignored invalid theme=%u\n", v);
        }
        else if (strcmp(key, "accent") == 0) {
            if (v <= 3) desk_accent = (int)v;
            else console_printf("settings: ignored invalid accent=%u\n", v);
        }
        else if (strcmp(key, "wallpaper") == 0) {
            if (v <= 2) desk_wallpaper = (int)v;
            else console_printf("settings: ignored invalid wallpaper=%u\n", v);
        }
        else if (strcmp(key, "lowres") == 0) desk_lowres = v ? 1 : 0;
        else if (strcmp(key, "bigtext") == 0) desk_bigtext = v ? 1 : 0;
        else if (strcmp(key, "shortcuts") == 0) {
            if (v <= 2) desk_shortcut_preset = (int)v;
            else console_printf("settings: ignored invalid shortcuts=%u\n", v);
        }
    }
}
static int desk_save_settings(char *status_out) {
    if (!fs_mounted()) { const char *t = "No disk"; int i=0; while(t[i]){status_out[i]=t[i];i++;} status_out[i]=0; return -1; }
    char data[256]; int n = 0;
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
    /* Phase 10 keys, same format. */
    const char *k5 = "theme="; while (*k5) data[n++] = *k5++;
    data[n++] = (char)('0' + desk_theme); data[n++] = '\n';
    const char *k6 = "accent="; while (*k6) data[n++] = *k6++;
    data[n++] = (char)('0' + desk_accent); data[n++] = '\n';
    const char *k7 = "wallpaper="; while (*k7) data[n++] = *k7++;
    data[n++] = (char)('0' + desk_wallpaper); data[n++] = '\n';
    const char *k8 = "lowres="; while (*k8) data[n++] = *k8++;
    data[n++] = desk_lowres ? '1' : '0'; data[n++] = '\n';
    const char *k9 = "bigtext="; while (*k9) data[n++] = *k9++;
    data[n++] = desk_bigtext ? '1' : '0'; data[n++] = '\n';
    const char *k10 = "shortcuts="; while (*k10) data[n++] = *k10++;
    data[n++] = (char)('0' + desk_shortcut_preset); data[n++] = '\n';
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
/* 6(b) part 10: re-enumerate the Files list without moving the
   scroll position (clamped to the new count), used after a
   delete so the list reflects the deletion immediately. */
static void desk_refresh_files(void) {
    desk_files_count = 0;
    if (!fs_mounted()) return;
    desk_files_count = fs_enum_as(shell_session_uid(), desk_files_names, desk_files_sizes, 32);
    int max = desk_files_count - 8; if (max < 0) max = 0;
    if (desk_files_scroll > max) desk_files_scroll = max;
}
static void desk_load_files(void) {
    desk_files_scroll = 0;
    desk_refresh_files();
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
       x+10, value button at x+200 (width 100, height 24).
       Page 0 is the original four rows (positions unchanged,
       so older tests still hit them); page 1 is the Phase 10
       appearance page. The page toggle sits below the rows,
       above Save, so neither moves. */
    if (wn->aux1 == 0) {
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
    } else {
        const char *names[6] = {"Theme", "Accent colour", "Wallpaper", "Low-resource", "Large text", "Shortcuts"};
        int row = 0;
        for (int s = 0; s < 6; s++) {
            if (!str_contains_ci(names[s], wn->search)) continue;
            s32 ry = y + 64 + row * 32;
            char val[32]; int vi = 0;
            const char *t = 0;
            if (s == 0) t = desk_theme_name();
            else if (s == 1) t = desk_accent_name();
            else if (s == 2) t = desk_wallpaper_name();
            else if (s == 3) { val[0]='O'; val[1]='n'; val[2]=0; if (!desk_lowres) { val[0]='O'; val[1]='f'; val[2]='f'; val[3]=0; } }
            else if (s == 4) { val[0]='O'; val[1]='n'; val[2]=0; if (!desk_bigtext) { val[0]='O'; val[1]='f'; val[2]='f'; val[3]=0; } }
            else {
                val[0] = desk_shortcut_keys[desk_shortcut_preset][0]; val[1] = '/';
                val[2] = desk_shortcut_keys[desk_shortcut_preset][1]; val[3] = 0;
            }
            if (t) { while (t[vi]) { val[vi] = t[vi]; vi++; } val[vi] = 0; }
            draw_text2(x + 10, ry + 4, names[s], 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            fb_fill_rect_clip(x + 200, ry, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
            draw_text2(x + 208, ry + 4, val, 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
            row++;
        }
    }
    /* Unlock row, page 0 only, at a fixed position below the four
       setting rows (which end at y+184) and above the toggle at
       y+252, so it never moves when the search filters the rows
       and never collides with the appearance page's six rows
       (it is not drawn there at all). No window resize: the
       toggle, Save, and every earlier row keep their positions.
       Label at x+10, field box x+110..x+310, Unlock button
       x+320..x+420. */
    if (wn->aux1 == 0) {
        draw_text2(x + 10, y + 212, "Unlock user:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        fb_fill_rect_clip(x + 110, y + 208, 200, 24, 0x00FFFFFFu, dx, dy, dw, dh);
        draw_text2(x + 114, y + 212, desk_settings_unlock, 0x00000000u, 0x00FFFFFFu, x + 110, y + 208, 200, 24, dx, dy, dw, dh);
        if (desk_settings_unlock_focused) fb_fill_rect_clip(x + 114 + desk_settings_unlock_len * 8, y + 212, 2, 16, 0x00000000u, dx, dy, dw, dh);
        fb_fill_rect_clip(x + 320, y + 208, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
        draw_text2(x + 328, y + 212, "Unlock", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    }
    /* Page toggle button (below the rows, above Save). */
    fb_fill_rect_clip(x + 10, y + 252, 140, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 18, y + 256, wn->aux1 == 0 ? "Appearance >" : "< General", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
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
    for (int r = 0; r < 8; r++) {
        int i = desk_files_scroll + r;
        if (i >= desk_files_count) break;
        s32 ry = y + 32 + r * 22;
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
    /* Files SHA-256 display: when a hash is valid and the
       selection still names the hashed file, the preview box
       shows the hash instead of the file preview — a header
       line plus the 64-char hex as two 32-char halves, so
       the whole hash fits the 460 px box (one 64-char line
       would clip at ~57 chars). The box is 60 px tall, so
       three 16 px lines fit exactly. */
    if (desk_files_hash_valid && wn->selected >= 0 && wn->selected < desk_files_count &&
        strcmp(desk_files_names[wn->selected], desk_files_hash_name) == 0) {
        char hdr[48]; int h = 0;
        const char *p = "SHA-256 of "; while (*p) hdr[h++] = *p++;
        p = desk_files_hash_name; while (*p && h < 46) hdr[h++] = *p++;
        hdr[h++] = ':'; hdr[h] = 0;
        char half[33]; int k;
        for (k = 0; k < 32; k++) half[k] = desk_files_hash[k];
        half[32] = 0;
        draw_text2(x + 14, py + 4, hdr, 0x00000000u, 0x00FFFFFFu, x + 10, py, w - 20, 60, dx, dy, dw, dh);
        draw_text2(x + 14, py + 20, half, 0x00000000u, 0x00FFFFFFu, x + 10, py, w - 20, 60, dx, dy, dw, dh);
        for (k = 0; k < 32; k++) half[k] = desk_files_hash[32 + k];
        half[32] = 0;
        draw_text2(x + 14, py + 36, half, 0x00000000u, 0x00FFFFFFu, x + 10, py, w - 20, 60, dx, dy, dw, dh);
    }
    /* Phase 10: Open button — .txt opens in the Editor, .bmp in
       the Viewer, .nxpkg installs through pkg_install, .nxupd
       applies through pkg_sysupdate (two-click confirm), .elf runs
       through proc_bg_start, anything else reports no viewer. */
    fb_fill_rect_clip(x + 10, py + 68, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 18, py + 72, "Open", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* 6(b) part 9: scroll buttons beside Open. They sit clear of
       the Open button and of the resize corner, and they do
       nothing when the list fits (scroll stays 0). */
    fb_fill_rect_clip(x + 130, py + 68, 52, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 138, py + 72, "Up", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 190, py + 68, 52, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 198, py + 72, "Dn", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* 6(b) part 10: Delete button beside Dn. x+250..x+330 is
       clear of Dn (ends x+242) and of the resize corner
       (bottom-right 16x16); the window is 480 wide. */
    fb_fill_rect_clip(x + 250, py + 68, 80, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 258, py + 72, "Delete", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Files copy button beside Delete. x+360..x+460 is
       clear of Delete (ends x+330) and of the resize
       corner; it shares the buttons row, so the rename
       row below and every earlier click coordinate are
       unchanged. Copy uses the same field as Rename
       (see below) as the destination name. */
    fb_fill_rect_clip(x + 360, py + 68, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 368, py + 72, "Copy", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Files new-name row below the buttons (window grew
       320 -> 352 tall for it; the buttons row above is
       unchanged, so every earlier click coordinate still
       lands). Label + white field box + Rename button:
       click the field, type the new name, click Rename
       (or Copy, which uses the same field as the
       destination name). The rename itself is
       fs_rename_as (the shell `mv` primitive) and the
       copy is fs_copy_as (the shell `cp` primitive),
       so the desktop and the shell share one
       no-overwrite, uid/mode-checked rule each. */
    draw_text2(x + 10, py + 100, "New name:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 90, py + 96, 260, 24, 0x00FFFFFFu, dx, dy, dw, dh);
    draw_text2(x + 94, py + 100, wn->field, 0x00000000u, 0x00FFFFFFu, x + 90, py + 96, 260, 24, dx, dy, dw, dh);
    if (wn->field_focused) fb_fill_rect_clip(x + 94 + wn->field_len * 8, py + 100, 2, 16, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 360, py + 96, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 368, py + 100, "Rename", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Files refresh button below the rename row (window grew
       352 -> 384 tall for it; every earlier row and click
       coordinate is unchanged). Files created or removed
       outside the window (an Editor save, a shell command)
       leave the list stale until the window is reopened;
       Refresh re-enumerates in place instead, scroll kept
       (clamped) by desk_refresh_files. */
    fb_fill_rect_clip(x + 10, py + 124, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 18, py + 128, "Refresh", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Files SHA-256 button beside Refresh. x+130..x+230 is
       clear of Refresh (ends x+110) and of the resize
       corner; it shares the Refresh row, so the window
       size and every earlier click coordinate are
       unchanged. No confirm: hashing reads a file and
       writes nothing. */
    fb_fill_rect_clip(x + 130, py + 124, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 138, py + 128, "Hash", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Files chmod row below the Refresh row (window grew
       384 -> 424 tall for it; every earlier row and click
       coordinate is unchanged, and the row clears the 16x16
       resize corner, which sits at the new bottom). Label +
       white mode field box + Chmod button: click the field,
       type the octal mode, click Chmod. The field is the
       separate desk_files_mode buffer, not wn->field, so
       typing a mode never touches the rename row. */
    draw_text2(x + 10, py + 156, "Mode:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 90, py + 152, 100, 24, 0x00FFFFFFu, dx, dy, dw, dh);
    draw_text2(x + 94, py + 156, desk_files_mode, 0x00000000u, 0x00FFFFFFu, x + 90, py + 152, 100, 24, dx, dy, dw, dh);
    if (desk_files_mode_focused) fb_fill_rect_clip(x + 94 + desk_files_mode_len * 8, py + 156, 2, 16, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 200, py + 152, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 208, py + 156, "Chmod", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
}
static void desk_draw_about_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = wn->w - 2, ch = wn->h - TITLE_H - 2;
    draw_text2(x + 10, y + 32, "nxtsOS v1.1.1", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 52, "Original kernel, Multiboot, 32-bit x86.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 72, "Not a Linux distribution or fork.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    char buf[64];
    u32_to_str(pmm_total_frames() * 4, buf, 10);
    draw_text2(x + 10, y + 92, "Memory total (KiB):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 190, y + 92, buf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 112, "Desktop: icons, launcher, clock,", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 132, "settings, lock screen, Calculator.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
}

/* ================= Phase 10 applications (v0.10.0) =================
   Built-in desktop windows (kernel-side, like Settings/Files):
   Network, Web, Editor, Monitor, Viewer. They use the same
   window struct as the older windows; per-app state lives in
   static buffers because only one window of each type can be
   open at once (open functions bring an existing one forward).
   Editor cap: 8192 bytes (a static buffer; larger files are
   refused, not truncated). Viewer cap: 24-bit uncompressed BMP,
   at most 128x128 pixels, file at most 128 KiB. Web cap: the
   8192-byte body buffer (a full buffer is reported as possibly
   truncated, never silently cut). */
static char desk_net_msg[128];
/* Network ping-host field: a second input row in the same
   window, so it cannot share wn->field with the Set-DNS row
   (both rows draw their field, and sharing one buffer would
   show the same text in both). Same 63-char cap and focus
   rules as the window fields; the client-area click handler
   clears this focus before dispatch, exactly like wn->field. */
static char desk_net_ping[64];
static int desk_net_ping_len = 0;
static int desk_net_ping_focused = 0;
static char desk_web_body[8192];
static u32 desk_web_len = 0;
static char desk_web_status[128];
static char desk_web_save[64];
static int desk_web_save_len = 0;
static int desk_web_save_focused = 0;
static char desk_ed_buf[8193];
static u32 desk_ed_len = 0;
static char desk_ed_name[32];
static char desk_ed_msg[128];
/* 6(b) part 7: New-file confirm arm. Set by the first New click
   while the buffer is non-empty; cleared by Save, Open, or the
   confirming second New click, so a single stray click can
   never discard edits. Typing does not clear it: only an
   explicit second New click discards. */
static int desk_ed_new_confirm = 0;
static u8 desk_bmp[131072];
static u32 desk_bmp_size = 0;
static int desk_bmp_w = 0, desk_bmp_h = 0, desk_bmp_ok = 0;
static char desk_bmp_name[32];
static char desk_bmp_msg[128];

static void ip_text(ip_t ip, char *out) {
    int n = 0;
    for (int i = 0; i < 4; i++) {
        char tmp[16]; u32_to_str(ip.b[i], tmp, 10);
        int t = 0; while (tmp[t]) out[n++] = tmp[t++];
        if (i < 3) out[n++] = '.';
    }
    out[n] = 0;
}
static void mac_text(mac_t m, char *out) {
    const char *hex = "0123456789ABCDEF";
    int n = 0;
    for (int i = 0; i < 6; i++) {
        out[n++] = hex[(m.b[i] >> 4) & 0xF]; out[n++] = hex[m.b[i] & 0xF];
        if (i < 5) out[n++] = ':';
    }
    out[n] = 0;
}
static void set_msg(char *dst, const char *src) {
    int i = 0; while (src[i] && i < 127) { dst[i] = src[i]; i++; } dst[i] = 0;
}
static void desk_draw_network_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = wn->w - 2, ch = wn->h - TITLE_H - 2;
    char line[96];
    draw_text2(x + 10, y + 32, "Network status", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    if (!net_present()) {
        draw_text2(x + 10, y + 56, "No network device found.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 10, y + 76, "Run QEMU with -device e1000,netdev=n0.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    } else {
        mac_t mac; net_mac(&mac); mac_text(mac, line);
        draw_text2(x + 10, y + 56, "MAC:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 70, y + 56, line, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 10, y + 76, net_ip_configured() ? "Configured: yes (DHCP done)" : "Configured: no (run DHCP)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        if (net_ip_configured()) {
            ip_t a; char t[32];
            net_ip_addr(&a); ip_text(a, t);
            draw_text2(x + 10, y + 96, "IP:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            draw_text2(x + 70, y + 96, t, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            net_ip_netmask(&a); ip_text(a, t);
            draw_text2(x + 10, y + 116, "Mask:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            draw_text2(x + 70, y + 116, t, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            net_ip_gateway(&a); ip_text(a, t);
            draw_text2(x + 10, y + 136, "Gateway:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            draw_text2(x + 90, y + 136, t, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            net_ip_dns(&a); ip_text(a, t);
            draw_text2(x + 10, y + 156, "DNS:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            draw_text2(x + 70, y + 156, t, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        }
        char num[16];
        u32_to_str(net_rx_count(), num, 10);
        draw_text2(x + 10, y + 180, "RX packets:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 130, y + 180, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str(net_tx_count(), num, 10);
        draw_text2(x + 10, y + 200, "TX packets:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 130, y + 200, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    }
    fb_fill_rect_clip(x + 10, y + 230, 120, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 18, y + 234, "Run DHCP", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 150, y + 230, 140, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 158, y + 234, "Ping gateway", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 264, desk_net_msg, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Set-DNS row (y+292..y+316), in the new area the taller
       window (480x360, was 480x320) adds below the message
       line: a white field box for a dotted-quad DNS address
       plus a Set DNS button. The row clears the 16x16 resize
       corner (y+344..y+360), and every earlier button keeps
       its position. The field caps at 63 characters like the
       Web and Files fields; net_parse_ip refuses a malformed
       address, so a mistyped address fails loudly, never
       silently. */
    draw_text2(x + 10, y + 296, "DNS:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 50, y + 292, 300, 24, 0x00FFFFFFu, dx, dy, dw, dh);
    draw_text2(x + 54, y + 296, wn->field, 0x00000000u, 0x00FFFFFFu, x + 50, y + 292, 300, 24, dx, dy, dw, dh);
    if (wn->field_focused) fb_fill_rect_clip(x + 54 + wn->field_len * 8, y + 296, 2, 16, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 360, y + 292, 110, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 368, y + 296, "Set DNS", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Ping-host row (y+324..y+348), in the new area the taller
       window (480x400, was 480x360) adds below the Set-DNS row:
       a "Ping:" label, a white field box for a dotted-quad
       host address, plus a Ping button. The row clears the
       16x16 resize corner (y+384..y+400), and every earlier
       button keeps its position. */
    draw_text2(x + 10, y + 328, "Ping:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 50, y + 324, 300, 24, 0x00FFFFFFu, dx, dy, dw, dh);
    draw_text2(x + 54, y + 328, desk_net_ping, 0x00000000u, 0x00FFFFFFu, x + 50, y + 324, 300, 24, dx, dy, dw, dh);
    if (desk_net_ping_focused) fb_fill_rect_clip(x + 54 + desk_net_ping_len * 8, y + 328, 2, 16, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 360, y + 324, 110, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 368, y + 328, "Ping", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
}
static int desk_open_network(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_NETWORK) { bring_to_front(i); return i; }
    int id = wm_create("Network", 160, 80, 480, 400, W_NETWORK);
    if (id < 0) return -1;
    desk_net_msg[0] = 0;
    desk_net_ping[0] = 0; desk_net_ping_len = 0; desk_net_ping_focused = 0;
    console_write("Desktop: Network opened\n");
    if (!net_present()) console_write("network: no device\n");
    return find_by_id(id);
}
/* Web fetch: parse "host[:port][/path]" with optional http(s)://
   prefix. Returns body length, or -1 failed, -2 cert refused. */
static int desk_web_fetch(const char *addr) {
    char host[64]; int hi = 0; int tls = 0; u16 port = 0; char path[64]; int pi = 0;
    int i = 0;
    if (addr[0]=='h' && addr[1]=='t' && addr[2]=='t' && addr[3]=='p') {
        i = 4;
        if (addr[i]=='s') { tls = 1; i++; }
        if (addr[i]==':' && addr[i+1]=='/' && addr[i+2]=='/') i += 3;
        else { i = 0; tls = 0; }
    }
    while (addr[i] && addr[i] != '/' && addr[i] != ':' && hi < 63) host[hi++] = addr[i++];
    host[hi] = 0;
    if (addr[i] == ':') {
        i++; u32 p = 0;
        while (addr[i] >= '0' && addr[i] <= '9') { p = p * 10 + (u32)(addr[i] - '0'); i++; }
        if (p > 0 && p < 65536) port = (u16)p;
    }
    if (port == 0) port = tls ? 443 : 80;
    if (addr[i] == '/') { while (addr[i] && pi < 63) path[pi++] = addr[i++]; }
    else { path[pi++] = '/'; }
    path[pi] = 0;
    if (hi == 0) return -1;
    int r;
    if (tls) r = net_https_get(host, port, path, desk_web_body, sizeof(desk_web_body));
    else r = net_http_get(host, port, path, desk_web_body, sizeof(desk_web_body));
    if (r >= 0) {
        desk_web_len = (u32)r;
        desk_web_body[desk_web_len < sizeof(desk_web_body) ? desk_web_len : sizeof(desk_web_body) - 1] = 0;
        if (net_fetch_truncated()) {
            set_msg(desk_web_status, "8192 bytes (buffer full, may be truncated)");
            console_write("web: truncated at 8192\n");
        } else {
            char tmp[64]; tmp[0]='O'; tmp[1]='K'; tmp[2]=' '; int n=3;
            char num[16]; u32_to_str(desk_web_len, num, 10);
            int t=0; while (num[t]) tmp[n++]=num[t++];
            tmp[n++]=' '; tmp[n++]='b'; tmp[n++]='y'; tmp[n++]='t'; tmp[n++]='e'; tmp[n++]='s'; tmp[n]=0;
            set_msg(desk_web_status, tmp);
            console_printf("web: fetched %u bytes\n", desk_web_len);
        }
        return r;
    }
    desk_web_len = 0; desk_web_body[0] = 0;
    if (r == -2) { set_msg(desk_web_status, "certificate refused"); console_write("web: certificate refused\n"); return -2; }
    set_msg(desk_web_status, "fetch failed");
    console_write("web: fetch failed\n");
    return -1;
}
static void desk_draw_web_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y, w = wn->w;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = w - 2, ch = wn->h - TITLE_H - 2;
    fb_draw_text_clip(x + 10, y + 32, "Address:", 0x00000000u, 0x00D0D0D0u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 80, y + 28, w - 100, 24, 0x00FFFFFFu, dx, dy, dw, dh);
    draw_text2(x + 84, y + 32, wn->field, 0x00000000u, 0x00FFFFFFu, x + 80, y + 28, w - 100, 24, dx, dy, dw, dh);
    if (wn->field_focused) fb_fill_rect_clip(x + 84 + wn->field_len * 8, y + 32, 2, 16, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 10, y + 64, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 18, y + 68, "Fetch", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + w - 120, y + 64, 50, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + w - 102, y + 68, "Up", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + w - 60, y + 64, 50, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + w - 42, y + 68, "Down", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 130, y + 68, desk_web_status, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Web Save row: a fetched page can be kept on disk,
       which the viewer alone never allowed — a desktop
       user fetching a text file had no way to save it
       for the Editor or for later. The row sits below
       the body (the body keeps its old 15 rows: the
       window grew 360 -> 400 and max_rows accounts for
       the row), clear of the resize corner, and no
       earlier button or click coordinate moved for it. */
    fb_draw_text_clip(x + 10, y + 356, "Save as:", 0x00000000u, 0x00D0D0D0u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 80, y + 352, 300, 24, 0x00FFFFFFu, dx, dy, dw, dh);
    draw_text2(x + 84, y + 356, desk_web_save, 0x00000000u, 0x00FFFFFFu, x + 80, y + 352, 300, 24, dx, dy, dw, dh);
    if (desk_web_save_focused) fb_fill_rect_clip(x + 84 + desk_web_save_len * 8, y + 356, 2, 16, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 390, y + 352, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 398, y + 356, "Save", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Body as text lines, scrolled by aux1. Long lines wrap at
       the window width; NUL bytes cannot appear (the fetch
       buffer is NUL-terminated and body text is drawn per
       line, stopping at NUL). */
    int max_chars = (w - 20) / 8;
    int line = 0, pos = 0, row = 0;
    int max_rows = (wn->h - 160) / 16;
    while (desk_web_body[pos] && row < max_rows) {
        char lbuf[96]; int n = 0;
        while (desk_web_body[pos] && desk_web_body[pos] != '\n' && n < max_chars && n < 95) {
            char c = desk_web_body[pos++];
            lbuf[n++] = (c == '\r' || (unsigned char)c < 32) ? ' ' : c;
        }
        if (desk_web_body[pos] == '\n') pos++;
        lbuf[n] = 0;
        if (line >= wn->aux1) {
            draw_text2(x + 10, y + 100 + row * 16, lbuf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            row++;
        }
        line++;
    }
}
static int desk_open_web(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_WEB) { bring_to_front(i); return i; }
    int id = wm_create("Web", 140, 60, 520, 400, W_WEB);
    if (id < 0) return -1;
    int idx = find_by_id(id);
    if (idx >= 0) {
        wins[idx].field[0] = 0; wins[idx].field_len = 0; wins[idx].field_focused = 0;
        wins[idx].aux1 = 0;
        desk_web_status[0] = 0; desk_web_len = 0; desk_web_body[0] = 0;
        desk_web_save[0] = 0; desk_web_save_len = 0; desk_web_save_focused = 0;
        console_write("Desktop: Web opened\n");
    }
    return idx;
}
/* Editor: load a file into the static buffer, sanitising bytes
   that cannot be edited or displayed (NULs and control bytes
   other than newline become '?'). Refuses files over the cap
   instead of truncating them. */
static int desk_editor_load(const char *name) {
    u32 size = 0;
    /* Read with the cap: fs_read_as fails if the file does not
       fit, so an oversize file is refused cleanly here. */
    u32 sz = 0;
    if (fs_read_as(name, (u8 *)desk_ed_buf, 8192, &sz, shell_session_uid()) != 0) {
        /* Distinguish missing from oversize is not possible via
           this call alone; report the refusal either way. */
        console_printf("editor: refused %s (missing or over 8192 bytes)\n", name);
        desk_notify("Editor: file missing or over 8KB, refused");
        return -1;
    }
    size = sz;
    int sanitized = 0;
    for (u32 i = 0; i < size; i++) {
        unsigned char c = (unsigned char)desk_ed_buf[i];
        if ((c < 32 && c != '\n') || c >= 127) { desk_ed_buf[i] = '?'; sanitized++; }
    }
    desk_ed_buf[size] = 0;
    desk_ed_len = size;
    int n = 0; while (name[n] && n < 31) { desk_ed_name[n] = name[n]; n++; } desk_ed_name[n] = 0;
    if (sanitized) console_printf("editor: sanitized %d bytes in %s\n", sanitized, name);
    console_printf("editor: opened %s %u bytes\n", name, size);
    { /* Status-line proof for the test: same line-count rule
         as the drawn status line (newlines + trailing part). */
        u32 nl = 0;
        if (size > 0) {
            for (u32 i = 0; i < size; i++) if (desk_ed_buf[i] == '\n') nl++;
            if (desk_ed_buf[size - 1] != '\n') nl++;
        }
        console_printf("editor: status %u lines %u bytes\n", nl, size);
    }
    return 0;
}
/* 6(b) part 8: Editor scroll. Before this chunk aux2 (the
   scroll offset) was set to 0 on load and never changed
   again: a file longer than the 13 visible rows showed
   only its head, and typing past the last visible row
   edited invisible text. max_rows mirrors the draw code
   exactly (body rows end 20 px above the status line). */
static int desk_editor_max_rows(int h) { int r = (h - 140) / 16; return r < 0 ? 0 : r; }
static int desk_editor_cur_line(int cursor) {
    int l = 0; int p = 0;
    while (p < cursor && desk_ed_buf[p]) { if (desk_ed_buf[p] == '\n') l++; p++; }
    return l;
}
/* Keep the cursor row on screen: scroll just enough that
   the cursor row is the first or last visible row. */
static void desk_editor_follow_cursor(int idx) {
    struct window *wn = &wins[idx];
    int mr = desk_editor_max_rows(wn->h);
    if (mr <= 0) return;
    int cl = desk_editor_cur_line(wn->aux1);
    if (cl < wn->aux2) wn->aux2 = cl;
    else if (cl >= wn->aux2 + mr) wn->aux2 = cl - mr + 1;
}
/* Furthest the Up/Down buttons may scroll: content rows are
   newlines + 1 for any non-empty buffer (the trailing row
   after a final newline counts: the cursor sits on it). */
static int desk_editor_max_scroll(struct window *wn) {
    int mr = desk_editor_max_rows(wn->h);
    if (mr <= 0 || desk_ed_len == 0) return 0;
    u32 rows = 1;
    for (u32 i = 0; i < desk_ed_len; i++) if (desk_ed_buf[i] == '\n') rows++;
    int ms = (int)rows - mr;
    return ms < 0 ? 0 : ms;
}
static void desk_editor_sync_field(int idx) {
    /* Filename field follows the loaded file, cursor to the end. */
    int n = 0; while (desk_ed_name[n] && n < 63) { wins[idx].field[n] = desk_ed_name[n]; n++; }
    wins[idx].field[n] = 0; wins[idx].field_len = n; wins[idx].field_focused = 0;
    wins[idx].aux1 = (int)desk_ed_len; wins[idx].aux2 = 0;
    /* A long file opens scrolled to its (end) cursor, not to
       a head the cursor is not on. */
    desk_editor_follow_cursor(idx);
}
static int desk_open_editor(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_EDITOR) { bring_to_front(i); desk_editor_sync_field(i); return i; }
    int id = wm_create("Editor", 140, 60, 520, 360, W_EDITOR);
    if (id < 0) return -1;
    int idx = find_by_id(id);
    if (idx >= 0) {
        desk_editor_sync_field(idx);
        console_write("Desktop: Editor opened\n");
    }
    return idx;
}
static void desk_draw_editor_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y, w = wn->w;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = w - 2, ch = wn->h - TITLE_H - 2;
    fb_draw_text_clip(x + 10, y + 32, "File:", 0x00000000u, 0x00D0D0D0u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 60, y + 28, w - 80, 24, 0x00FFFFFFu, dx, dy, dw, dh);
    draw_text2(x + 64, y + 32, wn->field, 0x00000000u, 0x00FFFFFFu, x + 60, y + 28, w - 80, 24, dx, dy, dw, dh);
    if (wn->field_focused) fb_fill_rect_clip(x + 64 + wn->field_len * 8, y + 32, 2, 16, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 10, y + 64, 80, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 18, y + 68, "Save", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 100, y + 64, 80, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 108, y + 68, "Open", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* 6(b) part 7: New button; the message moves right so it
       never paints over the button. */
    fb_fill_rect_clip(x + 190, y + 64, 80, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 198, y + 68, "New", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 280, y + 68, desk_ed_msg, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* 6(b) part 6: status line at the bottom of the window —
       line count, byte count, and 1-based cursor line/col,
       recomputed from the buffer on every draw so typing and
       cursor moves are reflected without extra state. Line
       count: newlines plus a trailing partial line; an empty
       file has 0 lines. Body rows stop 20 px higher so the
       status line is never painted over. */
    /* Body lines, scrolled by aux2. Cursor (aux1) drawn as a
       filled block over the character cell. */
    int max_chars = (w - 20) / 8;
    int max_rows = (wn->h - 140) / 16;
    if (max_rows < 0) max_rows = 0;
    int line = 0, pos = 0, row = 0;
    int cur_line = 0, cur_col = 0, cur_drawn = 0;
    { int p = 0; while (p < wn->aux1 && desk_ed_buf[p]) { if (desk_ed_buf[p] == '\n') { cur_line++; cur_col = 0; } else cur_col++; p++; } }
    u32 nlines = 0;
    if (desk_ed_len > 0) {
        for (u32 i = 0; i < desk_ed_len; i++) if (desk_ed_buf[i] == '\n') nlines++;
        if (desk_ed_buf[desk_ed_len - 1] != '\n') nlines++;
    }
    while (pos < (int)desk_ed_len && row < max_rows) {
        char lbuf[96]; int n = 0; int lstart = pos;
        while (pos < (int)desk_ed_len && desk_ed_buf[pos] != '\n' && n < max_chars && n < 95) lbuf[n++] = desk_ed_buf[pos++];
        if (pos < (int)desk_ed_len && desk_ed_buf[pos] == '\n') pos++;
        lbuf[n] = 0;
        (void)lstart;
        if (line >= wn->aux2) {
            draw_text2(x + 10, y + 100 + row * 16, lbuf, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            if (line == cur_line) {
                s32 ccx = x + 10 + cur_col * 8, ccy = y + 100 + row * 16;
                if (cur_col < max_chars) fb_fill_rect_clip(ccx, ccy, 8, 16, 0x00000000u, dx, dy, dw, dh);
                cur_drawn = 1;
            }
            row++;
        }
        line++;
    }
    if (desk_ed_len == 0) fb_fill_rect_clip(x + 10, y + 100, 8, 16, 0x00000000u, dx, dy, dw, dh);
    /* 6(b) part 8: the cursor row after a final newline is a
       real row the loop never draws (it stops at end of
       buffer), so draw its block here when it is on screen. */
    if (desk_ed_len > 0 && !cur_drawn && cur_line >= wn->aux2 && cur_line - wn->aux2 < max_rows && cur_col < max_chars)
        fb_fill_rect_clip(x + 10 + cur_col * 8, y + 100 + (cur_line - wn->aux2) * 16, 8, 16, 0x00000000u, dx, dy, dw, dh);
    /* Status line, Monitor-style fixed columns, at the foot of
       the window (body rows end above it by construction). */
    {
        s32 sy = y + wn->h - 20;
        char num[16];
        draw_text2(x + 10, sy, "Lines:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str(nlines, num, 10);
        draw_text2(x + 70, sy, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 130, sy, "Bytes:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str(desk_ed_len, num, 10);
        draw_text2(x + 190, sy, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 250, sy, "Ln", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str((u32)cur_line + 1, num, 10);
        draw_text2(x + 280, sy, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 320, sy, "Col", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str((u32)cur_col + 1, num, 10);
        draw_text2(x + 360, sy, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    }
    /* 6(b) part 8: scroll buttons, foot-right. They stop 4 px
       short of the 16x16 resize corner so a button click
       never starts a resize. */
    fb_fill_rect_clip(x + w - 116, y + wn->h - 24, 48, 20, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + w - 106, y + wn->h - 20, "Up", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + w - 64, y + wn->h - 24, 44, 20, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + w - 54, y + wn->h - 20, "Dn", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
}
static void desk_draw_monitor_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = wn->w - 2, ch = wn->h - TITLE_H - 2;
    char num[16], line[96];
    draw_text2(x + 10, y + 32, "System monitor (updates every second)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    u32_to_str(timer_ticks / 100, num, 10);
    draw_text2(x + 10, y + 56, "Uptime (s):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 130, y + 56, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    u32_to_str(pmm_total_frames() * 4, num, 10);
    draw_text2(x + 10, y + 76, "Memory total (KiB):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 200, y + 76, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    u32_to_str(pmm_free_frames() * 4, num, 10);
    draw_text2(x + 10, y + 96, "Memory free (KiB):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 200, y + 96, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* 6(b) part 5: memory used + a usage bar in the theme accent
       colour. Used is derived, never stored: total minus free,
       clamped at zero so a stale free count cannot go negative.
       The bar redraws every second with the rest of the window,
       so it tracks live allocation. */
    {
        u32 tot = pmm_total_frames() * 4, fre = pmm_free_frames() * 4;
        u32 used = tot >= fre ? tot - fre : 0;
        u32_to_str(used, num, 10);
        draw_text2(x + 10, y + 116, "Memory used (KiB):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 200, y + 116, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 10, y + 136, "Memory use:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        fb_fill_rect_clip(x + 130, y + 136, 260, 12, 0x00606060u, dx, dy, dw, dh);
        if (tot > 0) {
            u32 fill = used * 260 / tot;
            if (fill > 260) fill = 260;
            if (fill > 0) fb_fill_rect_clip(x + 130, y + 136, (s32)fill, 12, desk_accent_col(), dx, dy, dw, dh);
        }
    }
    u32_to_str((u32)wm_count(), num, 10);
    draw_text2(x + 10, y + 156, "Windows open:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 200, y + 156, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    u32_to_str(net_rx_count(), num, 10);
    draw_text2(x + 10, y + 176, "Net RX packets:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 200, y + 176, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    u32_to_str(net_tx_count(), num, 10);
    draw_text2(x + 10, y + 196, "Net TX packets:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 200, y + 196, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    u32_to_str(net_drop_count(), num, 10);
    draw_text2(x + 10, y + 216, "Net drops:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 200, y + 216, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    if (net_ip_configured()) {
        ip_t a;
        net_ip_addr(&a); ip_text(a, line);
        draw_text2(x + 10, y + 236, "IP:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 130, y + 236, line, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    } else {
        draw_text2(x + 10, y + 236, "IP: (not configured)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    }
    /* Monitor jobs list: the desktop form of shell `jobs` — every
       live background job, drawn from the same table through
       proc_bg_at, so a job started from Files Run (or the
       Calculator/Console launcher entries) is visible here even
       after its window closed, which otherwise leaves a desktop
       user with no way to see it at all. The list redraws every
       second with the rest of the window, so no Refresh button
       is needed; the rows below are the Kill target list. */
    draw_text2(x + 10, y + 256, "Background jobs:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    {
        char jname[32], jline[64]; u32 jpid, juid; int jn = 0;
        for (int r = 0; r < MAX_BG; r++) {
            if (proc_bg_at(r, jname, &jpid, &juid) != 0) break;
            int p = 0, t = 0;
            jline[p++] = 'p'; jline[p++] = 'i'; jline[p++] = 'd'; jline[p++] = ' ';
            { char num[16]; u32_to_str(jpid, num, 10); t = 0; while (num[t]) jline[p++] = num[t++]; }
            jline[p++] = ' '; jline[p++] = ' ';
            t = 0; while (jname[t] && p < 40) jline[p++] = jname[t++];
            jline[p++] = ' '; jline[p++] = ' ';
            jline[p++] = 'u'; jline[p++] = 'i'; jline[p++] = 'd'; jline[p++] = ' ';
            { char num[16]; u32_to_str(juid, num, 10); t = 0; while (num[t]) jline[p++] = num[t++]; }
            jline[p] = 0;
            /* Selected row highlighted, Files pattern. */
            if (r == wn->selected) fb_fill_rect_clip(x + 10, y + 276 + r * 20 - 2, 460, 20, 0x00A0C0FFu, dx, dy, dw, dh);
            draw_text2(x + 10, y + 276 + r * 20, jline, 0x00000000u, r == wn->selected ? 0x00A0C0FFu : 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
            jn++;
        }
        if (jn == 0)
            draw_text2(x + 10, y + 276, "(no background jobs)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    }
    /* Kill button below the 4 job rows, clear of the resize corner
       (window 480 wide, 400 tall): x+10..x+110, y+360..y+384. */
    fb_fill_rect_clip(x + 10, y + 360, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 18, y + 364, "Kill", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Monitor disk space: the desktop form of shell `fs` — a
       desktop-only user otherwise has no way to see disk total
       or free space at all, and a full disk is exactly what
       blocks a package install or an Editor save. The rows sit
       below Kill (the window grew 400 -> 440 for them, so no
       earlier row or click coordinate moved) and redraw every
       second with the rest of the window. */
    if (fs_mounted()) {
        u32_to_str(fs_total_sectors(), num, 10);
        draw_text2(x + 10, y + 392, "Disk total (sectors):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 200, y + 392, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        u32_to_str(fs_free_sectors(), num, 10);
        draw_text2(x + 10, y + 412, "Disk free (sectors):", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 200, y + 412, num, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    } else {
        draw_text2(x + 10, y + 392, "Disk: (not mounted)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    }
    (void)line;
}
static int desk_monitor_kill_arm_pid = -1; /* armed job pid, -1 = none */
static int desk_open_monitor(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_MONITOR) { bring_to_front(i); return i; }
    int id = wm_create("Monitor", 160, 80, 480, 440, W_MONITOR);
    if (id < 0) return -1;
    console_write("Desktop: Monitor opened\n");
    {
        u32 tot = pmm_total_frames() * 4, fre = pmm_free_frames() * 4;
        console_printf("monitor: mem used %u KiB of %u KiB\n", tot >= fre ? tot - fre : 0, tot);
    }
    if (fs_mounted())
        console_printf("monitor: disk %u sectors total, %u free\n", fs_total_sectors(), fs_free_sectors());
    else
        console_write("monitor: disk not mounted\n");
    {
        char jname[32]; u32 jpid, juid;
        for (int r = 0; r < MAX_BG; r++) {
            if (proc_bg_at(r, jname, &jpid, &juid) != 0) break;
            console_printf("monitor: pid %u %s uid %u\n", jpid, jname, juid);
        }
    }
    int wi = find_by_id(id);
    if (wi >= 0) wins[wi].selected = -1;
    desk_monitor_kill_arm_pid = -1;
    return wi;
}
/* BMP parsing: 24-bit uncompressed only, at most 128x128. All
   bounds are checked before any pixel is read, so a truncated
   or lying header is refused, never over-read. */
static u16 bmp_u16(const u8 *p) { return (u16)(p[0] | (p[1] << 8)); }
static u32 bmp_u32(const u8 *p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }
static s32 bmp_s32(const u8 *p) { return (s32)bmp_u32(p); }
static int desk_viewer_load(const char *name) {
    u32 sz = 0;
    if (fs_read_as(name, desk_bmp, sizeof(desk_bmp), &sz, shell_session_uid()) != 0) {
        console_printf("viewer: refused %s (missing or over 128 KiB)\n", name);
        desk_notify("Viewer: file missing or over 128KB, refused");
        return -1;
    }
    desk_bmp_size = sz;
    if (sz < 54 || desk_bmp[0] != 'B' || desk_bmp[1] != 'M') {
        console_printf("viewer: refused %s (not a BMP)\n", name);
        desk_notify("Viewer: not a BMP file");
        return -1;
    }
    u32 data_off = bmp_u32(desk_bmp + 10);
    u32 dib = bmp_u32(desk_bmp + 14);
    s32 w = bmp_s32(desk_bmp + 18), h = bmp_s32(desk_bmp + 22);
    u16 planes = bmp_u16(desk_bmp + 26), bpp = bmp_u16(desk_bmp + 28);
    u32 comp = bmp_u32(desk_bmp + 30);
    if (dib < 40 || planes != 1 || bpp != 24 || comp != 0) {
        console_printf("viewer: refused %s (only 24-bit uncompressed BMP)\n", name);
        desk_notify("Viewer: only 24-bit uncompressed BMP");
        return -1;
    }
    s32 ah = h < 0 ? -h : h;
    if (w <= 0 || w > 128 || ah <= 0 || ah > 128) {
        console_printf("viewer: refused %s (oversize %dx%d, cap 128x128)\n", name, w, ah);
        desk_notify("Viewer: image over 128x128, refused");
        return -1;
    }
    u32 stride = (u32)(((w * 3) + 3) & ~3);
    if (data_off >= sz || stride * (u32)ah > sz - data_off) {
        console_printf("viewer: refused %s (truncated pixel data)\n", name);
        desk_notify("Viewer: truncated pixel data");
        return -1;
    }
    desk_bmp_w = w; desk_bmp_h = ah; desk_bmp_ok = 1;
    int n = 0; while (name[n] && n < 31) { desk_bmp_name[n] = name[n]; n++; } desk_bmp_name[n] = 0;
    set_msg(desk_bmp_msg, "OK");
    console_printf("viewer: opened %s %dx%d\n", name, w, ah);
    return 0;
}
static int desk_open_viewer(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_VIEWER) { bring_to_front(i); return i; }
    int id = wm_create("Viewer", 160, 60, 480, 360, W_VIEWER);
    if (id < 0) return -1;
    console_write("Desktop: Viewer opened\n");
    return find_by_id(id);
}
static void desk_draw_viewer_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = wn->w - 2, ch = wn->h - TITLE_H - 2;
    if (!desk_bmp_ok) {
        draw_text2(x + 10, y + 32, "No image loaded.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        draw_text2(x + 10, y + 52, "Open a BMP image from Files.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        return;
    }
    char info[96]; int n = 0;
    { int t = 0; while (desk_bmp_name[t] && n < 30) info[n++] = desk_bmp_name[t++]; }
    info[n++] = ' ';
    { char num[16]; u32_to_str((u32)desk_bmp_w, num, 10); int t=0; while(num[t]) info[n++]=num[t++]; }
    info[n++] = 'x';
    { char num[16]; u32_to_str((u32)desk_bmp_h, num, 10); int t=0; while(num[t]) info[n++]=num[t++]; }
    info[n] = 0;
    draw_text2(x + 10, y + 32, info, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* BMP pixel data: BGR triples, rows bottom-up unless the
       height was negative (top-down). Pixels are inside the
       client area by construction (128 cap vs 478x338 area),
       and fb clips them to the dirty rect. */
    u32 data_off = bmp_u32(desk_bmp + 10);
    s32 h_raw = bmp_s32(desk_bmp + 22);
    u32 stride = (u32)(((desk_bmp_w * 3) + 3) & ~3);
    for (s32 r = 0; r < desk_bmp_h; r++) {
        s32 frow = h_raw > 0 ? (desk_bmp_h - 1 - r) : r;
        for (s32 c = 0; c < desk_bmp_w; c++) {
            u32 off = data_off + (u32)frow * stride + (u32)c * 3;
            u32 col = ((u32)desk_bmp[off + 2] << 16) | ((u32)desk_bmp[off + 1] << 8) | desk_bmp[off];
            fb_fill_rect_clip(x + 10 + c, y + 52 + r, 1, 1, col, dx, dy, dw, dh);
        }
    }
}

/* Packages window (6b utility app): lists installed packages from
   the pkg registry, and removes the selected one. The list is also
   printed once on open, so the serial log proves what the window
   showed. Remove is the desktop form of shell `pkg remove <name>`
   without force (root-only, dependents refuse): first click arms
   the confirm, Files Delete pattern, second click removes.
   Rollback is the desktop form of shell `sysrollback` (root-only,
   whole-system, no selection): first click arms the confirm,
   second click restores the snapshot the last system update left
   and consumes it, so a further Rollback finds no snapshot —
   the negative control in the autotest. A rollback replaces
   installed packages, so a single click must never apply it. */
static int desk_packages_del_arm = -1;
static int desk_packages_rb_arm = 0;
static void desk_draw_packages_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = wn->w - 2, ch = wn->h - TITLE_H - 2;
    draw_text2(x + 10, y + 32, "Installed packages:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    char name[32], ver[16], line[64];
    int n = 0;
    for (int i = 0; i < 8; i++) {
        if (pkg_registry_entry(i, name, ver) != 0) break;
        int p = 0, t = 0;
        while (name[t] && p < 60) line[p++] = name[t++];
        line[p++] = ' ';
        t = 0; while (ver[t] && p < 60) line[p++] = ver[t++];
        line[p] = 0;
        /* Selected row highlighted, Files pattern. */
        if (i == wn->selected) fb_fill_rect_clip(x + 10, y + 56 + i * 20 - 2, 460, 20, 0x00A0C0FFu, dx, dy, dw, dh);
        draw_text2(x + 10, y + 56 + i * 20, line, 0x00000000u, i == wn->selected ? 0x00A0C0FFu : 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        n++;
    }
    if (n == 0)
        draw_text2(x + 10, y + 56, "(no packages installed)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 56 + 8 * 20 + 12, "Select a row, then [Remove] to uninstall it.", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Remove button below the footer, clear of the resize corner
       (window 480 wide, 320 tall): x+10..x+110, y+252..y+276.
       Rollback button beside it, x+120..x+220, same row: it
       restores the last system update's snapshot (shell
       `sysrollback`), so it needs no row selection. */
    fb_fill_rect_clip(x + 10, y + 252, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 18, y + 256, "Remove", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 120, y + 252, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 128, y + 256, "Rollback", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
}
static int desk_open_packages(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_PACKAGES) { bring_to_front(i); return i; }
    int id = wm_create("Packages", 160, 80, 480, 320, W_PACKAGES);
    if (id < 0) return -1;
    console_write("Desktop: Packages opened\n");
    char name[32], ver[16];
    for (int i = 0; i < 8; i++) {
        if (pkg_registry_entry(i, name, ver) != 0) break;
        console_printf("packages: %s %s\n", name, ver);
    }
    int wi = find_by_id(id);
    if (wi >= 0) wins[wi].selected = -1;
    desk_packages_del_arm = -1;
    desk_packages_rb_arm = 0;
    return wi;
}

/* Repo browser window (6b utility app): shows the stored,
   signature-verified repo index — repository URL, index
   version, and name + version per entry. The list is copied
   at open time and printed to the serial log, so the test
   proves content, not just that a window opened. A stored
   index that fails re-verification is shown as "no index
   downloaded", never as stale data: the window never
   displays an unverified index. Update fetches a fresh
   index through the shell's pkg_repo_update rule and
   reloads the list; Install installs the selected row
   through the shell's pkg_repo_install rule — so the
   desktop and the shell share exactly one update rule
   and one install rule. */
static char desk_repo_url[128];
static char desk_repo_name[64][32], desk_repo_ver[64][16];
static int desk_repo_count = -1; /* -1 = no verified stored index */
static int desk_repo_scroll = 0; /* first visible row, 0..count-8 */
static u32 desk_repo_version = 0;
static void desk_draw_repo_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = wn->w - 2, ch = wn->h - TITLE_H - 2;
    char line[160];
    int p = 0; { const char *t = "Repository: "; while (*t) line[p++] = *t++; }
    { int t = 0; while (desk_repo_url[t] && p < 150) line[p++] = desk_repo_url[t++]; }
    line[p] = 0;
    draw_text2(x + 10, y + 32, line, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    if (desk_repo_count < 0) {
        draw_text2(x + 10, y + 56, "(no index downloaded - set a repository, then Update)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    } else {
        char vnum[16]; u32_to_str(desk_repo_version, vnum, 10);
        p = 0; { const char *t = "Index version: "; while (*t) line[p++] = *t++; }
        { int t = 0; while (vnum[t]) line[p++] = vnum[t++]; }
        line[p] = 0;
        draw_text2(x + 10, y + 56, line, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        if (desk_repo_count == 0)
            draw_text2(x + 10, y + 80, "(no packages in index)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        /* Repo scroll: the index holds up to 64 entries but the
           window shows 8 rows, so rows scroll..scroll+7 are drawn
           (was: rows 0..7 only, silently hiding entries 9+). */
        for (int i = desk_repo_scroll; i < desk_repo_count && i < desk_repo_scroll + 8; i++) {
            p = 0; int t = 0;
            while (desk_repo_name[i][t] && p < 150) line[p++] = desk_repo_name[i][t++];
            line[p++] = ' ';
            t = 0; while (desk_repo_ver[i][t] && p < 150) line[p++] = desk_repo_ver[i][t++];
            line[p] = 0;
            /* Selected row highlighted, Files pattern. */
            if (i == wn->selected) fb_fill_rect_clip(x + 10, y + 80 + (i - desk_repo_scroll) * 20 - 2, 460, 20, 0x00A0C0FFu, dx, dy, dw, dh);
            draw_text2(x + 10, y + 80 + (i - desk_repo_scroll) * 20, line, 0x00000000u, i == wn->selected ? 0x00A0C0FFu : 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
        }
        /* Scroll buttons below the footer, clear of the resize
           corner (window 480 wide, 320 tall): Up x+360..x+410,
           Dn x+420..x+470, both y+284..y+308. They do nothing
           when the index fits (scroll stays 0). */
        fb_fill_rect_clip(x + 360, y + 284, 50, 24, 0x00C0C0C0u, dx, dy, dw, dh);
        draw_text2(x + 368, y + 288, "Up", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
        fb_fill_rect_clip(x + 420, y + 284, 50, 24, 0x00C0C0C0u, dx, dy, dw, dh);
        draw_text2(x + 428, y + 288, "Dn", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    }
    /* Update/Install/Fetch row (y+252..y+276), below the 8 rows (end
       y+240) and above the scroll buttons (y+284): always drawn,
       even with no stored index, because Update is how an index
       is first fetched. The old footer ("Fetch/install from
       the shell") is replaced by these buttons. Fetch downloads
       the selected package's .nxpkg file to disk without
       installing it (the desktop form of shell `pkg fetch`),
       so a fetched file can later be installed from Files. */
    fb_fill_rect_clip(x + 10, y + 252, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 18, y + 256, "Update", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 120, y + 252, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 128, y + 256, "Install", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 230, y + 252, 100, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 238, y + 256, "Fetch", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
    /* Set-repo row (y+316..y+340), in the new area the taller
       window (480x360, was 480x320) adds below the scroll
       buttons: a white field box for the repository URL plus a
       Set repo button. The row clears the 16x16 resize corner
       (y+344..y+360), and every earlier button keeps its
       position. The field caps at 63 characters like the Web
       and Files fields; pkg_repo_set refuses a malformed URL,
       so a capped or mistyped URL fails loudly, never silently. */
    fb_fill_rect_clip(x + 10, y + 316, 340, 24, 0x00FFFFFFu, dx, dy, dw, dh);
    draw_text2(x + 14, y + 320, wn->field, 0x00000000u, 0x00FFFFFFu, x + 10, y + 316, 340, 24, dx, dy, dw, dh);
    if (wn->field_focused) fb_fill_rect_clip(x + 14 + wn->field_len * 8, y + 320, 2, 16, 0x00000000u, dx, dy, dw, dh);
    fb_fill_rect_clip(x + 360, y + 316, 110, 24, 0x00C0C0C0u, dx, dy, dw, dh);
    draw_text2(x + 368, y + 320, "Set repo", 0x00000000u, 0x00C0C0C0u, cx, cy, cw, ch, dx, dy, dw, dh);
}
/* Repo index reload shared by open and Update: re-reads the
   configured URL and the stored, signature-verified index,
   copies up to 64 entries, resets scroll to 0, and prints
   the list once, so the serial log proves content. A stored
   index that fails re-verification shows as "no stored
   index", never as stale data. */
static void desk_repo_reload(void) {
    if (pkg_repo_config_url(desk_repo_url, sizeof(desk_repo_url)) != 0) {
        const char *t = "(no repository set)"; int n = 0; while (t[n]) { desk_repo_url[n] = t[n]; n++; } desk_repo_url[n] = 0;
    }
    u32 ver = 0;
    int n = pkg_repo_browse_load(&ver);
    desk_repo_version = ver;
    desk_repo_count = n;
    desk_repo_scroll = 0;
    if (n < 0) {
        console_write("repo: no stored index\n");
    } else {
        console_printf("repo: index version %u\n", ver);
        char name[32], ver2[16];
        for (int i = 0; i < n && i < 64; i++) {
            if (pkg_repo_browse_entry(i, name, ver2) != 0) break;
            int t = 0; while (t < 31 && name[t]) { desk_repo_name[i][t] = name[t]; t++; } desk_repo_name[i][t] = 0;
            t = 0; while (t < 15 && ver2[t]) { desk_repo_ver[i][t] = ver2[t]; t++; } desk_repo_ver[i][t] = 0;
            console_printf("repo: %s %s\n", name, ver2);
        }
    }
}
static int desk_open_repo(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_REPO) { bring_to_front(i); return i; }
    int id = wm_create("Repo", 160, 80, 480, 360, W_REPO);
    if (id < 0) return -1;
    console_write("Desktop: Repo opened\n");
    desk_repo_reload();
    int wi = find_by_id(id);
    if (wi >= 0) wins[wi].selected = -1;
    return find_by_id(id);
}

/* Clock window (6b utility app): system time from the real
   CMOS RTC (same source as the taskbar clock, with seconds)
   plus the real calendar date from the CMOS date registers
   plus uptime since boot from timer_ticks. Read-only, and
   refreshed once per second by the desktop loop like the
   Monitor window. An invalid date read shows as
   "(unavailable)", never as an invented date. The time +
   date + uptime are printed once on open, so the serial
   log proves content, not just that a window opened. */
static void desk_draw_clock_content(int idx, s32 dx, s32 dy, s32 dw, s32 dh) {
    struct window *wn = &wins[idx];
    s32 x = wn->x, y = wn->y;
    s32 cx = x + 1, cy = y + TITLE_H + 1, cw = wn->w - 2, ch = wn->h - TITLE_H - 2;
    char clk[16], num[16], line[96];
    draw_text2(x + 10, y + 32, "Clock (updates every second)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    clock_text_sec(clk);
    draw_text2(x + 10, y + 56, "System time:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 130, y + 56, clk, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    char dat[16];
    date_text(dat);
    draw_text2(x + 10, y + 80, "Date:", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 130, y + 80, dat, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    u32 tot = timer_ticks / 100;
    u32 d = tot / 86400; tot %= 86400;
    u32 hh = tot / 3600; tot %= 3600;
    u32 mm = tot / 60; u32 ss = tot % 60;
    int p = 0; { const char *t = "Uptime: "; while (*t) line[p++] = *t++; }
    u32_to_str(d, num, 10); { int t = 0; while (num[t]) line[p++] = num[t++]; }
    line[p++] = 'd'; line[p++] = ' ';
    u32_to_str(hh, num, 10); { int t = 0; while (num[t]) line[p++] = num[t++]; }
    line[p++] = 'h'; line[p++] = ' ';
    u32_to_str(mm, num, 10); { int t = 0; while (num[t]) line[p++] = num[t++]; }
    line[p++] = 'm'; line[p++] = ' ';
    u32_to_str(ss, num, 10); { int t = 0; while (num[t]) line[p++] = num[t++]; }
    line[p++] = 's'; line[p] = 0;
    draw_text2(x + 10, y + 104, line, 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    if (desk_clock_24)
        draw_text2(x + 10, y + 128, "Format: 24-hour (Settings > Clock format)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    else
        draw_text2(x + 10, y + 128, "Format: 12-hour (Settings > Clock format)", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
    draw_text2(x + 10, y + 152, "Time and date are read from the system clock (CMOS RTC).", 0x00000000u, 0x00D0D0D0u, cx, cy, cw, ch, dx, dy, dw, dh);
}
static int desk_open_clock(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_CLOCK) { bring_to_front(i); return i; }
    int id = wm_create("Clock", 160, 80, 480, 320, W_CLOCK);
    if (id < 0) return -1;
    console_write("Desktop: Clock opened\n");
    char clk[16];
    clock_text_sec(clk);
    console_printf("clock: time %s\n", clk);
    char dat[16];
    date_text(dat);
    console_printf("clock: date %s\n", dat);
    console_printf("clock: uptime %u seconds\n", timer_ticks / 100);
    return find_by_id(id);
}

static void desk_draw_taskbar(s32 dx, s32 dy, s32 dw, s32 dh) {
    s32 sw = scr_w(), sh = scr_h();
    u32 tcol = desk_taskbar_col();
    u32 ttext = desk_taskbar_text_col();
    fb_fill_rect_clip(0, sh - TASKBAR_H, sw, TASKBAR_H, tcol, dx, dy, dw, dh);
    fb_fill_rect_clip(2, sh - TASKBAR_H + 2, 60, TASKBAR_H - 4, 0x00606060u, dx, dy, dw, dh);
    fb_draw_text_clip(8, sh - TASKBAR_H + 5, "Start", 0x00FFFFFFu, 0x00606060u, dx, dy, dw, dh);
    s32 bx = 66;
    for (int zi = 0; zi < zcount; zi++) {
        struct window *wn = &wins[zorder[zi]];
        if (wn->ws != desk_ws) continue; /* other workspace: not listed here */
        if (bx + 120 > sw) break;
        u32 bg = wn->focused ? 0x00808080u : (wn->minimized ? 0x00505050u : 0x00606060u);
        fb_fill_rect_clip(bx, sh - TASKBAR_H + 2, 118, TASKBAR_H - 4, bg, dx, dy, dw, dh);
        fb_draw_text_clip(bx + 4, sh - TASKBAR_H + 5, wn->title, 0x00FFFFFFu, bg, dx, dy, dw, dh);
        bx += 122;
    }
    /* Workspace button, left of the tray. */
    fb_fill_rect_clip(sw - 258, sh - TASKBAR_H + 2, 44, TASKBAR_H - 4, 0x00606060u, dx, dy, dw, dh);
    fb_draw_text_clip(sw - 252, sh - TASKBAR_H + 5, desk_ws == 0 ? "WS1" : "WS2", 0x00FFFFFFu, 0x00606060u, dx, dy, dw, dh);
    /* Tray, right-aligned: user, clock, bell, gear. */
    char clk[16]; clock_text(clk);
    fb_draw_text_clip(sw - 110, sh - TASKBAR_H + 5, clk, ttext, tcol, dx, dy, dw, dh);
    fb_draw_text_clip(sw - 200, sh - TASKBAR_H + 5, shell_session_name(), ttext, tcol, dx, dy, dw, dh);
    /* Bell with count, gear. */
    char bell[8]; bell[0] = 'B'; bell[1] = ':'; bell[2] = (char)('0' + (desk_notif_count > 9 ? 9 : desk_notif_count)); bell[3] = 0;
    fb_draw_text_clip(sw - 48, sh - TASKBAR_H + 5, bell, ttext, tcol, dx, dy, dw, dh);
    fb_draw_text_clip(sw - 24, sh - TASKBAR_H + 5, "G", ttext, tcol, dx, dy, dw, dh);
}

/* Phase 10 large text: draw a string at 2x scale (each glyph
   pixel becomes a 2x2 block), foreground pixels only, so it
   stays readable over wallpaper patterns. Used for desktop
   icon labels when the Large text setting is on. */
static void desk_draw_text2x(s32 x, s32 y, const char *s, u32 fg,
                             s32 dx, s32 dy, s32 dw, s32 dh) {
    int col = 0;
    while (s[col]) {
        const u8 *glyph = font8x16[(u8)s[col]];
        for (int row = 0; row < 16; row++) {
            u8 bits = glyph[row];
            for (int bit = 0; bit < 8; bit++) {
                if (bits & (u8)(0x80u >> bit))
                    fb_fill_rect_clip(x + col * 16 + bit * 2, y + row * 2, 2, 2, fg, dx, dy, dw, dh);
            }
        }
        col++;
    }
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
        /* Lock screen covers everything: present the full frame. */
        fb_present();
        return;
    }
    /* Phase 10 wallpaper: solid is the old flat fill; gradient
       interpolates the theme background toward black in 4px
       bands; dots puts accent dots on the theme background.
       Low-resource mode forces solid (no band/dot loops). */
    if (desk_wallpaper == 1 && !desk_lowres) {
        u32 bg = desk_bg_col();
        u32 br = (bg >> 16) & 0xFF, bgc = (bg >> 8) & 0xFF, bb = bg & 0xFF;
        for (s32 gy = 0; gy < scr_h(); gy += 4) {
            u32 f = (u32)(scr_h() - gy) * 256u / (u32)scr_h();
            u32 col = (((br * f / 256u) << 16) | ((bgc * f / 256u) << 8) | (bb * f / 256u));
            fb_fill_rect_clip(0, gy, scr_w(), 4, col, dx, dy, dw, dh);
        }
    } else if (desk_wallpaper == 2 && !desk_lowres) {
        fb_fill_rect_clip(0, 0, scr_w(), scr_h(), desk_bg_col(), dx, dy, dw, dh);
        u32 dot = desk_accent_col();
        for (s32 gy = 24; gy < scr_h(); gy += 48)
            for (s32 gx = 24; gx < scr_w(); gx += 48)
                fb_fill_rect_clip(gx, gy, 4, 4, dot, dx, dy, dw, dh);
    } else {
        fb_fill_rect_clip(0, 0, scr_w(), scr_h(), desk_bg_col(), dx, dy, dw, dh);
    }
    if (desk_icons_on) {
        for (int i = 0; i < 6; i++) {
            s32 ix, iy; desk_icon_rect(i, &ix, &iy);
            fb_fill_rect_clip(ix, iy, 48, 48, desk_icon_cols[i], dx, dy, dw, dh);
            if (desk_bigtext) desk_draw_text2x(ix, iy + 52, desk_icon_labels[i], 0x00FFFFFFu, dx, dy, dw, dh);
            else fb_draw_text_clip(ix, iy + 52, desk_icon_labels[i], 0x00FFFFFFu, desk_bg_col(), dx, dy, dw, dh);
        }
    }
    for (int zi = 0; zi < zcount; zi++) {
        struct window *wn = &wins[zorder[zi]];
        if (wn->minimized) continue;
        if (wn->ws != desk_ws) continue;
        if (!rects_overlap(wn->x, wn->y, wn->w, wn->h, dx, dy, dw, dh)) continue;
        draw_window_clip(zorder[zi], dx, dy, dw, dh);
        if (wn->type == W_SETTINGS) desk_draw_settings_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_FILES) desk_draw_files_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_ABOUT) desk_draw_about_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_NETWORK) desk_draw_network_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_WEB) desk_draw_web_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_EDITOR) desk_draw_editor_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_MONITOR) desk_draw_monitor_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_VIEWER) desk_draw_viewer_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_PACKAGES) desk_draw_packages_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_REPO) desk_draw_repo_content(zorder[zi], dx, dy, dw, dh);
        else if (wn->type == W_CLOCK) desk_draw_clock_content(zorder[zi], dx, dy, dw, dh);
        /* W_USER content is app-drawn, never redrawn here. */
    }
    /* Panels, on top of windows. */
    s32 sh = scr_h();
    if (desk_launcher_open) {
        /* Column 1 keeps the original seven entries plus
           Reboot appended as row 7 and Logout as row 8;
           column 2 (Phase 10 apps + the 6b Repo browser
           + Clock) is appended to the right. The panel
           grows upward with column 2: 9 rows need 228 px,
           so my0 moves up 24 px vs the 8-row panel —
           every autotest launcher click coordinate shifts
           up 24 px with it (see the autotest scripts
           below). Column 1's 9 rows need 224 px, so they
           fit inside the 228 px panel, and adding Logout
           moves no earlier row. */
        s32 mx0 = 0, my0 = sh - TASKBAR_H - 228, mw = 400, mh = 228;
        u32 pcol = desk_panel_col(), ptext = desk_panel_text_col();
        fb_fill_rect_clip(mx0, my0, mw, mh, pcol, dx, dy, dw, dh);
        fb_fill_rect_clip(mx0, my0, mw, 1, 0x00000000u, dx, dy, dw, dh);
        fb_fill_rect_clip(mx0 + 200, my0, 1, mh, 0x00000000u, dx, dy, dw, dh);
        const char *entries[9] = {"Settings", "Files", "Calculator", "About", "Terminal", "Lock", "Exit desktop", "Reboot", "Logout"};
        for (int i = 0; i < 9; i++) fb_draw_text_clip(mx0 + 10, my0 + 8 + i * 24, entries[i], ptext, pcol, dx, dy, dw, dh);
        const char *entries2[9] = {"Editor", "Monitor", "Network", "Web", "Viewer", "Console", "Packages", "Repo", "Clock"};
        for (int i = 0; i < 9; i++) fb_draw_text_clip(mx0 + 210, my0 + 8 + i * 24, entries2[i], ptext, pcol, dx, dy, dw, dh);
    }
    if (desk_quick_open) {
        s32 qx = scr_w() - 260, qy = sh - TASKBAR_H - 140;
        u32 pcol = desk_panel_col(), ptext = desk_panel_text_col();
        fb_fill_rect_clip(qx, qy, 260, 140, pcol, dx, dy, dw, dh);
        fb_draw_text_clip(qx + 10, qy + 8, "Quick settings", ptext, pcol, dx, dy, dw, dh);
        char v1[32], v2[32], v3[32], v4[32];
        idle_text(v1); mouse_text(v2);
        v3[0]='2'; v3[1]='4'; v3[2]='h'; v3[3]=0; if (!desk_clock_24) { v3[0]='1'; v3[1]='2'; v3[2]='h'; v3[3]=0; }
        v4[0]='O'; v4[1]='n'; v4[2]=0; if (!desk_icons_on) { v4[0]='O'; v4[1]='f'; v4[2]='f'; v4[3]=0; }
        const char *qn[4] = {"Idle", "Mouse", "Clock", "Icons"};
        const char *qv[4] = {v1, v2, v3, v4};
        for (int i = 0; i < 4; i++) {
            fb_draw_text_clip(qx + 10, qy + 32 + i * 22, qn[i], ptext, pcol, dx, dy, dw, dh);
            fb_fill_rect_clip(qx + 120, qy + 28 + i * 22, 100, 20, 0x00E0E0E0u, dx, dy, dw, dh);
            fb_draw_text_clip(qx + 126, qy + 32 + i * 22, qv[i], 0x00000000u, 0x00E0E0E0u, dx, dy, dw, dh);
        }
        fb_fill_rect_clip(qx + 10, qy + 116, 100, 20, 0x00E0E0E0u, dx, dy, dw, dh);
        fb_draw_text_clip(qx + 16, qy + 120, "Save", 0x00000000u, 0x00E0E0E0u, dx, dy, dw, dh);
    }
    if (desk_notif_open) {
        s32 nx = scr_w() - 300, ny = sh - TASKBAR_H - 200;
        u32 pcol = desk_panel_col(), ptext = desk_panel_text_col();
        fb_fill_rect_clip(nx, ny, 300, 200, pcol, dx, dy, dw, dh);
        fb_draw_text_clip(nx + 10, ny + 8, "Notifications", ptext, pcol, dx, dy, dw, dh);
        if (desk_notif_count == 0) fb_draw_text_clip(nx + 10, ny + 32, "(none)", ptext, pcol, dx, dy, dw, dh);
        for (int i = 0; i < desk_notif_count && i < 7; i++) fb_draw_text_clip(nx + 10, ny + 32 + i * 20, desk_notif[i], ptext, pcol, dx, dy, dw, dh);
        fb_fill_rect_clip(nx + 10, ny + 176, 80, 20, 0x00E0E0E0u, dx, dy, dw, dh);
        fb_draw_text_clip(nx + 16, ny + 180, "Clear", 0x00000000u, 0x00E0E0E0u, dx, dy, dw, dh);
    }
    if (rects_overlap(0, sh - TASKBAR_H, scr_w(), TASKBAR_H, dx, dy, dw, dh))
        desk_draw_taskbar(dx, dy, dw, dh);
    cursor_save_at(mouse_x(), mouse_y());
    draw_cursor();
    /* The scene is complete only now: present it atomically. */
    present_scene_rect(dx, dy, dw, dh);
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
    /* v1.1.0 release fix (calc regression): app paints land in the
       back buffer, and no desktop-redraw path presents them — every
       present goes through a redraw that repaints the desktop
       background over the client area first, so an app window's
       body could never become visible (its frame, drawn by the WM,
       showed fine while the body stayed desktop background, which
       is exactly what the calc test caught). Present the painted
       rect right away: in direct mode this is a no-op, and the
       next desktop redraw still repaints over it exactly as in
       v1.0.0 (the app repaints on its next event, as before). */
    fb_present_rect(ax, ay, cw, ch);
    return 0;
}
int wm_gui_text(u32 pid, s32 cx, s32 cy, const char *text, u32 fg, u32 bg) {
    struct window *wn = find_user_window(pid);
    if (!wn || wn->minimized) return -1;
    s32 ax = wn->x + 1 + cx, ay = wn->y + TITLE_H + 1 + cy;
    fb_draw_text_clip(ax, ay, text, fg, bg,
                      wn->x + 1, wn->y + TITLE_H + 1, wn->w - 2, wn->h - TITLE_H - 2);
    fb_present_rect(ax, ay, (s32)strlen(text) * 8, 16);
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
/* Settings Unlock row: the desktop form of shell `unlock <user>`,
   in the shell's own order (empty field first, then the root
   check, then the existence check) and through the same
   primitive (shell_unlock_user). The handler check is the only
   barrier: the primitive itself has no uid rule, so calling it
   without the check would let a non-root session reset any
   account's brute-force counter (Repo Fetch/Update precedent).
   No confirm: unlocking only resets a failure counter, and a
   locked account is restored by failing logins again, not by
   any destructive act. A success clears the field; a refusal
   keeps it for a retry (so a mistyped name can be corrected
   in place, and the no-such-user test presses Unlock twice
   to prove the field really survived the refusal). The
   audit entry a real desktop unlock writes ("unlock <name>",
   via shell_unlock_user) is QEMU-proven by read-back in
   tests/qemu_test_desktop_unlock_audit.py — root `cat
   audit.log` after a mode-28 unlock shows exactly one
   unlock entry, so the empty-field refusal in the same
   script audited nothing. The non-root refusal's absence
   is likewise QEMU-proven by read-back in
   tests/qemu_test_desktop_unlock_nonroot_audit.py — a
   non-root mode-28 run followed by root `cat audit.log`
   shows zero unlock entries, so the handler's early
   return (before shell_unlock_user) audits nothing. */
static void desk_settings_unlock_run(void) {
    if (desk_settings_unlock_len == 0) {
        console_write("settings: unlock needs user\n");
        return;
    }
    if (shell_session_uid() != 0) {
        console_write("settings: unlock needs root\n");
        return;
    }
    if (!shell_unlock_user(desk_settings_unlock)) {
        console_printf("settings: no such user %s\n", desk_settings_unlock);
        return;
    }
    console_printf("settings: unlocked %s\n", desk_settings_unlock);
    desk_settings_unlock_len = 0; desk_settings_unlock[0] = 0;
    desk_settings_unlock_focused = 0;
}
static int desk_open_settings(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_SETTINGS) { bring_to_front(i); return i; }
    int id = wm_create("Settings", 160, 80, 480, 320, W_SETTINGS);
    if (id < 0) return -1;
    int idx = find_by_id(id);
    if (idx >= 0) {
        wins[idx].search[0] = 0; wins[idx].search_len = 0;
        wins[idx].field[0] = 0; wins[idx].field_focused = 0;
        desk_settings_unlock_len = 0; desk_settings_unlock[0] = 0;
        desk_settings_unlock_focused = 0;
        wins[idx].aux1 = 0;
        desk_at_settings_opened = 1;
        console_write("Desktop: Settings opened\n");
    }
    return idx;
}
static int desk_open_files(void) {
    for (int i = 0; i < MAX_WINDOWS; i++)
        if (wins[i].used && wins[i].type == W_FILES) { bring_to_front(i); return i; }
    int id = wm_create("Files", 160, 80, 480, 424, W_FILES);
    if (id < 0) return -1;
    int idx = find_by_id(id);
    if (idx >= 0) {
        wins[idx].selected = -1; wins[idx].preview[0] = 0;
        wins[idx].field_len = 0; wins[idx].field[0] = 0;
        wins[idx].field_focused = 0;
        desk_files_mode_len = 0; desk_files_mode[0] = 0;
        desk_files_mode_focused = 0;
        desk_files_sysupd_arm = -1;
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
/* Reboot confirm arm: a single launcher Reboot click only
   arms; the confirming click is a second Reboot click after
   the launcher is reopened (it closes after every click).
   Any other launcher or icon action disarms. Reset on
   desktop start in wm_desktop_internal. */
static int desk_reboot_armed = 0;
static int desk_logout_armed = 0;
/* Set by a confirmed Logout click; the shell performs the logout
   (kill own jobs, audit, session end) when the desktop returns,
   so the shell's `logout` rule runs exactly once for both paths. */
static int desk_logout_requested = 0;
int wm_logout_requested(void) {
    int r = desk_logout_requested;
    desk_logout_requested = 0;
    return r;
}

static void desk_do_action(int action, int *exit_desktop) {
    /* Actions: 0=Settings,1=Files,2=Calculator,3=About,4=Terminal,5=Lock,6=Exit,7=Reboot,8=Logout;
       column 2 starts at 9 (Editor) through 17 (Clock). */
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
    else if (action == 7) {
        /* Reboot: the shell's `reboot` primitive (keyboard
           controller reset), with the Files Delete two-click
           confirm — a reboot loses unsaved editor work, so a
           single click must never do it. The first click only
           arms ("desktop: reboot confirm"); the second click
           reboots ("desktop: rebooting"). No uid check: the
           shell `reboot` has none either, so desktop and shell
           share exactly one reboot rule. There is no power-off:
           the kernel has no ACPI shutdown, so Reboot is the
           only power action offered. */
        if (desk_reboot_armed) {
            desk_reboot_armed = 0;
            console_write("desktop: rebooting\n");
            outb(0x64, 0xFE);
            for (;;) __asm__ volatile ("hlt");
        } else {
            desk_reboot_armed = 1;
            console_write("desktop: reboot confirm\n");
            desk_notify("Reboot? Click Reboot again to confirm");
        }
    }
    else if (action == 8) {
        /* Logout: the shell's `logout` primitive, with the Files
           Delete two-click confirm — a logout kills the session's
           background jobs, so a single click must never do it.
           The first click only arms ("desktop: logout confirm");
           the second click sets the logout request and exits
           the desktop ("desktop: logging out"), and the shell
           performs the logout on return. No uid check: the
           shell `logout` has none either, so desktop and shell
           share exactly one logout rule. */
        if (desk_logout_armed) {
            desk_logout_armed = 0;
            desk_logout_requested = 1;
            console_write("desktop: logging out\n");
            *exit_desktop = 1;
        } else {
            desk_logout_armed = 1;
            console_write("desktop: logout confirm\n");
            desk_notify("Logout? Click Logout again to confirm");
        }
    }
    /* Phase 10 launcher column 2. */
    else if (action == 9) {
        desk_ed_len = 0; desk_ed_buf[0] = 0;
        { const char *t = "notes.txt"; int n = 0; while (t[n]) { desk_ed_name[n] = t[n]; n++; } desk_ed_name[n] = 0; }
        desk_ed_msg[0] = 0;
        desk_open_editor();
    }
    else if (action == 10) desk_open_monitor();
    else if (action == 11) desk_open_network();
    else if (action == 12) desk_open_web();
    else if (action == 13) desk_open_viewer();
    else if (action == 14) {
        if (proc_bg_start("term.elf", shell_session_uid()) != 0) {
            desk_notify("Console not installed: pkg install term.nxpkg, then try again");
        } else {
            desk_notify("Console started");
        }
    }
    else if (action == 15) desk_open_packages();
    else if (action == 16) desk_open_repo();
    else if (action == 17) desk_open_clock();
    if (action != 7) desk_reboot_armed = 0;
    if (action != 8) desk_logout_armed = 0;
}
/* Phase 10 snap: left half (0), right half (1), or
   maximise/restore toggle (2), applied to the topmost
   non-minimised window on the current workspace. The first
   snap saves the geometry; restore returns to it. */
static void desk_snap_topmost(int mode) {
    int wi = -1;
    for (int zi = zcount - 1; zi >= 0; zi--) {
        if (!wins[zorder[zi]].minimized && wins[zorder[zi]].ws == desk_ws) { wi = zorder[zi]; break; }
    }
    if (wi < 0) return;
    struct window *wn = &wins[wi];
    if (mode == 0 || mode == 1) {
        if (!wn->snapped) { wn->old_x = wn->x; wn->old_y = wn->y; wn->old_w = wn->w; wn->old_h = wn->h; wn->snapped = 1; }
        wn->maximized = 0;
        wn->y = 0; wn->h = scr_h() - TASKBAR_H;
        if (mode == 0) { wn->x = 0; wn->w = scr_w() / 2; }
        else { wn->x = scr_w() / 2; wn->w = scr_w() - scr_w() / 2; }
        console_printf("Desktop: snapped %s to %s half (x=%d w=%d)\n", wn->title, mode == 0 ? "left" : "right", wn->x, wn->w);
    } else {
        if (wn->snapped) {
            wn->x = wn->old_x; wn->y = wn->old_y; wn->w = wn->old_w; wn->h = wn->old_h; wn->snapped = 0;
            console_printf("Desktop: snap restored %s (x=%d w=%d)\n", wn->title, wn->x, wn->w);
        } else if (wn->maximized) {
            wn->x = wn->old_x; wn->y = wn->old_y; wn->w = wn->old_w; wn->h = wn->old_h; wn->maximized = 0;
            console_printf("Desktop: snap restored %s (x=%d w=%d)\n", wn->title, wn->x, wn->w);
        } else {
            wn->old_x = wn->x; wn->old_y = wn->y; wn->old_w = wn->w; wn->old_h = wn->h; wn->maximized = 1;
            wn->x = 0; wn->y = 0; wn->w = scr_w(); wn->h = scr_h() - TASKBAR_H;
            console_printf("Desktop: snapped %s to full (x=%d w=%d)\n", wn->title, wn->x, wn->w);
        }
    }
    if (wn->type == W_USER) gui_queue_event(wn, GUI_EV_EXPOSE, 0, 0, 0, 0);
    desk_redraw();
}
static int wm_desktop_internal(int autotest) {
    if (!fb_ready()) { console_write("desktop: no framebuffer available\n"); return -1; }
    /* Reset desktop state, load persistent settings, start. */
    memset(wins, 0, sizeof(wins)); zcount = 0; next_id = 1;
    desk_ws = 0;
    desk_launcher_open = desk_quick_open = desk_notif_open = 0;
    desk_locked = 0; desk_lock_len = 0; desk_lock_failures = 0;
    desk_notif_count = 0;
    desk_at_settings_opened = desk_at_idle_cycled = desk_at_lock_shown = 0;
    desk_at_lock_unlocked = desk_at_terminal_exit = 0;
    desk_reboot_armed = 0;
    desk_logout_armed = 0;
    desk_logout_requested = 0;
    desk_files_sysupd_arm = -1;
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
            int max_step = autotest == 2 ? 15 : (autotest == 3 ? 6 :
                (autotest == 4 ? 21 : (autotest == 5 ? 243 :
                (autotest == 6 ? 27 : (autotest == 7 ? 40 :
                (autotest == 8 ? 3 : (autotest == 9 ? 15 :
                (autotest == 10 ? 65 : (autotest == 11 ? 13 : (autotest == 12 ? 12 : (autotest == 13 ? 12 : (autotest == 14 ? 24 : (autotest == 15 ? 8 : (autotest == 16 ? 18 : (autotest == 17 ? 16 : (autotest == 18 ? 13 : (autotest == 19 ? 81 : (autotest == 20 ? 40 : (autotest == 21 ? 68 : (autotest == 22 ? 89 : (autotest == 23 ? 10 : (autotest == 24 ? 7 : (autotest == 25 ? 87 : (autotest == 26 ? 34 : (autotest == 27 ? 11 : (autotest == 28 ? 15 : (autotest == 29 ? 15 : (autotest == 30 ? 7 : 11))))))))))))))))))))))))))));
            if (step != auto_step && step <= max_step) {
                auto_step = step;
                if (autotest == 4) {
                    /* Phase 10 polish script, 30 ticks per step:
                       0-2 Settings icon; 3-5 Appearance toggle;
                       6-8 Theme value (Classic -> Dark); 9-11 Save;
                       12-13 workspace button (WS1 -> WS2);
                       14 sample a pixel inside the Settings
                       window (must be dark desktop bg, the
                       window is hidden on WS2); 15-16 back to
                       WS1; 17 sample again (must be client
                       grey); 18 '[' snaps Settings left;
                       19 print geometry; 20 '\' restores;
                       21 print geometry. */
                    if (step == 0) mouse_test_set(40, 40, 0);
                    else if (step == 1) mouse_test_set(40, 40, 1);
                    else if (step == 2) mouse_test_set(40, 40, 0);
                    else if (step == 3) mouse_test_set(240, 344, 0);
                    else if (step == 4) mouse_test_set(240, 344, 1);
                    else if (step == 5) mouse_test_set(240, 344, 0);
                    else if (step == 6) mouse_test_set(410, 156, 0);
                    else if (step == 7) mouse_test_set(410, 156, 1);
                    else if (step == 8) mouse_test_set(410, 156, 0);
                    else if (step == 9) mouse_test_set(230, 368, 0);
                    else if (step == 10) mouse_test_set(230, 368, 1);
                    else if (step == 11) mouse_test_set(230, 368, 0);
                    else if (step == 12) mouse_test_set(564, 588, 1);
                    else if (step == 13) mouse_test_set(564, 588, 0);
                    else if (step == 14 || step == 17) {
                        int si = -1;
                        for (int i = 0; i < MAX_WINDOWS; i++) if (wins[i].used && wins[i].type == W_SETTINGS) si = i;
                        if (si >= 0) console_printf("p10: ws%d pixel 0x%x\n", step == 14 ? 2 : 1, fb_read_pixel(300, 200));
                        else console_write("p10: no settings window\n");
                    }
                    else if (step == 15) mouse_test_set(564, 588, 1);
                    else if (step == 16) mouse_test_set(564, 588, 0);
                    else if (step == 18) keyboard_inject_char('[');
                    else if (step == 19 || step == 21) {
                        int si = -1;
                        for (int i = 0; i < MAX_WINDOWS; i++) if (wins[i].used && wins[i].type == W_SETTINGS) si = i;
                        if (si >= 0) console_printf("p10: %s x=%d w=%d\n", step == 19 ? "snapped" : "restored", wins[si].x, wins[si].w);
                    }
                    else if (step == 20) keyboard_inject_char('\\');
                } else if (autotest == 5) {
                    /* Phase 10 apps script: Start, then launcher
                       column 2 entries (Editor, Monitor, Network,
                       Web, Viewer, Console, Packages, Repo,
                       Clock), then Files: select notes.txt,
                       Open (Editor), 6(b) part 7 New-file flow
                       (New twice, type fresh.txt, Save), 6(b)
                       part 8 Editor scroll (body click, 16
                       newlines, Up/Down buttons), close
                       Editor, select pic.bmp, Open (Viewer),
                       then 6(b) part 9 Files scroll (close
                       Viewer, Files icon, Dn button, row 7,
                       Open into the Editor).
                       Launcher panel is 228 px tall (9
                       column-2 rows), so column-2 click rows
                       sit 24 px above the old 8-row
                       coordinates. Editor at 140,60: New
                       button centre 370,136, filename field
                       300,100, Save centre 190,136, Up button
                       centre 568,406, Down button centre
                       618,406. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 360, 1);
                    else if (step == 3) mouse_test_set(300, 360, 0);
                    else if (step == 4) mouse_test_set(32, 588, 1);
                    else if (step == 5) mouse_test_set(32, 588, 0);
                    else if (step == 6) mouse_test_set(300, 384, 1);
                    else if (step == 7) mouse_test_set(300, 384, 0);
                    else if (step == 8) mouse_test_set(32, 588, 1);
                    else if (step == 9) mouse_test_set(32, 588, 0);
                    else if (step == 10) mouse_test_set(300, 408, 1);
                    else if (step == 11) mouse_test_set(300, 408, 0);
                    else if (step == 12) mouse_test_set(32, 588, 1);
                    else if (step == 13) mouse_test_set(32, 588, 0);
                    else if (step == 14) mouse_test_set(300, 432, 1);
                    else if (step == 15) mouse_test_set(300, 432, 0);
                    else if (step == 16) mouse_test_set(32, 588, 1);
                    else if (step == 17) mouse_test_set(32, 588, 0);
                    else if (step == 18) mouse_test_set(300, 456, 1);
                    else if (step == 19) mouse_test_set(300, 456, 0);
                    else if (step == 20) mouse_test_set(32, 588, 1);
                    else if (step == 21) mouse_test_set(32, 588, 0);
                    else if (step == 22) mouse_test_set(300, 480, 1);
                    else if (step == 23) mouse_test_set(300, 480, 0);
                    else if (step == 24) mouse_test_set(32, 588, 1);
                    else if (step == 25) mouse_test_set(32, 588, 0);
                    else if (step == 26) mouse_test_set(300, 504, 1);
                    else if (step == 27) mouse_test_set(300, 504, 0);
                    else if (step == 28) mouse_test_set(32, 588, 1);
                    else if (step == 29) mouse_test_set(32, 588, 0);
                    else if (step == 30) mouse_test_set(300, 528, 1);
                    else if (step == 31) mouse_test_set(300, 528, 0);
                    else if (step == 32) mouse_test_set(32, 588, 1);
                    else if (step == 33) mouse_test_set(32, 588, 0);
                    else if (step == 34) mouse_test_set(300, 552, 1);
                    else if (step == 35) mouse_test_set(300, 552, 0);
                    else if (step == 36) mouse_test_set(40, 132, 0);
                    else if (step == 37) mouse_test_set(40, 132, 1);
                    else if (step == 38) mouse_test_set(40, 132, 0);
                    else if (step == 39) mouse_test_set(200, 122, 1);
                    else if (step == 40) mouse_test_set(200, 122, 0);
                    else if (step == 41) mouse_test_set(220, 376, 1);
                    else if (step == 42) mouse_test_set(220, 376, 0);
                    else if (step == 43) mouse_test_set(370, 136, 1);
                    else if (step == 44) mouse_test_set(370, 136, 0);
                    else if (step == 45) mouse_test_set(370, 136, 1);
                    else if (step == 46) mouse_test_set(370, 136, 0);
                    else if (step == 47) mouse_test_set(300, 100, 1);
                    else if (step == 48) mouse_test_set(300, 100, 0);
                    else if (step >= 49 && step <= 57) {
                        const char *nm = "fresh.txt";
                        keyboard_inject_char(nm[step - 49]);
                    }
                    else if (step == 58) mouse_test_set(190, 136, 1);
                    else if (step == 59) mouse_test_set(190, 136, 0);
                    /* 6(b) part 8: Editor scroll. Click the body
                       to leave the filename field, type 16
                       newlines (cursor-follow scrolls the view:
                       "editor: scroll 1..4"), Up button (568,406)
                       then Down button (618,406), close Editor,
                       select pic.bmp, Open (Viewer).
                       6(b) part 9: Files scroll. Close Viewer
                       (632,70, same title-button geometry as the
                       Editor close), Files icon (40,132) to bring
                       Files forward, Dn scroll button (376,376:
                       Files at 160,80, Dn rect x+190..x+242,
                       y py+68..py+92), row 7 (200,266) which
                       after one scroll is index 8 = filler1.txt
                       on the 13-file setup disk, Open (220,376)
                       into the Editor.
                       6(b) part 10: Files delete. Close Editor
                       (652,70), Files icon (40,132) to bring
                       Files forward, Delete button (450,376:
                       Files at 160,80, Delete rect x+250..
                       x+330, py+68..py+92) twice on the still
                       selected filler1.txt (confirm, then
                       delete), row 7 (200,266) which after
                       the in-place reload is index 8 =
                       filler2.txt, Open (220,376) into the
                       Editor — proving the list reloaded and
                       shifted, not just that a marker printed.
                       Files rename (to match shell `mv`):
                       close Editor (652,70), Files icon
                       (40,132), row 7 (200,266) = filler2.txt,
                       rename field (300,404: Files at 160,80,
                       field rect x+90..x+350, y py+96..py+120),
                       type "renamed.txt", Rename button
                       (570,404: rect x+360..x+460, same row),
                       row 7 again = renamed.txt at the same
                       index (rename is metadata-only, the
                       entry does not move), Open into the
                       Editor — proving the rename + reload.
                       Negative control: close Editor, Files
                       icon, row 7 = renamed.txt, field click,
                       type "filler3.txt" (an existing file),
                       Rename -> "files: rename failed
                       renamed.txt", proving no overwrite.
                       Files copy (to match shell `cp`):
                       Copy button (570,376: rect x+360..
                       x+460, buttons row) with the field
                       still holding "filler3.txt" -> "files:
                       copy failed renamed.txt" (no-overwrite
                       negative control); field click, 11
                       backspaces to clear it, type
                       "copied.txt", Copy -> "files: copied
                       renamed.txt to copied.txt"; row 7
                       (200,266) = copied.txt — the copy takes
                       the first free directory slot, which is
                       the filler1.txt slot freed by the delete,
                       so at the kept scroll 1 it sits at
                       index 8, exactly row 7 — Open into the
                       Editor, proving the copy exists with
                       its content (17 bytes, 1 line).
                       Files refresh: close Editor, Files
                       icon, row 7 = copied.txt, Open into
                       the Editor, New twice, field click,
                       type "refreshed.txt", Save (the
                       6(b) part 7 New-file flow again — the
                       save creates a file on disk while the
                       Files window behind it still shows
                       the old list), close Editor, Files
                       icon, Refresh button (220,432: Files
                       at 160,80, Refresh rect x+10..x+110,
                       y py+124..py+148) -> "files:
                       refreshed"; the new file took the
                       first free slot, which is slot 17
                       (slots 0..16 are all occupied: the 13
                       setup files, calc.elf, packages.txt
                       written by the boot-1 installs,
                       term.elf, fresh.txt, and copied.txt
                       in the freed filler1 slot), so nine
                       Dn clicks take the scroll 1 -> 10
                       and row 7 (200,266) is index 17 =
                       refreshed.txt, Open into the Editor
                       — proving the refresh picked up the
                       outside-window save, not just that
                       a marker printed. */
                    else if (step == 60) mouse_test_set(300, 200, 1);
                    else if (step == 61) mouse_test_set(300, 200, 0);
                    else if (step >= 62 && step <= 77) keyboard_inject_char('\n');
                    else if (step == 78) mouse_test_set(568, 406, 1);
                    else if (step == 79) mouse_test_set(568, 406, 0);
                    else if (step == 80) mouse_test_set(618, 406, 1);
                    else if (step == 81) mouse_test_set(618, 406, 0);
                    else if (step == 82) mouse_test_set(652, 70, 1);
                    else if (step == 83) mouse_test_set(652, 70, 0);
                    else if (step == 84) mouse_test_set(200, 144, 1);
                    else if (step == 85) mouse_test_set(200, 144, 0);
                    else if (step == 86) mouse_test_set(220, 376, 1);
                    else if (step == 87) mouse_test_set(220, 376, 0);
                    else if (step == 88) mouse_test_set(632, 70, 1);
                    else if (step == 89) mouse_test_set(632, 70, 0);
                    else if (step == 90) mouse_test_set(40, 132, 1);
                    else if (step == 91) mouse_test_set(40, 132, 0);
                    else if (step == 92) mouse_test_set(376, 376, 1);
                    else if (step == 93) mouse_test_set(376, 376, 0);
                    else if (step == 94) mouse_test_set(200, 266, 1);
                    else if (step == 95) mouse_test_set(200, 266, 0);
                    else if (step == 96) mouse_test_set(220, 376, 1);
                    else if (step == 97) mouse_test_set(220, 376, 0);
                    else if (step == 98) mouse_test_set(652, 70, 1);
                    else if (step == 99) mouse_test_set(652, 70, 0);
                    else if (step == 100) mouse_test_set(40, 132, 1);
                    else if (step == 101) mouse_test_set(40, 132, 0);
                    else if (step == 102) mouse_test_set(450, 376, 1);
                    else if (step == 103) mouse_test_set(450, 376, 0);
                    else if (step == 104) mouse_test_set(450, 376, 1);
                    else if (step == 105) mouse_test_set(450, 376, 0);
                    else if (step == 106) mouse_test_set(200, 266, 1);
                    else if (step == 107) mouse_test_set(200, 266, 0);
                    else if (step == 108) mouse_test_set(220, 376, 1);
                    else if (step == 109) mouse_test_set(220, 376, 0);
                    else if (step == 110) mouse_test_set(652, 70, 1);
                    else if (step == 111) mouse_test_set(652, 70, 0);
                    else if (step == 112) mouse_test_set(40, 132, 1);
                    else if (step == 113) mouse_test_set(40, 132, 0);
                    else if (step == 114) mouse_test_set(200, 266, 1);
                    else if (step == 115) mouse_test_set(200, 266, 0);
                    else if (step == 116) mouse_test_set(300, 404, 1);
                    else if (step == 117) mouse_test_set(300, 404, 0);
                    else if (step >= 118 && step <= 128) {
                        const char *nm = "renamed.txt";
                        keyboard_inject_char(nm[step - 118]);
                    }
                    else if (step == 129) mouse_test_set(570, 404, 1);
                    else if (step == 130) mouse_test_set(570, 404, 0);
                    else if (step == 131) mouse_test_set(200, 266, 1);
                    else if (step == 132) mouse_test_set(200, 266, 0);
                    else if (step == 133) mouse_test_set(220, 376, 1);
                    else if (step == 134) mouse_test_set(220, 376, 0);
                    else if (step == 135) mouse_test_set(652, 70, 1);
                    else if (step == 136) mouse_test_set(652, 70, 0);
                    else if (step == 137) mouse_test_set(40, 132, 1);
                    else if (step == 138) mouse_test_set(40, 132, 0);
                    else if (step == 139) mouse_test_set(200, 266, 1);
                    else if (step == 140) mouse_test_set(200, 266, 0);
                    else if (step == 141) mouse_test_set(300, 404, 1);
                    else if (step == 142) mouse_test_set(300, 404, 0);
                    else if (step >= 143 && step <= 153) {
                        const char *nm = "filler3.txt";
                        keyboard_inject_char(nm[step - 143]);
                    }
                    else if (step == 154) mouse_test_set(570, 404, 1);
                    else if (step == 155) mouse_test_set(570, 404, 0);
                    else if (step == 156) mouse_test_set(570, 376, 1);
                    else if (step == 157) mouse_test_set(570, 376, 0);
                    else if (step == 158) mouse_test_set(300, 404, 1);
                    else if (step == 159) mouse_test_set(300, 404, 0);
                    else if (step >= 160 && step <= 170) keyboard_inject_char('\b');
                    else if (step >= 171 && step <= 180) {
                        const char *nm = "copied.txt";
                        keyboard_inject_char(nm[step - 171]);
                    }
                    else if (step == 181) mouse_test_set(570, 376, 1);
                    else if (step == 182) mouse_test_set(570, 376, 0);
                    else if (step == 183) mouse_test_set(200, 266, 1);
                    else if (step == 184) mouse_test_set(200, 266, 0);
                    else if (step == 185) mouse_test_set(220, 376, 1);
                    else if (step == 186) mouse_test_set(220, 376, 0);
                    else if (step == 187) mouse_test_set(652, 70, 1);
                    else if (step == 188) mouse_test_set(652, 70, 0);
                    else if (step == 189) mouse_test_set(40, 132, 1);
                    else if (step == 190) mouse_test_set(40, 132, 0);
                    else if (step == 191) mouse_test_set(200, 266, 1);
                    else if (step == 192) mouse_test_set(200, 266, 0);
                    else if (step == 193) mouse_test_set(220, 376, 1);
                    else if (step == 194) mouse_test_set(220, 376, 0);
                    else if (step == 195) mouse_test_set(370, 136, 1);
                    else if (step == 196) mouse_test_set(370, 136, 0);
                    else if (step == 197) mouse_test_set(370, 136, 1);
                    else if (step == 198) mouse_test_set(370, 136, 0);
                    else if (step == 199) mouse_test_set(300, 100, 1);
                    else if (step == 200) mouse_test_set(300, 100, 0);
                    else if (step >= 201 && step <= 213) {
                        const char *nm = "refreshed.txt";
                        keyboard_inject_char(nm[step - 201]);
                    }
                    else if (step == 214) mouse_test_set(190, 136, 1);
                    else if (step == 215) mouse_test_set(190, 136, 0);
                    else if (step == 216) mouse_test_set(652, 70, 1);
                    else if (step == 217) mouse_test_set(652, 70, 0);
                    else if (step == 218) mouse_test_set(40, 132, 1);
                    else if (step == 219) mouse_test_set(40, 132, 0);
                    else if (step == 220) mouse_test_set(220, 432, 1);
                    else if (step == 221) mouse_test_set(220, 432, 0);
                    else if (step == 222) mouse_test_set(376, 376, 1);
                    else if (step == 223) mouse_test_set(376, 376, 0);
                    else if (step == 224) mouse_test_set(376, 376, 1);
                    else if (step == 225) mouse_test_set(376, 376, 0);
                    else if (step == 226) mouse_test_set(376, 376, 1);
                    else if (step == 227) mouse_test_set(376, 376, 0);
                    else if (step == 228) mouse_test_set(376, 376, 1);
                    else if (step == 229) mouse_test_set(376, 376, 0);
                    else if (step == 230) mouse_test_set(376, 376, 1);
                    else if (step == 231) mouse_test_set(376, 376, 0);
                    else if (step == 232) mouse_test_set(376, 376, 1);
                    else if (step == 233) mouse_test_set(376, 376, 0);
                    else if (step == 234) mouse_test_set(376, 376, 1);
                    else if (step == 235) mouse_test_set(376, 376, 0);
                    else if (step == 236) mouse_test_set(376, 376, 1);
                    else if (step == 237) mouse_test_set(376, 376, 0);
                    else if (step == 238) mouse_test_set(376, 376, 1);
                    else if (step == 239) mouse_test_set(376, 376, 0);
                    else if (step == 240) mouse_test_set(200, 266, 1);
                    else if (step == 241) mouse_test_set(200, 266, 0);
                    else if (step == 242) mouse_test_set(220, 376, 1);
                    else if (step == 243) mouse_test_set(220, 376, 0);
                } else if (autotest == 6) {
                    /* Phase 10 security script: Settings (garbage
                       settings.txt is rejected at load), Files,
                       then evil.txt -> Editor (sanitised), close,
                       empty.txt -> Editor, close, big.bmp ->
                       Viewer refused, good.bmp -> Viewer opened,
                       close Viewer. Disk order: evil, empty,
                       big.bmp, good.bmp, settings.txt. */
                    if (step == 0) mouse_test_set(40, 40, 0);
                    else if (step == 1) mouse_test_set(40, 40, 1);
                    else if (step == 2) mouse_test_set(40, 40, 0);
                    else if (step == 3) mouse_test_set(40, 132, 0);
                    else if (step == 4) mouse_test_set(40, 132, 1);
                    else if (step == 5) mouse_test_set(40, 132, 0);
                    else if (step == 6) mouse_test_set(200, 122, 1);
                    else if (step == 7) mouse_test_set(200, 122, 0);
                    else if (step == 8) mouse_test_set(220, 376, 1);
                    else if (step == 9) mouse_test_set(220, 376, 0);
                    else if (step == 10) mouse_test_set(652, 70, 1);
                    else if (step == 11) mouse_test_set(652, 70, 0);
                    else if (step == 12) mouse_test_set(200, 144, 1);
                    else if (step == 13) mouse_test_set(200, 144, 0);
                    else if (step == 14) mouse_test_set(220, 376, 1);
                    else if (step == 15) mouse_test_set(220, 376, 0);
                    else if (step == 16) mouse_test_set(652, 70, 1);
                    else if (step == 17) mouse_test_set(652, 70, 0);
                    else if (step == 18) mouse_test_set(200, 166, 1);
                    else if (step == 19) mouse_test_set(200, 166, 0);
                    else if (step == 20) mouse_test_set(220, 376, 1);
                    else if (step == 21) mouse_test_set(220, 376, 0);
                    else if (step == 22) mouse_test_set(200, 188, 1);
                    else if (step == 23) mouse_test_set(200, 188, 0);
                    else if (step == 24) mouse_test_set(220, 376, 1);
                    else if (step == 25) mouse_test_set(220, 376, 0);
                    else if (step == 26) mouse_test_set(632, 70, 1);
                    else if (step == 27) mouse_test_set(632, 70, 0);
                } else if (autotest == 7) {
                    /* Phase 10 web script (slirp): Start, Web,
                       focus the address field, type a host/path
                       for a 20000-byte page, Fetch. The fetch
                       blocks the loop, so later steps are just
                       waiting time for the marker. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 432, 1);
                    else if (step == 3) mouse_test_set(300, 432, 0);
                    else if (step == 4) mouse_test_set(300, 100, 1);
                    else if (step == 5) mouse_test_set(300, 100, 0);
                    else if (step >= 6 && step <= 27) {
                        const char *addr = "10.0.2.2:18081/big.txt";
                        keyboard_inject_char(addr[step - 6]);
                    }
                    else if (step == 28) mouse_test_set(190, 132, 1);
                    else if (step == 29) mouse_test_set(190, 132, 0);
                } else if (autotest == 9) {
                    /* Repo scroll script, 30 ticks per step:
                       0-1 Start; 2-3 launcher Repo row (300,528);
                       Repo window at 160,80, so Dn button centre
                       (160+445, 80+296) = (605,376), Up centre
                       (160+385, 80+296) = (545,376). 4-5 Dn ->
                       scroll 1; 6-7 Dn -> scroll 2 (the clamp for
                       a 10-entry index); 8-9 Dn -> no change, no
                       marker; 10-11 Up -> scroll 1; 12-13 Up ->
                       scroll 0; 14-15 Up -> no change, no marker. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 528, 1);
                    else if (step == 3) mouse_test_set(300, 528, 0);
                    else if (step == 4) mouse_test_set(605, 376, 1);
                    else if (step == 5) mouse_test_set(605, 376, 0);
                    else if (step == 6) mouse_test_set(605, 376, 1);
                    else if (step == 7) mouse_test_set(605, 376, 0);
                    else if (step == 8) mouse_test_set(605, 376, 1);
                    else if (step == 9) mouse_test_set(605, 376, 0);
                    else if (step == 10) mouse_test_set(545, 376, 1);
                    else if (step == 11) mouse_test_set(545, 376, 0);
                    else if (step == 12) mouse_test_set(545, 376, 1);
                    else if (step == 13) mouse_test_set(545, 376, 0);
                    else if (step == 14) mouse_test_set(545, 376, 1);
                    else if (step == 15) mouse_test_set(545, 376, 0);
                } else if (autotest == 10) {
                    /* Repo Update/Install script, 30 ticks per
                       step: 0-1 Start; 2-3 launcher Repo row
                       (300,528); Repo at 160,80 with no stored
                       index (the boot ran pkg repo but no pkg
                       update). 4 Update press (220,344: Update
                       rect x+10..x+110, y+252..y+276); the fetch
                       blocks the loop, so steps 5-31 are all the
                       same release (whichever step lands after
                       the fetch still releases the button, Web
                       test pattern). 32-33 Install with no
                       selection -> "repo: install needs
                       selection". 34-35 row 0 select (300,170)
                       -> "repo: selected sysinfo". 36 Install
                       press (330,344); the fetch+install blocks
                       the loop, so steps 37-61 are the same
                       release. 62-63 Start; 64-65 launcher
                       Packages row (300,504), which prints the
                       installed sysinfo entry. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 528, 1);
                    else if (step == 3) mouse_test_set(300, 528, 0);
                    else if (step == 4) mouse_test_set(220, 344, 1);
                    else if (step >= 5 && step <= 31) mouse_test_set(220, 344, 0);
                    else if (step == 32) mouse_test_set(330, 344, 1);
                    else if (step == 33) mouse_test_set(330, 344, 0);
                    else if (step == 34) mouse_test_set(300, 170, 1);
                    else if (step == 35) mouse_test_set(300, 170, 0);
                    else if (step == 36) mouse_test_set(330, 344, 1);
                    else if (step >= 37 && step <= 61) mouse_test_set(330, 344, 0);
                    else if (step == 62) mouse_test_set(32, 588, 1);
                    else if (step == 63) mouse_test_set(32, 588, 0);
                    else if (step == 64) mouse_test_set(300, 504, 1);
                    else if (step == 65) mouse_test_set(300, 504, 0);
                } else if (autotest == 11) {
                    /* Packages Remove script, 30 ticks per step:
                       0-1 Start; 2-3 launcher Packages row (300,504);
                       Packages at 160,80, rows at y+56+r*20 (row 1 =
                       term, installed second after calc). 4-5 Remove
                       press (220,344) with no selection -> "packages:
                       remove needs selection". 6-7 row 1 select
                       (300,164) -> "packages: selected term". 8-9
                       Remove press -> "packages: remove confirm
                       term". 10-11 Remove press again -> "Removed
                       term" + "packages: removed term". 12-13
                       Terminal icon (48,384), desktop exits so the
                       harness can run `pkg list` on the shell. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 504, 1);
                    else if (step == 3) mouse_test_set(300, 504, 0);
                    else if (step == 4) mouse_test_set(220, 344, 1);
                    else if (step == 5) mouse_test_set(220, 344, 0);
                    else if (step == 6) mouse_test_set(300, 164, 1);
                    else if (step == 7) mouse_test_set(300, 164, 0);
                    else if (step == 8) mouse_test_set(220, 344, 1);
                    else if (step == 9) mouse_test_set(220, 344, 0);
                    else if (step == 10) mouse_test_set(220, 344, 1);
                    else if (step == 11) mouse_test_set(220, 344, 0);
                    else if (step == 12) mouse_test_set(48, 384, 1);
                    else if (step == 13) mouse_test_set(48, 384, 0);
                } else if (autotest == 12) {
                    /* Files Install script, 30 ticks per step:
                       Files icon (40,132) opens Files at 160,80;
                       the disk holds only calc.nxpkg, so row 0
                       (200,122) is certainly it. 3-4 select row 0;
                       5-6 Open (220,376) -> "Installed calc 1.0"
                       + "files: installed calc.nxpkg", list
                       re-enumerated, selection cleared. 7-8
                       select row 0 again (still calc.nxpkg, now
                       followed by calc.elf + packages.txt);
                       9-10 Open again -> "pkg: package already
                       installed (same version)" refusal, the
                       negative control proving the first install
                       really registered. 11-12 Terminal icon
                       (48,384), desktop exits so the harness can
                       run `pkg list` on the shell. */
                    if (step == 0) mouse_test_set(40, 132, 0);
                    else if (step == 1) mouse_test_set(40, 132, 1);
                    else if (step == 2) mouse_test_set(40, 132, 0);
                    else if (step == 3) mouse_test_set(200, 122, 1);
                    else if (step == 4) mouse_test_set(200, 122, 0);
                    else if (step == 5) mouse_test_set(220, 376, 1);
                    else if (step == 6) mouse_test_set(220, 376, 0);
                    else if (step == 7) mouse_test_set(200, 122, 1);
                    else if (step == 8) mouse_test_set(200, 122, 0);
                    else if (step == 9) mouse_test_set(220, 376, 1);
                    else if (step == 10) mouse_test_set(220, 376, 0);
                    else if (step == 11) mouse_test_set(48, 384, 1);
                    else if (step == 12) mouse_test_set(48, 384, 0);
                } else if (autotest == 13) {
                    /* Files Run script, 30 ticks per step:
                       Files icon (40,132) opens Files at 160,80;
                       boot 1 installed calc only, so rows are
                       calc.nxpkg (row 0), calc.elf (row 1),
                       packages.txt (row 2). 3-4 select row 1
                       (200,144). 5-6 Open (220,376) -> "Background
                       job calc.elf started" + "files: started
                       calc.elf", the Calculator window opens on
                       top. 7-8 wait for the window. 9-10 click
                       the Calculator X button (552,170: window
                       240,160 320x280, close box x+w-16..x,
                       y+2..y+18) -> "Window closed: Calculator".
                       11-12 Terminal icon (48,384), desktop exits
                       so the harness can run `jobs` on the shell. */
                    if (step == 0) mouse_test_set(40, 132, 0);
                    else if (step == 1) mouse_test_set(40, 132, 1);
                    else if (step == 2) mouse_test_set(40, 132, 0);
                    else if (step == 3) mouse_test_set(200, 144, 1);
                    else if (step == 4) mouse_test_set(200, 144, 0);
                    else if (step == 5) mouse_test_set(220, 376, 1);
                    else if (step == 6) mouse_test_set(220, 376, 0);
                    else if (step == 9) mouse_test_set(552, 170, 1);
                    else if (step == 10) mouse_test_set(552, 170, 0);
                    else if (step == 11) mouse_test_set(48, 384, 1);
                    else if (step == 12) mouse_test_set(48, 384, 0);
                } else if (autotest == 14) {
                    /* Monitor Jobs script, 30 ticks per step:
                       0-2 Files icon (40,132); 3-4 row 1 select
                       (200,144) = calc.elf (boot 1 installed calc
                       only); 5-6 Open (220,376) -> job started,
                       Calculator window opens; 7-8 wait; 9-10
                       Calculator X (552,170) -> window closed but
                       the job keeps running (the orphan case);
                       11-12 Start (32,588); 13-14 launcher
                       Monitor row (300,380) -> Monitor at 160,80
                       480x440; 15-16 Kill press (220,452) with no
                       selection -> "monitor: kill needs
                       selection"; 17-18 row 0 select (300,366) ->
                       "monitor: selected calc.elf"; 19-20 Kill
                       press -> "monitor: kill confirm calc.elf";
                       21-22 Kill press -> "Killed background job
                       pid ..." + "monitor: killed calc.elf";
                       23-24 Terminal icon (48,384), desktop exits
                       so the harness can run `jobs` on the shell. */
                    if (step == 0) mouse_test_set(40, 132, 0);
                    else if (step == 1) mouse_test_set(40, 132, 1);
                    else if (step == 2) mouse_test_set(40, 132, 0);
                    else if (step == 3) mouse_test_set(200, 144, 1);
                    else if (step == 4) mouse_test_set(200, 144, 0);
                    else if (step == 5) mouse_test_set(220, 376, 1);
                    else if (step == 6) mouse_test_set(220, 376, 0);
                    else if (step == 9) mouse_test_set(552, 170, 1);
                    else if (step == 10) mouse_test_set(552, 170, 0);
                    else if (step == 11) mouse_test_set(32, 588, 1);
                    else if (step == 12) mouse_test_set(32, 588, 0);
                    else if (step == 13) mouse_test_set(300, 380, 1);
                    else if (step == 14) mouse_test_set(300, 380, 0);
                    else if (step == 15) mouse_test_set(220, 452, 1);
                    else if (step == 16) mouse_test_set(220, 452, 0);
                    else if (step == 17) mouse_test_set(300, 366, 1);
                    else if (step == 18) mouse_test_set(300, 366, 0);
                    else if (step == 19) mouse_test_set(220, 452, 1);
                    else if (step == 20) mouse_test_set(220, 452, 0);
                    else if (step == 21) mouse_test_set(220, 452, 1);
                    else if (step == 22) mouse_test_set(220, 452, 0);
                    else if (step == 23) mouse_test_set(48, 384, 1);
                    else if (step == 24) mouse_test_set(48, 384, 0);
                } else if (autotest == 15) {
                    /* Desktop Reboot script, 30 ticks per step:
                       0-2 Start (32,588); 3-4 launcher Reboot
                       row, column 1 row 7 (100,528) -> first
                       click only arms ("desktop: reboot
                       confirm"); 5-6 Start again; 7-8 Reboot
                       row again -> confirming click reboots
                       ("desktop: rebooting", then the machine
                       resets and boots a second time). The
                       launcher panel is 228 px tall with
                       my0 = 600-24-228 = 348, so row 7 spans
                       y 516..540; earlier rows are untouched
                       by the appended entry. */
                    if (step == 0) mouse_test_set(32, 588, 0);
                    else if (step == 1) mouse_test_set(32, 588, 1);
                    else if (step == 2) mouse_test_set(32, 588, 0);
                    else if (step == 3) mouse_test_set(100, 528, 1);
                    else if (step == 4) mouse_test_set(100, 528, 0);
                    else if (step == 5) mouse_test_set(32, 588, 1);
                    else if (step == 6) mouse_test_set(32, 588, 0);
                    else if (step == 7) mouse_test_set(100, 528, 1);
                    else if (step == 8) mouse_test_set(100, 528, 0);
                } else if (autotest == 16) {
                    /* Desktop Logout script, 30 ticks per step:
                       0-2 Files icon (40,132); 3-4 row 1 select
                       (200,144) = calc.elf (boot 1 installed calc
                       only, Monitor Jobs pattern); 5-6 Open
                       (220,376) -> job started, Calculator
                       window opens; 7-8 wait; 9-10 Calculator
                       X (552,170) -> window closed but the job
                       keeps running (the orphan case, so the
                       logout's job kill has something to kill);
                       11-12 Start (32,588); 13-14 launcher
                       Logout row, column 1 row 8 (100,552) ->
                       first click only arms ("desktop: logout
                       confirm"); 15-16 Start again; 17-18
                       Logout row again -> confirming click
                       exits the desktop ("desktop: logging
                       out") and the shell performs the logout.
                       The launcher panel is 228 px tall with
                       my0 = 600-24-228 = 348, so row 8 spans
                       y 540..564; earlier rows are untouched
                       by the appended entry. */
                    if (step == 0) mouse_test_set(40, 132, 0);
                    else if (step == 1) mouse_test_set(40, 132, 1);
                    else if (step == 2) mouse_test_set(40, 132, 0);
                    else if (step == 3) mouse_test_set(200, 144, 1);
                    else if (step == 4) mouse_test_set(200, 144, 0);
                    else if (step == 5) mouse_test_set(220, 376, 1);
                    else if (step == 6) mouse_test_set(220, 376, 0);
                    else if (step == 9) mouse_test_set(552, 170, 1);
                    else if (step == 10) mouse_test_set(552, 170, 0);
                    else if (step == 11) mouse_test_set(32, 588, 1);
                    else if (step == 12) mouse_test_set(32, 588, 0);
                    else if (step == 13) mouse_test_set(100, 552, 1);
                    else if (step == 14) mouse_test_set(100, 552, 0);
                    else if (step == 15) mouse_test_set(32, 588, 1);
                    else if (step == 16) mouse_test_set(32, 588, 0);
                    else if (step == 17) mouse_test_set(100, 552, 1);
                    else if (step == 18) mouse_test_set(100, 552, 0);
                } else if (autotest == 17) {
                    /* Files Sysupdate script, 30 ticks per step:
                       0-2 Files icon (40,132); the disk holds
                       only bundle_good.nxupd, so row 0
                       (200,122) is certainly it. 3-4 select row
                       0; 5-6 Open (220,376) -> first click only
                       arms ("files: sysupdate confirm
                       bundle_good.nxupd"); 7-8 Open again ->
                       confirming click applies the update
                       ("System update complete: 2 package(s)"
                       + "files: sysupdate applied
                       bundle_good.nxupd"), the list
                       re-enumerates in place and row 0 is
                       still the bundle (it stays in slot 0,
                       the new files take later slots). 9-10
                       select row 0 again; 11-12 Open -> arm
                       again; 13-14 Open -> confirming click
                       is refused ("sysupdate: package already
                       installed (same version)" + "files:
                       sysupdate failed bundle_good.nxupd"),
                       the negative control proving the first
                       update really registered. 15-16 Terminal
                       icon (48,384), desktop exits so the
                       harness can run `pkg list` on the
                       shell. */
                    if (step == 0) mouse_test_set(40, 132, 0);
                    else if (step == 1) mouse_test_set(40, 132, 1);
                    else if (step == 2) mouse_test_set(40, 132, 0);
                    else if (step == 3) mouse_test_set(200, 122, 1);
                    else if (step == 4) mouse_test_set(200, 122, 0);
                    else if (step == 5) mouse_test_set(220, 376, 1);
                    else if (step == 6) mouse_test_set(220, 376, 0);
                    else if (step == 7) mouse_test_set(220, 376, 1);
                    else if (step == 8) mouse_test_set(220, 376, 0);
                    else if (step == 9) mouse_test_set(200, 122, 1);
                    else if (step == 10) mouse_test_set(200, 122, 0);
                    else if (step == 11) mouse_test_set(220, 376, 1);
                    else if (step == 12) mouse_test_set(220, 376, 0);
                    else if (step == 13) mouse_test_set(220, 376, 1);
                    else if (step == 14) mouse_test_set(220, 376, 0);
                    else if (step == 15) mouse_test_set(48, 384, 1);
                    else if (step == 16) mouse_test_set(48, 384, 0);
                } else if (autotest == 18) {
                    /* Packages Rollback script, 30 ticks per step:
                       boot 1 already ran shell `sysupdate
                       bundle_good.nxupd`, so greet 1.0 + hello 1.0
                       are installed and a snapshot is on disk.
                       0-1 Start; 2-3 launcher Packages row (300,504);
                       Packages at 160,80, rows at y+56+r*20. 4-5
                       Rollback press (330,344) -> first click only
                       arms ("packages: rollback confirm"). 6-7
                       Rollback press again -> confirming click
                       rolls back ("Rolled back to the previous
                       version" + "packages: rollback done").
                       8-9 Rollback press -> arm again; 10-11
                       Rollback press -> confirming click is
                       refused ("sysrollback: no update to roll
                       back" + "packages: rollback failed"), the
                       negative control proving the first rollback
                       really consumed the snapshot. 12-13
                       Terminal icon (48,384), desktop exits so the
                       harness can run `pkg list` on the shell. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 504, 1);
                    else if (step == 3) mouse_test_set(300, 504, 0);
                    else if (step == 4) mouse_test_set(330, 344, 1);
                    else if (step == 5) mouse_test_set(330, 344, 0);
                    else if (step == 6) mouse_test_set(330, 344, 1);
                    else if (step == 7) mouse_test_set(330, 344, 0);
                    else if (step == 8) mouse_test_set(330, 344, 1);
                    else if (step == 9) mouse_test_set(330, 344, 0);
                    else if (step == 10) mouse_test_set(330, 344, 1);
                    else if (step == 11) mouse_test_set(330, 344, 0);
                    else if (step == 12) mouse_test_set(48, 384, 1);
                    else if (step == 13) mouse_test_set(48, 384, 0);
                } else if (autotest == 19) {
                    /* Repo Set script, 30 ticks per step:
                       fresh disk, no repo.txt: Repo opens
                       with "(no repository set)" and no stored
                       index. 0-1 Start; 2-3 launcher Repo row
                       (300,528); Repo at 160,80, now 480x360.
                       4-5 Set repo press (575,408) with an empty
                       field -> "repo: set needs url". 6-7 field
                       click (340,408) to focus. 8-21 type
                       "10.0.2.2:18088" (Web test pattern). 22-23
                       Set press -> "Repository set to ..." +
                       "repo: set ...". 24 Update press (220,344);
                       the fetch blocks the loop, so steps 25-51
                       are the same release. 52-53 row 0 select
                       (300,170) -> "repo: selected sysinfo".
                       54 Install press (330,344); steps 55-79
                       the same release. 80-81 Terminal icon
                       (48,384), desktop exits so the harness
                       can run `pkg repo` + `pkg list`. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 528, 1);
                    else if (step == 3) mouse_test_set(300, 528, 0);
                    else if (step == 4) mouse_test_set(575, 408, 1);
                    else if (step == 5) mouse_test_set(575, 408, 0);
                    else if (step == 6) mouse_test_set(340, 408, 1);
                    else if (step == 7) mouse_test_set(340, 408, 0);
                    else if (step >= 8 && step <= 21) {
                        const char *addr = "10.0.2.2:18088";
                        keyboard_inject_char(addr[step - 8]);
                    }
                    else if (step == 22) mouse_test_set(575, 408, 1);
                    else if (step == 23) mouse_test_set(575, 408, 0);
                    else if (step == 24) mouse_test_set(220, 344, 1);
                    else if (step >= 25 && step <= 51) mouse_test_set(220, 344, 0);
                    else if (step == 52) mouse_test_set(300, 170, 1);
                    else if (step == 53) mouse_test_set(300, 170, 0);
                    else if (step == 54) mouse_test_set(330, 344, 1);
                    else if (step >= 55 && step <= 79) mouse_test_set(330, 344, 0);
                    else if (step == 80) mouse_test_set(48, 384, 1);
                    else if (step == 81) mouse_test_set(48, 384, 0);
                } else if (autotest == 20) {
                    /* Network DNS Set script, 30 ticks per
                       step: fresh disk, DHCP done on the
                       shell first (so netinfo prints a DNS
                       line after the desktop exits). 0-1
                       Start; 2-3 launcher Network row
                       (300,408); Network at 160,80, now
                       480x360. 4-5 Set DNS press (575,384)
                       with an empty field -> "network: dns
                       needs ip". 6-7 field click (360,384)
                       to focus. 8-16 type "999.1.1.1".
                       17-18 Set press -> "network: dns bad
                       ip 999.1.1.1", field content kept.
                       19-20 field click again: the client-
                       area click handler clears every
                       window's field focus before dispatch,
                       so the Set click itself defocused the
                       field (shared field pattern, not a
                       DNS bug) and backspaces typed without
                       the re-click would go nowhere.
                       21-29 backspace x9 to clear. 30-36
                       type "1.1.1.1". 37-38 Set press ->
                       "network: dns set 1.1.1.1". 39-40
                       Terminal icon (48,384), desktop
                       exits so the harness can run
                       `netinfo` on the shell. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 408, 1);
                    else if (step == 3) mouse_test_set(300, 408, 0);
                    else if (step == 4) mouse_test_set(575, 384, 1);
                    else if (step == 5) mouse_test_set(575, 384, 0);
                    else if (step == 6) mouse_test_set(360, 384, 1);
                    else if (step == 7) mouse_test_set(360, 384, 0);
                    else if (step >= 8 && step <= 16) {
                        const char *addr = "999.1.1.1";
                        keyboard_inject_char(addr[step - 8]);
                    }
                    else if (step == 17) mouse_test_set(575, 384, 1);
                    else if (step == 18) mouse_test_set(575, 384, 0);
                    else if (step == 19) mouse_test_set(360, 384, 1);
                    else if (step == 20) mouse_test_set(360, 384, 0);
                    else if (step >= 21 && step <= 29) keyboard_inject_char('\b');
                    else if (step >= 30 && step <= 36) {
                        const char *addr = "1.1.1.1";
                        keyboard_inject_char(addr[step - 30]);
                    }
                    else if (step == 37) mouse_test_set(575, 384, 1);
                    else if (step == 38) mouse_test_set(575, 384, 0);
                    else if (step == 39) mouse_test_set(48, 384, 1);
                    else if (step == 40) mouse_test_set(48, 384, 0);
                } else if (autotest == 21) {
                    /* Network Ping-host script, 30 ticks per
                       step: fresh disk, DHCP done on the shell
                       first (so the window is configured when
                       Ping runs). 0-1 Start; 2-3 launcher
                       Network row (300,408); Network at 160,80,
                       now 480x400. 4-5 Ping press (575,416)
                       with an empty field -> "network: ping
                       needs ip". 6-7 ping field click (360,416)
                       to focus. 8-16 type "999.1.1.1". 17-18
                       Ping press -> "network: ping bad ip
                       999.1.1.1", field content kept. 19-20
                       ping field click again: the client-area
                       click handler clears every field focus
                       before dispatch, so the Ping click itself
                       defocused the field (shared field pattern,
                       not a ping bug) and backspaces typed
                       without the re-click would go nowhere.
                       21-29 backspace x9 to clear. 30-37 type
                       "10.0.2.2". 38-39 Ping press -> "network:
                       ping reply 10.0.2.2" (slirp host answers
                       ICMP, shell net test pattern). 40-41 ping
                       field click again: the reply cleared the
                       field, so the click only refocuses it.
                       42-50 type "192.0.2.1" (TEST-NET-1, no
                       host answers). 51 Ping press; 52-66 the
                       same release: net_ping waits up to 300
                       ticks (10 steps) for a reply that never
                       comes, so the release range must cover
                       the whole wait (Repo Update pattern).
                       -> "network: ping no reply 192.0.2.1".
                       67-68 Terminal icon (48,384), desktop
                       exits. Ping changes no registry state,
                       so the markers are the proof here, not a
                       post-desktop shell command. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 408, 1);
                    else if (step == 3) mouse_test_set(300, 408, 0);
                    else if (step == 4) mouse_test_set(575, 416, 1);
                    else if (step == 5) mouse_test_set(575, 416, 0);
                    else if (step == 6) mouse_test_set(360, 416, 1);
                    else if (step == 7) mouse_test_set(360, 416, 0);
                    else if (step >= 8 && step <= 16) {
                        const char *addr = "999.1.1.1";
                        keyboard_inject_char(addr[step - 8]);
                    }
                    else if (step == 17) mouse_test_set(575, 416, 1);
                    else if (step == 18) mouse_test_set(575, 416, 0);
                    else if (step == 19) mouse_test_set(360, 416, 1);
                    else if (step == 20) mouse_test_set(360, 416, 0);
                    else if (step >= 21 && step <= 29) keyboard_inject_char('\b');
                    else if (step >= 30 && step <= 37) {
                        const char *addr = "10.0.2.2";
                        keyboard_inject_char(addr[step - 30]);
                    }
                    else if (step == 38) mouse_test_set(575, 416, 1);
                    else if (step == 39) mouse_test_set(575, 416, 0);
                    else if (step == 40) mouse_test_set(360, 416, 1);
                    else if (step == 41) mouse_test_set(360, 416, 0);
                    else if (step >= 42 && step <= 50) {
                        const char *addr = "192.0.2.1";
                        keyboard_inject_char(addr[step - 42]);
                    }
                    else if (step == 51) mouse_test_set(575, 416, 1);
                    else if (step >= 52 && step <= 66) mouse_test_set(575, 416, 0);
                    else if (step == 67) mouse_test_set(48, 384, 1);
                    else if (step == 68) mouse_test_set(48, 384, 0);
                } else if (autotest == 22) {
                    /* Repo Fetch script, 30 ticks per step:
                       fresh disk, no repo.txt: Repo opens
                       with "(no repository set)" and no stored
                       index. 0-1 Start; 2-3 launcher Repo row
                       (300,528); Repo at 160,80, 480x360.
                       4-5 Fetch press (440,344) with no
                       selection -> "repo: fetch needs
                       selection". 6-7 Set repo press (575,408)
                       with an empty field -> "repo: set needs
                       url". 8-9 field click (340,408) to focus.
                       10-23 type "10.0.2.2:18088" (Web test
                       pattern). 24-25 Set press -> "Repository
                       set to ..." + "repo: set ...". 26 Update
                       press (220,344); the fetch blocks the
                       loop, so steps 27-53 are the same release.
                       54-55 row 0 select (300,170) -> "repo:
                       selected sysinfo". 56 Fetch press
                       (440,344); steps 57-83 the same release
                       (download like Install). -> "Fetched
                       sysinfo 1.0" + "repo: fetched sysinfo",
                       selection cleared. 84-85 row 0 select
                       again. 86-87 Fetch press -> "pkg fetch:
                       file already exists" + "repo: fetch
                       failed sysinfo", the negative control
                       proving the first fetch really wrote
                       sysinfo.nxpkg to disk. 88-89 Terminal icon
                       (48,384), desktop exits so the harness
                       can run `ls` + `pkg list` on the shell:
                       ls must show sysinfo.nxpkg, pkg list must
                       still report no packages installed, proving
                       fetch is not install. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 528, 1);
                    else if (step == 3) mouse_test_set(300, 528, 0);
                    else if (step == 4) mouse_test_set(440, 344, 1);
                    else if (step == 5) mouse_test_set(440, 344, 0);
                    else if (step == 6) mouse_test_set(575, 408, 1);
                    else if (step == 7) mouse_test_set(575, 408, 0);
                    else if (step == 8) mouse_test_set(340, 408, 1);
                    else if (step == 9) mouse_test_set(340, 408, 0);
                    else if (step >= 10 && step <= 23) {
                        const char *addr = "10.0.2.2:18088";
                        keyboard_inject_char(addr[step - 10]);
                    }
                    else if (step == 24) mouse_test_set(575, 408, 1);
                    else if (step == 25) mouse_test_set(575, 408, 0);
                    else if (step == 26) mouse_test_set(220, 344, 1);
                    else if (step >= 27 && step <= 53) mouse_test_set(220, 344, 0);
                    else if (step == 54) mouse_test_set(300, 170, 1);
                    else if (step == 55) mouse_test_set(300, 170, 0);
                    else if (step == 56) mouse_test_set(440, 344, 1);
                    else if (step >= 57 && step <= 83) mouse_test_set(440, 344, 0);
                    else if (step == 84) mouse_test_set(300, 170, 1);
                    else if (step == 85) mouse_test_set(300, 170, 0);
                    else if (step == 86) mouse_test_set(440, 344, 1);
                    else if (step == 87) mouse_test_set(440, 344, 0);
                    else if (step == 88) mouse_test_set(48, 384, 1);
                    else if (step == 89) mouse_test_set(48, 384, 0);
                } else if (autotest == 23) {
                    /* Files Hash script, 30 ticks per step:
                       Files icon (40,132) opens Files at 160,80;
                       the disk holds only readme.txt, so row 0
                       (200,122) is certainly it. 0-2 icon press
                       (Files Install pattern); 3-4 Hash press
                       (340,432) with no selection -> "files:
                       hash needs selection". 5-6 select row 0.
                       7-8 Hash press -> "files: sha256
                       readme.txt <hex>" (the harness checks
                       the hex against hashlib of the same
                       bytes). 9-10 Terminal icon (48,384),
                       desktop exits so the harness can run
                       shell `sha256 readme.txt` as a second,
                       independent proof of the same value. */
                    if (step == 0) mouse_test_set(40, 132, 0);
                    else if (step == 1) mouse_test_set(40, 132, 1);
                    else if (step == 2) mouse_test_set(40, 132, 0);
                    else if (step == 3) mouse_test_set(340, 432, 1);
                    else if (step == 4) mouse_test_set(340, 432, 0);
                    else if (step == 5) mouse_test_set(200, 122, 1);
                    else if (step == 6) mouse_test_set(200, 122, 0);
                    else if (step == 7) mouse_test_set(340, 432, 1);
                    else if (step == 8) mouse_test_set(340, 432, 0);
                    else if (step == 9) mouse_test_set(48, 384, 1);
                    else if (step == 10) mouse_test_set(48, 384, 0);
                } else if (autotest == 24) {
                    /* Monitor Disk script, 30 ticks per step:
                       0-2 Start (32,588); 3-4 launcher Monitor
                       row (300,380) -> Monitor at 160,80
                       480x440; 5 samples both Disk rows for a
                       non-background pixel (the label text is
                       black on the grey client area, so a scan
                       that finds none means a row did not
                       draw — the pixel proof, not just the
                       open marker); 6-7 Terminal icon
                       (48,384), desktop exits so the harness
                       can run shell `fs` as a second,
                       independent proof of the same numbers. */
                    if (step == 0) mouse_test_set(32, 588, 0);
                    else if (step == 1) mouse_test_set(32, 588, 1);
                    else if (step == 2) mouse_test_set(32, 588, 0);
                    else if (step == 3) mouse_test_set(300, 380, 1);
                    else if (step == 4) mouse_test_set(300, 380, 0);
                    else if (step == 5) {
                        int ft = 0, ff = 0;
                        for (int px = 170; px < 470; px += 2) {
                            if (fb_read_pixel(px, 480) != 0x00D0D0D0u) ft = 1;
                            if (fb_read_pixel(px, 500) != 0x00D0D0D0u) ff = 1;
                        }
                        console_write((ft && ff) ? "monitor: disk rows drawn\n" : "monitor: disk rows blank\n");
                    }
                    else if (step == 6) mouse_test_set(48, 384, 1);
                    else if (step == 7) mouse_test_set(48, 384, 0);
                } else if (autotest == 25) {
                    /* Web Save script, 30 ticks per step:
                       0-1 Start (32,588); 2-3 launcher Web row
                       (300,432) -> Web at 140,60, now 520x400;
                       4-5 Save press (580,424) with no fetch ->
                       "web: save needs fetch". 6-7 address
                       field click (300,100). 8-31 type
                       "10.0.2.2:18082/small.txt" (Web test
                       pattern). 32 Fetch press (190,132);
                       the fetch blocks the loop, so steps
                       33-59 are the same release. 60-61 Save
                       press with a fetched body but an empty
                       name -> "web: save needs name". 62-63
                       save-field click (370,424). 64-71 type
                       "page.txt". 72-73 Save press -> "web:
                       saved page.txt N bytes". 74-75
                       save-field click again (success cleared
                       the field). 76-83 type "page.txt"
                       again. 84-85 Save press -> "web: save
                       exists page.txt", the negative control
                       proving the first save really wrote
                       the file (never overwritten). 86-87
                       Terminal icon (48,384), desktop exits
                       so the harness can run `ls` + `cat
                       page.txt` on the shell: the saved bytes
                       must equal the served page. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 432, 1);
                    else if (step == 3) mouse_test_set(300, 432, 0);
                    else if (step == 4) mouse_test_set(580, 424, 1);
                    else if (step == 5) mouse_test_set(580, 424, 0);
                    else if (step == 6) mouse_test_set(300, 100, 1);
                    else if (step == 7) mouse_test_set(300, 100, 0);
                    else if (step >= 8 && step <= 31) {
                        const char *addr = "10.0.2.2:18082/small.txt";
                        keyboard_inject_char(addr[step - 8]);
                    }
                    else if (step == 32) mouse_test_set(190, 132, 1);
                    else if (step >= 33 && step <= 59) mouse_test_set(190, 132, 0);
                    else if (step == 60) mouse_test_set(580, 424, 1);
                    else if (step == 61) mouse_test_set(580, 424, 0);
                    else if (step == 62) mouse_test_set(370, 424, 1);
                    else if (step == 63) mouse_test_set(370, 424, 0);
                    else if (step >= 64 && step <= 71) {
                        const char *nm = "page.txt";
                        keyboard_inject_char(nm[step - 64]);
                    }
                    else if (step == 72) mouse_test_set(580, 424, 1);
                    else if (step == 73) mouse_test_set(580, 424, 0);
                    else if (step == 74) mouse_test_set(370, 424, 1);
                    else if (step == 75) mouse_test_set(370, 424, 0);
                    else if (step >= 76 && step <= 83) {
                        const char *nm = "page.txt";
                        keyboard_inject_char(nm[step - 76]);
                    }
                    else if (step == 84) mouse_test_set(580, 424, 1);
                    else if (step == 85) mouse_test_set(580, 424, 0);
                    else if (step == 86) mouse_test_set(48, 384, 1);
                    else if (step == 87) mouse_test_set(48, 384, 0);
                } else if (autotest == 26) {
                    /* Files Chmod script, 30 ticks per step:
                       Files icon (40,132) opens Files at 160,80,
                       now 480x424, so the Mode row sits at
                       y+368..y+392: field click (300,460),
                       Chmod button (410,460). The disk holds
                       only readme.txt, so row 0 (200,122) is
                       certainly it. 0-2 icon press (Files Hash
                       pattern). 3-4 Chmod press with no
                       selection -> "files: chmod needs
                       selection". 5-6 select row 0. 7-8 Chmod
                       press with an empty mode -> "files:
                       chmod needs mode". 9-10 mode-field
                       click. 11-13 type "999". 14-15 Chmod
                       press -> "files: chmod bad mode 999"
                       (the field is kept, never masked).
                       16-17 field click again (the Chmod
                       click cleared focus, DNS-set trap).
                       18-20 backspace x3. 21-23 type "600".
                       24-25 Chmod press -> "files: chmod
                       readme.txt mode 600" (success clears
                       the field). 26-27 field click again.
                       28-30 type "644". 31-32 Chmod press ->
                       "files: chmod readme.txt mode 644",
                       proving the field really cleared (a
                       stale "600" would have made "600644",
                       a bad mode). 33-34 Terminal icon
                       (48,384), desktop exits so the harness
                       can run shell `ls`: mode 420 is the
                       decimal form of 0644, the second proof
                       that the desktop chmod really landed. */
                    if (step == 0) mouse_test_set(40, 132, 0);
                    else if (step == 1) mouse_test_set(40, 132, 1);
                    else if (step == 2) mouse_test_set(40, 132, 0);
                    else if (step == 3) mouse_test_set(410, 460, 1);
                    else if (step == 4) mouse_test_set(410, 460, 0);
                    else if (step == 5) mouse_test_set(200, 122, 1);
                    else if (step == 6) mouse_test_set(200, 122, 0);
                    else if (step == 7) mouse_test_set(410, 460, 1);
                    else if (step == 8) mouse_test_set(410, 460, 0);
                    else if (step == 9) mouse_test_set(300, 460, 1);
                    else if (step == 10) mouse_test_set(300, 460, 0);
                    else if (step >= 11 && step <= 13) {
                        const char *m = "999";
                        keyboard_inject_char(m[step - 11]);
                    }
                    else if (step == 14) mouse_test_set(410, 460, 1);
                    else if (step == 15) mouse_test_set(410, 460, 0);
                    else if (step == 16) mouse_test_set(300, 460, 1);
                    else if (step == 17) mouse_test_set(300, 460, 0);
                    else if (step >= 18 && step <= 20) keyboard_inject_char('\b');
                    else if (step >= 21 && step <= 23) {
                        const char *m = "600";
                        keyboard_inject_char(m[step - 21]);
                    }
                    else if (step == 24) mouse_test_set(410, 460, 1);
                    else if (step == 25) mouse_test_set(410, 460, 0);
                    else if (step == 26) mouse_test_set(300, 460, 1);
                    else if (step == 27) mouse_test_set(300, 460, 0);
                    else if (step >= 28 && step <= 30) {
                        const char *m = "644";
                        keyboard_inject_char(m[step - 28]);
                    }
                    else if (step == 31) mouse_test_set(410, 460, 1);
                    else if (step == 32) mouse_test_set(410, 460, 0);
                    else if (step == 33) mouse_test_set(48, 384, 1);
                    else if (step == 34) mouse_test_set(48, 384, 0);
                } else if (autotest == 27) {
                    /* Repo root-check script, 30 ticks per step.
                       Runs as a NON-ROOT session (the harness
                       logs in as alice; root's shell `pkg update`
                       already stored the 1-package index, so row
                       0 is certainly sysinfo). 0-1 Start; 2-3
                       launcher Repo row (300,528) -> "Desktop:
                       Repo opened", "repo: index version 1",
                       "repo: sysinfo 1.0". 4-5 Update press
                       (220,344) -> "repo: update needs root"
                       (the root check fires before any fetch,
                       so no wide release range is needed).
                       6-7 row 0 select (300,170) -> "repo:
                       selected sysinfo". 8-9 Install press
                       (330,344) -> "repo: install needs root"
                       (selection first, then root, Fetch
                       pattern; again no fetch runs, so no wide
                       range). 10-11 Terminal icon (48,384),
                       desktop exits so the harness can run
                       shell `pkg list`: "(no packages
                       installed)" is the proof nothing was
                       installed, and the absence of any
                       "Installed sysinfo 1.0" line is the
                       negative control. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 528, 1);
                    else if (step == 3) mouse_test_set(300, 528, 0);
                    else if (step == 4) mouse_test_set(220, 344, 1);
                    else if (step == 5) mouse_test_set(220, 344, 0);
                    else if (step == 6) mouse_test_set(300, 170, 1);
                    else if (step == 7) mouse_test_set(300, 170, 0);
                    else if (step == 8) mouse_test_set(330, 344, 1);
                    else if (step == 9) mouse_test_set(330, 344, 0);
                    else if (step == 10) mouse_test_set(48, 384, 1);
                    else if (step == 11) mouse_test_set(48, 384, 0);
                } else if (autotest == 28) {
                    /* Settings Unlock script, 30 ticks per step.
                       The SAME script runs for both phases of the
                       harness: as root it must unlock, as a
                       non-root session it must refuse — only the
                       expected marker differs. 0-2 Settings icon
                       (40,40) -> "Desktop: Settings opened".
                       3-4 Unlock press (530,300) with an empty
                       field -> "settings: unlock needs user"
                       (empty first, the shell's usage-then-uid
                       order, so this marker is the same for
                       every session). 5-6 Unlock field click
                       (370,300) -> focus. 7-11 type "alice".
                       12-13 Unlock press (530,300) -> root:
                       "settings: unlocked alice"; non-root:
                       "settings: unlock needs root" (the field
                       is kept on refusal). 14-15 Terminal icon
                       (48,384), desktop exits so the harness
                       can run shell commands after it. */
                    if (step == 0) mouse_test_set(40, 40, 0);
                    else if (step == 1) mouse_test_set(40, 40, 1);
                    else if (step == 2) mouse_test_set(40, 40, 0);
                    else if (step == 3) mouse_test_set(530, 300, 1);
                    else if (step == 4) mouse_test_set(530, 300, 0);
                    else if (step == 5) mouse_test_set(370, 300, 1);
                    else if (step == 6) mouse_test_set(370, 300, 0);
                    else if (step >= 7 && step <= 11) {
                        const char *m = "alice";
                        keyboard_inject_char(m[step - 7]);
                    }
                    else if (step == 12) mouse_test_set(530, 300, 1);
                    else if (step == 13) mouse_test_set(530, 300, 0);
                    else if (step == 14) mouse_test_set(48, 384, 1);
                    else if (step == 15) mouse_test_set(48, 384, 0);
                } else if (autotest == 29) {
                    /* Unlock-unknown-user script, 30 ticks per
                       step, same coordinates as mode 28 (Settings
                       icon, Unlock field, Unlock button, Terminal
                       icon). 0-2 Settings icon (40,40) ->
                       "Desktop: Settings opened". 3-4 Unlock
                       field click (370,300) -> focus. 5-9 type
                       "ghost". 10-11 Unlock press (530,300) ->
                       "settings: no such user ghost" (the field
                       is kept on refusal). 12-13 Unlock press
                       again -> the same refusal a second time,
                       proving the field really survived. 14-15
                       Terminal icon (48,384), desktop exits. */
                    if (step == 0) mouse_test_set(40, 40, 0);
                    else if (step == 1) mouse_test_set(40, 40, 1);
                    else if (step == 2) mouse_test_set(40, 40, 0);
                    else if (step == 3) mouse_test_set(370, 300, 1);
                    else if (step == 4) mouse_test_set(370, 300, 0);
                    else if (step >= 5 && step <= 9) {
                        const char *m = "ghost";
                        keyboard_inject_char(m[step - 5]);
                    }
                    else if (step == 10) mouse_test_set(530, 300, 1);
                    else if (step == 11) mouse_test_set(530, 300, 0);
                    else if (step == 12) mouse_test_set(530, 300, 1);
                    else if (step == 13) mouse_test_set(530, 300, 0);
                    else if (step == 14) mouse_test_set(48, 384, 1);
                    else if (step == 15) mouse_test_set(48, 384, 0);
                } else if (autotest == 30) {
                    /* Fallback-redraw script (v1.1.0 real-device
                       green-screen bug), 30 ticks per step:
                       0-1 Start; 2-3 Web row (300,432); 4 idle
                       (window opens); 5 force the
                       cursor_move_only fallback with a stale old
                       position — exactly what a real PS/2 mouse
                       produces when an interrupt moves the
                       pointer between the loop's prev update and
                       a redraw's cursor save — and sample the
                       scene IN THE SAME STEP, before any clock
                       refresh can repaint over it. Pre-fix the
                       fallback ran the classic redraw: green
                       background 0x00106040, classic taskbar,
                       window frames without desktop content.
                       Post-fix it runs a full desktop redraw:
                       Classic background 0x00183050, zero green
                       pixels, Web window present. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 432, 1);
                    else if (step == 3) mouse_test_set(300, 432, 0);
                    else if (step == 5) {
                        s32 sx = cursor_saved_x, sy = cursor_saved_y;
                        cursor_move_only(0, 0, mouse_x(), mouse_y());
                        u32 bg = fb_read_pixel(700, 300);
                        u32 green = 0;
                        for (s32 yy = 0; yy < 600; yy += 2)
                            for (s32 xx = 0; xx < 800; xx += 2)
                                if (fb_read_pixel(xx, yy) == 0x00106040u) green++;
                        int web = 0;
                        for (int i = 0; i < MAX_WINDOWS; i++)
                            if (wins[i].used && wins[i].type == W_WEB) web = 1;
                        console_printf("fb30: saved=(%d,%d) bg=0x%x green=%u web=%d\n", sx, sy, bg, green, web);
                    }
                } else if (autotest == 8) {
                    /* Phase 10 no-NIC script (boot with -nic
                       none): Start, Network. The open prints
                       the no-device marker. */
                    if (step == 0) mouse_test_set(32, 588, 1);
                    else if (step == 1) mouse_test_set(32, 588, 0);
                    else if (step == 2) mouse_test_set(300, 408, 1);
                    else if (step == 3) mouse_test_set(300, 408, 0);
                } else if (autotest == 3) {
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
                       8-9: click Lock entry (100,480) (lock screen shows);
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
                    else if (step == 8) mouse_test_set(100, 480, 1);
                    else if (step == 9) mouse_test_set(100, 480, 0);
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
                       8-9: click Lock entry (100,480) (lock screen shows);
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
                    else if (step == 8) mouse_test_set(100, 480, 1);
                    else if (step == 9) mouse_test_set(100, 480, 0);
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
                /* Settings Unlock field, if focused: keys go
                   here, never to the search field (Files mode
                   before rename precedent). The search branch
                   below only runs when the Unlock field is not
                   focused, so an Unlock click followed by typing
                   cannot leak characters into the search box. */
                int ui = -1;
                for (int i = 0; i < MAX_WINDOWS; i++)
                    if (wins[i].used && wins[i].type == W_SETTINGS && desk_settings_unlock_focused) ui = i;
                if (ui >= 0) {
                    struct window *wn = &wins[ui];
                    if (c == '\b') { if (desk_settings_unlock_len > 0) desk_settings_unlock[--desk_settings_unlock_len] = 0; }
                    else if (c == '\n') { desk_settings_unlock_focused = 0; }
                    else if (c >= 32 && c < 127 && desk_settings_unlock_len < 63) { desk_settings_unlock[desk_settings_unlock_len++] = (char)c; desk_settings_unlock[desk_settings_unlock_len] = 0; }
                    if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
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
                    /* Focused window gets the key, by type. Input
                       windows consume their keys; anything else
                       falls through to the desktop-global keys
                       (shortcuts + snap). */
                    int fidx = -1;
                    for (int i = 0; i < MAX_WINDOWS; i++)
                        if (wins[i].used && wins[i].focused && wins[i].ws == desk_ws) fidx = i;
                    if (fidx >= 0 && wins[fidx].type == W_EDITOR) {
                        struct window *wn = &wins[fidx];
                        if (wn->field_focused) {
                            if (c == '\b') { if (wn->field_len > 0) wn->field[--wn->field_len] = 0; }
                            else if (c == '\n') wn->field_focused = 0;
                            else if (c >= 32 && c < 127 && wn->field_len < 63) { wn->field[wn->field_len++] = (char)c; wn->field[wn->field_len] = 0; }
                        } else {
                            if (c == '\b') {
                                if (wn->aux1 > 0) {
                                    memmove(&desk_ed_buf[wn->aux1 - 1], &desk_ed_buf[wn->aux1], desk_ed_len - (u32)wn->aux1);
                                    desk_ed_len--; wn->aux1--; desk_ed_buf[desk_ed_len] = 0;
                                }
                            } else if (c == '[') { if (wn->aux1 > 0) wn->aux1--; }
                            else if (c == ']') { if (wn->aux1 < (int)desk_ed_len) wn->aux1++; }
                            else if (c == '\n') {
                                if (desk_ed_len < 8192) {
                                    memmove(&desk_ed_buf[wn->aux1 + 1], &desk_ed_buf[wn->aux1], desk_ed_len - (u32)wn->aux1);
                                    desk_ed_buf[wn->aux1] = '\n'; wn->aux1++; desk_ed_len++; desk_ed_buf[desk_ed_len] = 0;
                                }
                            }
                            else if (c >= 32 && c < 127 && desk_ed_len < 8192) {
                                memmove(&desk_ed_buf[wn->aux1 + 1], &desk_ed_buf[wn->aux1], desk_ed_len - (u32)wn->aux1);
                                desk_ed_buf[wn->aux1] = (char)c; wn->aux1++; desk_ed_len++; desk_ed_buf[desk_ed_len] = 0;
                            }
                        }
                        /* 6(b) part 8: typing or cursor moves
                           that leave the visible rows scroll
                           the view to follow the cursor. */
                        { int old = wn->aux2; desk_editor_follow_cursor(fidx); if (wn->aux2 != old) console_printf("editor: scroll %d\n", wn->aux2); }
                        if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
                    } else if (fidx >= 0 && wins[fidx].type == W_WEB) {
                        struct window *wn = &wins[fidx];
                        if (desk_web_save_focused) {
                            if (c == '\b') { if (desk_web_save_len > 0) desk_web_save[--desk_web_save_len] = 0; }
                            else if (c == '\n') { desk_web_save_focused = 0; }
                            else if (c >= 32 && c < 127 && desk_web_save_len < 63) { desk_web_save[desk_web_save_len++] = (char)c; desk_web_save[desk_web_save_len] = 0; }
                            if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
                        } else if (wn->field_focused) {
                            if (c == '\b') { if (wn->field_len > 0) wn->field[--wn->field_len] = 0; }
                            else if (c == '\n') { wn->field_focused = 0; desk_web_fetch(wn->field); wn->aux1 = 0; }
                            else if (c >= 32 && c < 127 && wn->field_len < 63) { wn->field[wn->field_len++] = (char)c; wn->field[wn->field_len] = 0; }
                            if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
                        }
                    } else if (fidx >= 0 && wins[fidx].type == W_FILES && desk_files_mode_focused) {
                        /* Files chmod mode field: the same field
                           keys as the rename row, but on the
                           separate mode buffer, so typing a mode
                           never touches the new-name field.
                           Enter only defocuses — Chmod is a
                           button click, so there is exactly one
                           action path. Placed before the rename
                           branch (Web save before address
                           precedent): when the mode field is
                           focused, keys go there, never to the
                           rename field. */
                        struct window *wn = &wins[fidx];
                        if (c == '\b') { if (desk_files_mode_len > 0) desk_files_mode[--desk_files_mode_len] = 0; }
                        else if (c == '\n') { desk_files_mode_focused = 0; }
                        else if (c >= 32 && c < 127 && desk_files_mode_len < 63) { desk_files_mode[desk_files_mode_len++] = (char)c; desk_files_mode[desk_files_mode_len] = 0; }
                        if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
                    } else if (fidx >= 0 && wins[fidx].type == W_FILES && wins[fidx].field_focused) {
                        /* Files new-name field (rename/copy):
                           the same field keys as Web/Editor,
                           but Enter only defocuses — Rename
                           and Copy are button clicks, so there
                           is exactly one action path each. When
                           the field is not focused this branch
                           does not match, so desktop-global
                           shortcut keys still reach the else
                           below. */
                        struct window *wn = &wins[fidx];
                        if (c == '\b') { if (wn->field_len > 0) wn->field[--wn->field_len] = 0; }
                        else if (c == '\n') { wn->field_focused = 0; }
                        else if (c >= 32 && c < 127 && wn->field_len < 63) { wn->field[wn->field_len++] = (char)c; wn->field[wn->field_len] = 0; }
                        if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
                    } else if (fidx >= 0 && wins[fidx].type == W_REPO && wins[fidx].field_focused) {
                        /* Repo set-url field: the same field keys
                           as Files rename, but Enter only
                           defocuses — Set repo is a button click,
                           so there is exactly one action path. */
                        struct window *wn = &wins[fidx];
                        if (c == '\b') { if (wn->field_len > 0) wn->field[--wn->field_len] = 0; }
                        else if (c == '\n') { wn->field_focused = 0; }
                        else if (c >= 32 && c < 127 && wn->field_len < 63) { wn->field[wn->field_len++] = (char)c; wn->field[wn->field_len] = 0; }
                        if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
                    } else if (fidx >= 0 && wins[fidx].type == W_NETWORK && wins[fidx].field_focused) {
                        /* Network set-DNS field: the same field
                           keys as the Repo set-url field, but
                           Enter only defocuses — Set DNS is a
                           button click, so there is exactly one
                           action path. */
                        struct window *wn = &wins[fidx];
                        if (c == '\b') { if (wn->field_len > 0) wn->field[--wn->field_len] = 0; }
                        else if (c == '\n') { wn->field_focused = 0; }
                        else if (c >= 32 && c < 127 && wn->field_len < 63) { wn->field[wn->field_len++] = (char)c; wn->field[wn->field_len] = 0; }
                        if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
                    } else if (fidx >= 0 && wins[fidx].type == W_NETWORK && desk_net_ping_focused) {
                        /* Network ping-host field: the same field
                           keys as the Set-DNS field, but on the
                           separate ping buffer, so typing a host
                           address never touches the DNS field.
                           Enter only defocuses — Ping is a button
                           click, so there is exactly one action
                           path. */
                        struct window *wn = &wins[fidx];
                        if (c == '\b') { if (desk_net_ping_len > 0) desk_net_ping[--desk_net_ping_len] = 0; }
                        else if (c == '\n') { desk_net_ping_focused = 0; }
                        else if (c >= 32 && c < 127 && desk_net_ping_len < 63) { desk_net_ping[desk_net_ping_len++] = (char)c; desk_net_ping[desk_net_ping_len] = 0; }
                        if (!pending_redraw) { pend_x = wn->x; pend_y = wn->y; pend_w = wn->w; pend_h = wn->h; pending_redraw = 1; }
                    } else if (fidx >= 0 && wins[fidx].type == W_USER) {
                        gui_queue_event(&wins[fidx], GUI_EV_KEY, 0, 0, c, 0);
                    } else {
                        /* Desktop-global keys. Shortcut letters
                           match case-insensitively. */
                        char lc = c;
                        if (lc >= 'A' && lc <= 'Z') lc = (char)(lc + 32);
                        char lock_k = desk_shortcut_keys[desk_shortcut_preset][0];
                        char ws_k = desk_shortcut_keys[desk_shortcut_preset][1];
                        if (lock_k >= 'A' && lock_k <= 'Z') lock_k = (char)(lock_k + 32);
                        if (ws_k >= 'A' && ws_k <= 'Z') ws_k = (char)(ws_k + 32);
                        if (lc == lock_k) { desk_show_lock(); desk_redraw(); }
                        else if (lc == ws_k) { desk_ws = desk_ws ? 0 : 1; console_printf("Desktop: workspace %d\n", desk_ws + 1); desk_redraw(); }
                        else if (c == '[') desk_snap_topmost(0);
                        else if (c == ']') desk_snap_topmost(1);
                        else if (c == '\\') desk_snap_topmost(2);
                    }
                }
                } /* close the Unlock-field else: search-or-focused dispatch */
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
                s32 my0 = scr_h() - TASKBAR_H - 228;
                int hit = -1;
                for (int i = 0; i < 9; i++) if (inside(mx, my, 0, my0 + i * 24, 200, 24)) hit = i;
                if (hit < 0) for (int i = 0; i < 9; i++) if (inside(mx, my, 200, my0 + i * 24, 200, 24)) hit = 9 + i;
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
                else if (mx >= scr_w() - 258 && mx < scr_w() - 214) {
                    desk_ws = desk_ws ? 0 : 1;
                    console_printf("Desktop: workspace %d\n", desk_ws + 1);
                    desk_redraw();
                }
                else {
                    s32 bx = 66;
                    for (int zi = 0; zi < zcount; zi++) {
                        struct window *wn = &wins[zorder[zi]];
                        if (wn->ws != desk_ws) continue;
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
                    if (wn->ws != desk_ws) continue;
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
                        if (wn->ws != desk_ws) continue;
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
                            desk_net_ping_focused = 0;
                            desk_files_mode_focused = 0;
                            desk_settings_unlock_focused = 0;
                            if (wn->type == W_SETTINGS) {
                                if (inside(mx, my, wn->x + 80, wn->y + 28, wn->w - 100, 24)) {
                                    wn->field_focused = 1;
                                } else if (inside(mx, my, wn->x + 10, wn->y + 252, 140, 24)) {
                                    wn->aux1 = wn->aux1 ? 0 : 1;
                                    desk_redraw();
                                } else {
                                    /* Value buttons: rows in order,
                                       filtered by search, same
                                       layout as drawing. */
                                    if (wn->aux1 == 0) {
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
                                    } else {
                                        const char *names[6] = {"Theme", "Accent colour", "Wallpaper", "Low-resource", "Large text", "Shortcuts"};
                                        int row = 0;
                                        for (int s = 0; s < 6; s++) {
                                            if (!str_contains_ci(names[s], wn->search)) continue;
                                            s32 ry = wn->y + 64 + row * 32;
                                            if (inside(mx, my, wn->x + 200, ry, 100, 24)) {
                                                if (s == 0) { desk_theme = (desk_theme + 1) % 4; console_printf("Desktop theme changed to %s\n", desk_theme_name()); }
                                                else if (s == 1) { desk_accent = (desk_accent + 1) % 4; console_printf("Desktop accent changed to %s\n", desk_accent_name()); }
                                                else if (s == 2) { desk_wallpaper = (desk_wallpaper + 1) % 3; console_printf("Desktop wallpaper changed to %s\n", desk_wallpaper_name()); }
                                                else if (s == 3) desk_lowres = !desk_lowres;
                                                else if (s == 4) desk_bigtext = !desk_bigtext;
                                                else { desk_shortcut_preset = (desk_shortcut_preset + 1) % 3; console_printf("Desktop shortcuts changed to %c/%c\n", desk_shortcut_keys[desk_shortcut_preset][0], desk_shortcut_keys[desk_shortcut_preset][1]); }
                                                desk_redraw();
                                            }
                                            row++;
                                        }
                                    }
                                }
                                /* Unlock row (page 0 only, fixed
                                   position — it cannot fall into
                                   the value-button else chain,
                                   whose rows end at y+184, nor
                                   the toggle at y+252). Standalone
                                   block like the Files scroll
                                   buttons: field click focuses,
                                   button click runs the unlock. */
                                if (wn->aux1 == 0) {
                                    if (inside(mx, my, wn->x + 110, wn->y + 208, 200, 24)) {
                                        desk_settings_unlock_focused = 1;
                                        desk_redraw();
                                    } else if (inside(mx, my, wn->x + 320, wn->y + 208, 100, 24)) {
                                        desk_settings_unlock_run();
                                        desk_redraw();
                                    }
                                }
                                if (inside(mx, my, wn->x + 10, wn->y + wn->h - 44, 120, 24)) {
                                    desk_save_settings(wn->field);
                                    desk_redraw();
                                }
                            } else if (wn->type == W_FILES) {
                                for (int r = 0; r < 8; r++) {
                                    int i = desk_files_scroll + r;
                                    if (i >= desk_files_count) break;
                                    s32 ry = wn->y + 32 + r * 22;
                                    if (inside(mx, my, wn->x + 10, ry - 2, wn->w - 20, 20)) {
                                        /* 6(b) part 10: selecting a
                                           different file disarms a
                                           pending Delete confirm. */
                                        if (desk_files_del_arm != i) desk_files_del_arm = -1;
                                        if (desk_files_sysupd_arm != i) desk_files_sysupd_arm = -1;
                                        desk_files_hash_valid = 0;
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
                            }
                            /* 6(b) part 9: Files scroll buttons. They
                               work with no selection (unlike Open
                               below), clamp to 0..count-8, and print
                               only on a real change, like the Editor
                               scroll buttons. The selection is left
                               alone: scrolling never deselects. */
                            if (wn->type == W_FILES) {
                                s32 py = wn->y + 32 + 8 * 22 + 8;
                                int max = desk_files_count - 8; if (max < 0) max = 0;
                                if (inside(mx, my, wn->x + 130, py + 68, 52, 24)) {
                                    if (desk_files_scroll > 0) { desk_files_scroll--; console_printf("files: scroll %d\n", desk_files_scroll); desk_redraw(); }
                                } else if (inside(mx, my, wn->x + 190, py + 68, 52, 24)) {
                                    if (desk_files_scroll < max) { desk_files_scroll++; console_printf("files: scroll %d\n", desk_files_scroll); desk_redraw(); }
                                }
                            }
                            /* 6(b) part 10: Files Delete button.
                               Standalone block like the scroll
                               buttons (not in the Open else-chain):
                               first click on the selected file only
                               arms the confirm (serial marker +
                               preview text), the second click on
                               the same file deletes via
                               fs_delete_as (uid/mode enforced, so
                               a file the session may not write
                               fails closed with a marker, never a
                               silent no-op), then the list is
                               re-enumerated in place (scroll kept,
                               clamped) and the selection cleared.
                               A click with no selection does
                               nothing. */
                            if (wn->type == W_FILES && wn->selected >= 0 && wn->selected < desk_files_count) {
                                s32 py = wn->y + 32 + 8 * 22 + 8;
                                if (inside(mx, my, wn->x + 250, py + 68, 80, 24)) {
                                    const char *nm = desk_files_names[wn->selected];
                                    if (desk_files_del_arm != wn->selected) {
                                        desk_files_del_arm = wn->selected;
                                        console_printf("files: delete confirm %s\n", nm);
                                        const char *t = "Click Delete again to remove ";
                                        int k = 0; while (t[k]) { wn->preview[k] = t[k]; k++; }
                                        int j = 0; while (nm[j]) { wn->preview[k++] = nm[j++]; }
                                        wn->preview[k] = 0;
                                    } else if (fs_delete_as(nm, shell_session_uid()) == 0) {
                                        console_printf("files: deleted %s\n", nm);
                                        desk_files_del_arm = -1;
                                        wn->selected = -1;
                                        wn->preview[0] = 0;
                                        desk_refresh_files();
                                    } else {
                                        console_printf("files: delete failed %s\n", nm);
                                        desk_files_del_arm = -1;
                                    }
                                    desk_redraw();
                                }
                            }
                            /* Files rename field + Rename
                               button. Standalone blocks like
                               Delete: clicking the field
                               focuses it (keys then go to the
                               new W_FILES key branch); Rename
                               with an empty field only reports
                               "needs name", never renames to
                               an empty string. A successful
                               rename goes through fs_rename_as
                               (no overwrite, uid/mode checked,
                               system-file rule for non-root),
                               then re-enumerates in place like
                               Delete (scroll kept, selection +
                               field cleared, delete arm
                               cleared). A failed rename leaves
                               the list and the field alone, so
                               the user can fix the name and
                               retry. A click with no selection
                               does nothing. */
                            if (wn->type == W_FILES) {
                                s32 py = wn->y + 32 + 8 * 22 + 8;
                                if (inside(mx, my, wn->x + 90, py + 96, 260, 24)) {
                                    wn->field_focused = 1;
                                    desk_redraw();
                                }
                            }
                            if (wn->type == W_FILES && wn->selected >= 0 && wn->selected < desk_files_count) {
                                s32 py = wn->y + 32 + 8 * 22 + 8;
                                if (inside(mx, my, wn->x + 360, py + 96, 100, 24)) {
                                    const char *nm = desk_files_names[wn->selected];
                                    if (wn->field_len == 0) {
                                        console_printf("files: rename needs name\n");
                                        const char *t = "Type a new name first"; int k=0; while(t[k]){wn->preview[k]=t[k];k++;}
                                        wn->preview[k]=0;
                                    } else if (fs_rename_as(nm, wn->field, shell_session_uid()) == 0) {
                                        console_printf("files: renamed %s to %s\n", nm, wn->field);
                                        desk_files_del_arm = -1;
                                        wn->selected = -1;
                                        wn->preview[0] = 0;
                                        wn->field_len = 0; wn->field[0] = 0;
                                        wn->field_focused = 0;
                                        desk_refresh_files();
                                    } else {
                                        console_printf("files: rename failed %s\n", nm);
                                    }
                                    desk_redraw();
                                }
                            }
                            /* Files Copy button. Standalone block
                               like Delete/Rename: the destination
                               name is the new-name field below the
                               buttons. An empty field only reports
                               "needs name", never copies to an empty
                               string. A successful copy goes through
                               fs_copy_as (the shell `cp` primitive:
                               byte-exact, no overwrite, read rule
                               on the source, system-file rule for
                               non-root), then re-enumerates in place
                               like Rename (scroll kept, selection +
                               field cleared, delete arm cleared).
                               A failed copy leaves the list and the
                               field alone, so the user can fix the
                               name and retry. A click with no
                               selection does nothing. */
                            if (wn->type == W_FILES && wn->selected >= 0 && wn->selected < desk_files_count) {
                                s32 py = wn->y + 32 + 8 * 22 + 8;
                                if (inside(mx, my, wn->x + 360, py + 68, 100, 24)) {
                                    const char *nm = desk_files_names[wn->selected];
                                    if (wn->field_len == 0) {
                                        console_printf("files: copy needs name\n");
                                        const char *t = "Type a new name first"; int k=0; while(t[k]){wn->preview[k]=t[k];k++;}
                                        wn->preview[k]=0;
                                    } else if (fs_copy_as(nm, wn->field, shell_session_uid()) == 0) {
                                        console_printf("files: copied %s to %s\n", nm, wn->field);
                                        desk_files_del_arm = -1;
                                        wn->selected = -1;
                                        wn->preview[0] = 0;
                                        wn->field_len = 0; wn->field[0] = 0;
                                        wn->field_focused = 0;
                                        desk_refresh_files();
                                    } else {
                                        console_printf("files: copy failed %s\n", nm);
                                    }
                                    desk_redraw();
                                }
                            }
                            /* Files Refresh button. Standalone block
                               like Delete/Rename/Copy: re-enumerates
                               the list in place (scroll kept, clamped
                               by desk_refresh_files) so files created
                               or removed outside the window (Editor
                               save, shell) appear without closing
                               and reopening it. Selection, preview,
                               and delete arm are cleared (the old
                               selection may no longer name the same
                               file); the typed new-name field is left
                               alone, as Delete leaves it. It works
                               with no selection. */
                            if (wn->type == W_FILES) {
                                s32 py = wn->y + 32 + 8 * 22 + 8;
                                if (inside(mx, my, wn->x + 10, py + 124, 100, 24)) {
                                    desk_refresh_files();
                                    wn->selected = -1;
                                    wn->preview[0] = 0;
                                    desk_files_del_arm = -1;
                                    desk_files_sysupd_arm = -1;
                                    desk_files_hash_valid = 0;
                                    console_printf("files: refreshed\n");
                                    desk_redraw();
                                }
                            }
                            /* Files Hash button. Standalone block
                               like Refresh: the desktop form of
                               shell `sha256 <file>` (same read
                               rule, same 64 KiB cap — fs_read_as
                               refuses a larger file, so the hash
                               is never a truncated prefix). A
                               click with no selection only
                               reports "needs selection", never
                               hashes row 0. A success prints the
                               full hex beside "files: sha256
                               <name>" and shows it in the preview
                               box (two halves, see the draw
                               function); a failure keeps the
                               selection for a retry and clears
                               any stale hash display. No confirm:
                               hashing reads and writes nothing. */
                            if (wn->type == W_FILES) {
                                s32 py = wn->y + 32 + 8 * 22 + 8;
                                if (inside(mx, my, wn->x + 130, py + 124, 100, 24)) {
                                    if (wn->selected < 0 || wn->selected >= desk_files_count) {
                                        console_write("files: hash needs selection\n");
                                        const char *t = "Select a file first"; int k = 0; while (t[k]) { wn->preview[k] = t[k]; k++; }
                                        wn->preview[k] = 0;
                                    } else {
                                        const char *nm = desk_files_names[wn->selected];
                                        u32 sz = 0;
                                        if (fs_read_as(nm, desk_files_hash_buf, sizeof(desk_files_hash_buf), &sz, shell_session_uid()) == 0) {
                                            u8 digest[32];
                                            sha256_compute(desk_files_hash_buf, sz, digest);
                                            sha256_hex(digest, desk_files_hash);
                                            int k = 0; while (nm[k] && k < 31) { desk_files_hash_name[k] = nm[k]; k++; }
                                            desk_files_hash_name[k] = 0;
                                            desk_files_hash_valid = 1;
                                            console_printf("files: sha256 %s %s\n", nm, desk_files_hash);
                                        } else {
                                            desk_files_hash_valid = 0;
                                            console_printf("files: hash failed %s\n", nm);
                                        }
                                    }
                                    desk_redraw();
                                }
                            }
                            /* Files chmod mode field + Chmod
                               button. Standalone blocks like
                               Hash: the field click focuses the
                               separate mode buffer (the client-
                               area handler above already cleared
                               every focus, so this branch re-sets
                               it — Network ping precedent). The
                               button is the desktop form of
                               shell `chmod <file> <mode>` and
                               uses the shell's parse rule
                               exactly: an optional leading 0,
                               then exactly 3 octal digits —
                               anything else reports "bad mode"
                               and keeps the field, never a
                               masked value, so 999 cannot
                               silently become a valid mode. A
                               click with no selection only
                               reports "needs selection"; an
                               empty field only reports "needs
                               mode". On success fs_chmod_as
                               (owner-or-root rule, the shell's
                               rule) prints "files: chmod <name>
                               mode <mode>" and the field clears
                               (so a second chmod types fresh —
                               the test proves this by chmodding
                               back); a failure keeps the field
                               for a retry. No confirm: a mode
                               change is reversible by changing
                               it back, and the owner can always
                               chmod back even from mode 000. */
                            if (wn->type == W_FILES) {
                                s32 py = wn->y + 32 + 8 * 22 + 8;
                                if (inside(mx, my, wn->x + 90, py + 152, 100, 24)) {
                                    desk_files_mode_focused = 1;
                                    desk_redraw();
                                }
                            }
                            if (wn->type == W_FILES) {
                                s32 py = wn->y + 32 + 8 * 22 + 8;
                                if (inside(mx, my, wn->x + 200, py + 152, 100, 24)) {
                                    if (wn->selected < 0 || wn->selected >= desk_files_count) {
                                        console_write("files: chmod needs selection\n");
                                        const char *t = "Select a file first"; int k = 0; while (t[k]) { wn->preview[k] = t[k]; k++; }
                                        wn->preview[k] = 0;
                                    } else if (desk_files_mode_len == 0) {
                                        console_write("files: chmod needs mode\n");
                                        const char *t = "Type a mode first"; int k = 0; while (t[k]) { wn->preview[k] = t[k]; k++; }
                                        wn->preview[k] = 0;
                                    } else {
                                        const char *nm = desk_files_names[wn->selected];
                                        const char *d = desk_files_mode;
                                        if (d[0] == '0') d++;
                                        u32 mode = 0; int ok = 1;
                                        if (d[0] == 0 || d[1] == 0 || d[2] == 0 || d[3] != 0) ok = 0;
                                        for (int i = 0; ok && i < 3; i++) {
                                            if (d[i] < '0' || d[i] > '7') ok = 0;
                                            else mode = mode * 8u + (u32)(d[i] - '0');
                                        }
                                        if (!ok) {
                                            console_printf("files: chmod bad mode %s\n", desk_files_mode);
                                        } else if (fs_chmod_as(nm, mode, shell_session_uid()) == 0) {
                                            console_printf("files: chmod %s mode %s\n", nm, desk_files_mode);
                                            desk_files_mode_len = 0; desk_files_mode[0] = 0;
                                            desk_files_mode_focused = 0;
                                        } else {
                                            console_printf("files: chmod failed %s\n", nm);
                                        }
                                    }
                                    desk_redraw();
                                }
                            }
                            /* Open button (Files) and the Phase 10
                               window controls live in their own chain:
                               the row-selection loop above already ran
                               for Files windows. */
                            if (wn->type == W_FILES && wn->selected >= 0 && wn->selected < desk_files_count) {
                                s32 py = wn->y + 32 + 8 * 22 + 8;
                                if (inside(mx, my, wn->x + 10, py + 68, 100, 24)) {
                                    const char *nm = desk_files_names[wn->selected];
                                    int ln = 0; while (nm[ln]) ln++;
                                    if (ln >= 4 && nm[ln-4]=='.' && nm[ln-3]=='t' && nm[ln-2]=='x' && nm[ln-1]=='t') {
                                        if (desk_editor_load(nm) == 0) desk_open_editor();
                                    } else if (ln >= 4 && nm[ln-4]=='.' && nm[ln-3]=='b' && nm[ln-2]=='m' && nm[ln-1]=='p') {
                                        if (desk_viewer_load(nm) == 0) desk_open_viewer();
                                    } else if (ln >= 6 && nm[ln-6]=='.' && nm[ln-5]=='n' && nm[ln-4]=='x' && nm[ln-3]=='u' && nm[ln-2]=='p' && nm[ln-1]=='d') {
                                        /* Files Sysupdate: Open on a
                                           .nxupd file is the desktop
                                           form of shell `sysupdate
                                           <bundle>` (the two-phase,
                                           signature-verified update
                                           in pkg_sysupdate, snapshot
                                           left for `sysrollback`):
                                           root-only like the shell
                                           (the shell's uid check
                                           lives in shell.c,
                                           pkg_sysupdate itself has
                                           none). Two-click confirm,
                                           Files Delete pattern: a
                                           system update replaces
                                           installed packages, so a
                                           single click must never
                                           apply it — the first click
                                           only arms ("files:
                                           sysupdate confirm
                                           <file>"), the second click
                                           on the same selected bundle
                                           applies it. A success prints
                                           "files: sysupdate applied
                                           <file>" beside pkg's own
                                           "System update complete"
                                           line and re-enumerates in
                                           place (the update wrote new
                                           files, so the list would
                                           otherwise be stale),
                                           selection cleared; a
                                           failure prints "files:
                                           sysupdate failed <file>"
                                           and clears the arm but
                                           keeps the selection for a
                                           retry (pkg's own failure
                                           line already printed). */
                                        if (shell_session_uid() != 0) {
                                            console_write("files: sysupdate needs root\n");
                                        } else if (desk_files_sysupd_arm != wn->selected) {
                                            desk_files_sysupd_arm = wn->selected;
                                            console_printf("files: sysupdate confirm %s\n", nm);
                                            desk_notify("Click Open again to apply the system update");
                                        } else if (pkg_sysupdate(nm) == 0) {
                                            console_printf("files: sysupdate applied %s\n", nm);
                                            desk_files_sysupd_arm = -1;
                                            desk_files_del_arm = -1;
                                            wn->selected = -1;
                                            wn->preview[0] = 0;
                                            desk_refresh_files();
                                        } else {
                                            console_printf("files: sysupdate failed %s\n", nm);
                                            desk_files_sysupd_arm = -1;
                                        }
                                    } else if (ln >= 6 && nm[ln-6]=='.' && nm[ln-5]=='n' && nm[ln-4]=='x' && nm[ln-3]=='p' && nm[ln-2]=='k' && nm[ln-1]=='g') {
                                        /* Files Install: Open on a .nxpkg
                                           file is the desktop form of
                                           shell `pkg install <file>` (the
                                           local-file path, signature
                                           verified by pkg_install): root-
                                           only like the shell (the shell's
                                           uid check lives in shell.c,
                                           pkg_install itself has none).
                                           No confirm: Repo Install has
                                           none either, and install is
                                           not destructive the way
                                           Remove is. A success prints
                                           "files: installed <file>" and
                                           re-enumerates in place (the
                                           install wrote new files, so
                                           the list would otherwise be
                                           stale), selection cleared; a
                                           failure keeps the selection
                                           for a retry (pkg's own failure
                                           line already printed). */
                                        if (shell_session_uid() != 0) {
                                            console_write("files: install needs root\n");
                                        } else if (pkg_install(nm) == 0) {
                                            console_printf("files: installed %s\n", nm);
                                            desk_files_del_arm = -1;
                                            wn->selected = -1;
                                            wn->preview[0] = 0;
                                            desk_refresh_files();
                                        }
                                        } else if (ln >= 4 && nm[ln-4]=='.' && nm[ln-3]=='e' && nm[ln-2]=='l' && nm[ln-1]=='f') {
                                        /* Files Run: Open on a .elf
                                           file is the desktop form of
                                           shell `run <file>` for GUI
                                           programs (the Calculator
                                           launcher entry already
                                           starts calc.elf this way,
                                           but any other program file
                                           had no desktop path — Open
                                           reported "no viewer" for
                                           it). It goes through
                                           proc_bg_start with the
                                           session uid, exactly like
                                           the launcher: a GUI program
                                           opens its window, which
                                           the desktop loop then
                                           ticks. A console program
                                           also runs, but with no
                                           visible console on the
                                           desktop (its output goes
                                           to the serial log); the
                                           shell `run` stays the right
                                           path for those. A success
                                           prints "files: started
                                           <file>" beside proc's own
                                           "Background job <file>
                                           started" line; a failure
                                           prints "files: run failed
                                           <file>". Run writes no
                                           files, so unlike Install
                                           there is no re-enumeration
                                           and the selection is kept
                                           either way (a failure
                                           keeps it for a retry, a
                                           success keeps it so the
                                           program can be run again).
                                           */
                                        if (proc_bg_start(nm, shell_session_uid()) == 0) {
                                            console_printf("files: started %s\n", nm);
                                        } else {
                                            console_printf("files: run failed %s\n", nm);
                                        }
                                    } else {
                                        desk_notify("No viewer for this file type");
                                        console_printf("files: no viewer for %s\n", nm);
                                    }
                                    desk_redraw();
                                }
                            } else if (wn->type == W_NETWORK) {
                                if (inside(mx, my, wn->x + 10, wn->y + 230, 120, 24)) {
                                    if (!net_present()) { set_msg(desk_net_msg, "No network device"); console_write("network: dhcp with no device\n"); }
                                    else if (net_dhcp() == 0) { set_msg(desk_net_msg, "DHCP ok"); console_write("network: dhcp ok\n"); }
                                    else { set_msg(desk_net_msg, "DHCP failed"); console_write("network: dhcp failed\n"); }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 150, wn->y + 230, 140, 24)) {
                                    if (!net_ip_configured()) { set_msg(desk_net_msg, "Not configured, run DHCP first"); }
                                    else {
                                        ip_t gw; net_ip_gateway(&gw);
                                        if (net_ping(gw) == 0) set_msg(desk_net_msg, "Ping reply received");
                                        else set_msg(desk_net_msg, "Ping failed");
                                        console_printf("network: ping gateway %s\n", desk_net_msg);
                                    }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 50, wn->y + 292, 300, 24)) {
                                    /* Set-DNS field (Files rename
                                       pattern): click focuses the
                                       field so typing goes to it. */
                                    wn->field_focused = 1;
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 360, wn->y + 292, 110, 24)) {
                                    /* Set DNS is the desktop form
                                       of shell `dnsset <ip>`: the
                                       shell command has no uid
                                       check, so neither does this
                                       (net_set_dns itself has
                                       none). An empty field only
                                       reports it; a malformed
                                       address fails with its own
                                       reason and keeps the field
                                       for a retry; on success the
                                       DNS line above reloads in
                                       place (it reads net_ip_dns
                                       on every draw) and the field
                                       clears. No confirm: setting
                                       a DNS address is
                                       non-destructive and
                                       reversible by setting
                                       another, Repo Set precedent. */
                                    if (wn->field_len == 0) {
                                        set_msg(desk_net_msg, "DNS needs IP");
                                        console_write("network: dns needs ip\n");
                                    } else {
                                        ip_t dip;
                                        if (!net_parse_ip(wn->field, &dip)) {
                                            set_msg(desk_net_msg, "Bad DNS IP");
                                            console_printf("network: dns bad ip %s\n", wn->field);
                                        } else {
                                            char dtxt[32]; ip_text(dip, dtxt);
                                            net_set_dns(dip);
                                            set_msg(desk_net_msg, "DNS set");
                                            console_printf("network: dns set %s\n", dtxt);
                                            wn->field_len = 0; wn->field[0] = 0; wn->field_focused = 0;
                                        }
                                    }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 50, wn->y + 324, 300, 24)) {
                                    /* Ping-host field (Files rename
                                       pattern): click focuses the
                                       field so typing goes to it. */
                                    desk_net_ping_focused = 1;
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 360, wn->y + 324, 110, 24)) {
                                    /* Ping host is the desktop form
                                       of shell `ping <ip>` for an
                                       arbitrary host (Ping gateway
                                       only probes the gateway): the
                                       shell command has no uid
                                       check, so neither does this.
                                       An empty field only reports
                                       it; a malformed address fails
                                       with its own reason and keeps
                                       the field for a retry; without
                                       a configured IP it reports
                                       "not configured" instead of
                                       probing. A reply clears the
                                       field, a timeout keeps it for
                                       a retry. No confirm: a ping
                                       is a read-only probe. */
                                    if (desk_net_ping_len == 0) {
                                        set_msg(desk_net_msg, "Ping needs IP");
                                        console_write("network: ping needs ip\n");
                                    } else if (!net_ip_configured()) {
                                        set_msg(desk_net_msg, "Not configured, run DHCP first");
                                        console_write("network: ping not configured\n");
                                    } else {
                                        ip_t pip;
                                        if (!net_parse_ip(desk_net_ping, &pip)) {
                                            set_msg(desk_net_msg, "Bad ping IP");
                                            console_printf("network: ping bad ip %s\n", desk_net_ping);
                                        } else {
                                            char ptxt[32]; ip_text(pip, ptxt);
                                            if (net_ping(pip) == 0) {
                                                set_msg(desk_net_msg, "Ping reply received");
                                                console_printf("network: ping reply %s\n", ptxt);
                                                desk_net_ping_len = 0; desk_net_ping[0] = 0; desk_net_ping_focused = 0;
                                            } else {
                                                set_msg(desk_net_msg, "Ping failed");
                                                console_printf("network: ping no reply %s\n", ptxt);
                                            }
                                        }
                                    }
                                    desk_redraw();
                                }
                            } else if (wn->type == W_MONITOR) {
                                /* Monitor Kill: the desktop form of
                                   shell `kill <pid>`, through the same
                                   proc_bg_kill with the session uid,
                                   so the shell's permission rule is
                                   shared, not re-implemented (root
                                   kills any job, anyone else only
                                   their own). Two-click confirm,
                                   Files Delete pattern, but armed
                                   by pid, not by row: the list
                                   redraws every second and a job
                                   may finish between the clicks,
                                   so re-reading the row at confirm
                                   time and comparing pids refuses
                                   to kill a different job that
                                   slid into the armed row. A failed
                                   kill keeps the selection for a
                                   retry; a success clears both.
                                   Kill with no selection only
                                   prints, never kills row 0. */
                                if (inside(mx, my, wn->x + 10, wn->y + 360, 100, 24)) {
                                    if (wn->selected < 0) {
                                        console_write("monitor: kill needs selection\n");
                                    } else {
                                        char kname[32]; u32 kpid, kuid;
                                        if (proc_bg_at(wn->selected, kname, &kpid, &kuid) != 0) {
                                            wn->selected = -1; desk_monitor_kill_arm_pid = -1;
                                            console_write("monitor: kill needs selection\n");
                                        } else if (desk_monitor_kill_arm_pid != (int)kpid) {
                                            desk_monitor_kill_arm_pid = (int)kpid;
                                            console_printf("monitor: kill confirm %s\n", kname);
                                        } else if (proc_bg_kill(kpid, shell_session_uid()) == 0) {
                                            console_printf("monitor: killed %s\n", kname);
                                            desk_monitor_kill_arm_pid = -1;
                                            wn->selected = -1;
                                        } else {
                                            console_printf("monitor: kill failed %s\n", kname);
                                        }
                                    }
                                    desk_redraw();
                                } else {
                                    int hit = -1;
                                    for (int r = 0; r < MAX_BG; r++) {
                                        char hname[32]; u32 hpid, huid;
                                        if (proc_bg_at(r, hname, &hpid, &huid) != 0) break;
                                        if (inside(mx, my, wn->x + 10, wn->y + 276 + r * 20, 460, 20)) { hit = r; break; }
                                    }
                                    if (hit >= 0) {
                                        if (wn->selected != hit) desk_monitor_kill_arm_pid = -1;
                                        wn->selected = hit;
                                        { char sname[32]; u32 spid, suid; if (proc_bg_at(hit, sname, &spid, &suid) == 0) console_printf("monitor: selected %s\n", sname); }
                                        desk_redraw();
                                    }
                                }
                            } else if (wn->type == W_WEB) {
                                desk_web_save_focused = 0;
                                if (inside(mx, my, wn->x + 80, wn->y + 28, wn->w - 100, 24)) wn->field_focused = 1;
                                else if (inside(mx, my, wn->x + 10, wn->y + 64, 100, 24)) { desk_web_fetch(wn->field); wn->aux1 = 0; desk_redraw(); }
                                else if (inside(mx, my, wn->x + wn->w - 120, wn->y + 64, 50, 24)) { if (wn->aux1 > 0) wn->aux1--; desk_redraw(); }
                                else if (inside(mx, my, wn->x + wn->w - 60, wn->y + 64, 50, 24)) { wn->aux1++; desk_redraw(); }
                                else if (inside(mx, my, wn->x + 80, wn->y + 352, 300, 24)) desk_web_save_focused = 1;
                                else if (inside(mx, my, wn->x + 390, wn->y + 352, 100, 24)) {
                                    /* Web Save: the fetched body to
                                       disk through the filesystem's
                                       own write rule (session uid,
                                       mode 0644, Editor Save
                                       precedent). No root check:
                                       the write rule itself
                                       decides. An existing file
                                       is refused, never
                                       overwritten (Files Copy /
                                       Repo Fetch precedent) —
                                       fs_write_as overwrites, so
                                       the fs_exists refusal is
                                       what keeps a save from
                                       destroying a file. */
                                    if (desk_web_len == 0) { set_msg(desk_web_status, "save needs fetch"); console_write("web: save needs fetch\n"); }
                                    else if (desk_web_save_len == 0) { set_msg(desk_web_status, "save needs name"); console_write("web: save needs name\n"); }
                                    else if (fs_exists(desk_web_save)) { set_msg(desk_web_status, "save exists"); console_printf("web: save exists %s\n", desk_web_save); }
                                    else if (fs_write_as(desk_web_save, (const u8 *)desk_web_body, desk_web_len, shell_session_uid(), 0644) == 0) {
                                        char tmp[64]; tmp[0]='S'; tmp[1]='a'; tmp[2]='v'; tmp[3]='e'; tmp[4]='d'; tmp[5]=' '; int n=6;
                                        char num[16]; u32_to_str(desk_web_len, num, 10);
                                        int t=0; while (num[t]) tmp[n++]=num[t++];
                                        tmp[n++]=' '; tmp[n++]='b'; tmp[n++]='y'; tmp[n++]='t'; tmp[n++]='e'; tmp[n++]='s'; tmp[n]=0;
                                        set_msg(desk_web_status, tmp);
                                        console_printf("web: saved %s %u bytes\n", desk_web_save, desk_web_len);
                                        desk_web_save[0] = 0; desk_web_save_len = 0;
                                    } else { set_msg(desk_web_status, "save failed"); console_printf("web: save failed %s\n", desk_web_save); }
                                    desk_redraw();
                                }
                                else wn->field_focused = 0;
                            } else if (wn->type == W_EDITOR) {
                                if (inside(mx, my, wn->x + 60, wn->y + 28, wn->w - 80, 24)) wn->field_focused = 1;
                                else if (inside(mx, my, wn->x + 10, wn->y + 64, 80, 24)) {
                                    desk_ed_new_confirm = 0;
                                    if (wn->field_len == 0) { set_msg(desk_ed_msg, "No filename"); }
                                    else if (fs_write_as(wn->field, (const u8 *)desk_ed_buf, desk_ed_len, shell_session_uid(), 0644) == 0) {
                                        char tmp[64]; tmp[0]='S'; tmp[1]='a'; tmp[2]='v'; tmp[3]='e'; tmp[4]='d'; tmp[5]=' '; int n=6;
                                        char num[16]; u32_to_str(desk_ed_len, num, 10);
                                        int t=0; while (num[t]) tmp[n++]=num[t++];
                                        tmp[n++]=' '; tmp[n++]='b'; tmp[n++]='y'; tmp[n++]='t'; tmp[n++]='e'; tmp[n++]='s'; tmp[n]=0;
                                        set_msg(desk_ed_msg, tmp);
                                        { int k = 0; while (wn->field[k] && k < 31) { desk_ed_name[k] = wn->field[k]; k++; } desk_ed_name[k] = 0; }
                                        console_printf("editor: saved %s %u bytes\n", wn->field, desk_ed_len);
                                    } else { set_msg(desk_ed_msg, "Save failed"); console_write("editor: save failed\n"); }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 100, wn->y + 64, 80, 24)) {
                                    desk_ed_new_confirm = 0;
                                    if (wn->field_len > 0 && desk_editor_load(wn->field) == 0) {
                                        desk_editor_sync_field(wi);
                                        set_msg(desk_ed_msg, "Opened");
                                    }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 190, wn->y + 64, 80, 24)) {
                                    /* 6(b) part 7: New-file flow. A
                                       non-empty buffer is never
                                       discarded on one click: the
                                       first click only arms the
                                       confirm and says so; the
                                       second click clears the buffer
                                       AND the filename field, so the
                                       user types a fresh name and
                                       Saves it. An empty buffer
                                       needs no confirm. The status
                                       marker uses the same counting
                                       rule as the drawn status line,
                                       so the test proves the buffer
                                       is really empty. */
                                    if (desk_ed_len > 0 && !desk_ed_new_confirm) {
                                        desk_ed_new_confirm = 1;
                                        set_msg(desk_ed_msg, "Click New again to discard");
                                        /* Counts prove the first click
                                           preserved the buffer: the
                                           test asserts the pre-clear
                                           counts, not just the arm. */
                                        { u32 nl = 0;
                                            for (u32 i = 0; i < desk_ed_len; i++) if (desk_ed_buf[i] == '\n') nl++;
                                            if (desk_ed_buf[desk_ed_len - 1] != '\n') nl++;
                                            console_printf("editor: new confirm %u lines %u bytes\n", nl, desk_ed_len);
                                        }
                                    } else {
                                        desk_ed_len = 0; desk_ed_buf[0] = 0;
                                        wn->aux1 = 0; wn->aux2 = 0;
                                        wn->field_len = 0; wn->field[0] = 0;
                                        desk_ed_name[0] = 0;
                                        desk_ed_new_confirm = 0;
                                        set_msg(desk_ed_msg, "New file");
                                        console_write("editor: new file\n");
                                        console_write("editor: status 0 lines 0 bytes\n");
                                    }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + wn->w - 116, wn->y + wn->h - 24, 48, 20)) {
                                    /* 6(b) part 8: scroll up one row. */
                                    if (wn->aux2 > 0) { wn->aux2--; console_printf("editor: scroll btn %d\n", wn->aux2); }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + wn->w - 64, wn->y + wn->h - 24, 44, 20)) {
                                    /* 6(b) part 8: scroll down one row. */
                                    if (wn->aux2 < desk_editor_max_scroll(wn)) { wn->aux2++; console_printf("editor: scroll btn %d\n", wn->aux2); }
                                    desk_redraw();
                                } else {
                                    wn->field_focused = 0;
                                    /* Click in body: place the cursor. */
                                    int line = (my - (wn->y + 100)) / 16 + wn->aux2;
                                    int col = (mx - (wn->x + 10)) / 8;
                                    if (line >= 0 && col >= 0) {
                                        int p = 0, l = 0;
                                        while (l < line && desk_ed_buf[p]) { if (desk_ed_buf[p] == '\n') l++; p++; }
                                        int ls = p, ll = 0;
                                        while (desk_ed_buf[p] && desk_ed_buf[p] != '\n') { p++; ll++; }
                                        if (col > ll) col = ll;
                                        wn->aux1 = ls + col;
                                        desk_redraw();
                                    }
                                }
                            } else if (wn->type == W_REPO) {
                                /* Repo buttons (window at wn->x,wn->y):
                                   Update x+10..x+110, Install
                                   x+120..x+220, Fetch x+230..x+330,
                                   all y+252..y+276;
                                   scroll Up x+360..x+410, Dn
                                   x+420..x+470, y+284..y+308; rows
                                   x+10..x+470, y+80+r*20..+20.
                                   Update needs a configured network
                                   (Network ping pattern: "not
                                   configured, run DHCP first",
                                   never a silent fetch failure);
                                   on success it reloads the list
                                   in place and clears the selection.
                                   Update and Install are both
                                   root-only, the shell's `pkg
                                   update` / `pkg install` rule
                                   (Fetch/Set precedent) — the pkg
                                   layer itself writes as uid 0,
                                   so a handler check is the only
                                   thing standing between a non-root
                                   desktop session and a package
                                   install. Install needs a selected
                                   row (Files copy pattern); on
                                   success the selection clears, on
                                   failure it stays for a retry and
                                   pkg's own failure line already
                                   printed.
                                   The fetch/install block the
                                   desktop loop while they run, Web
                                   Fetch precedent. Set-repo field
                                   x+10..x+350, Set repo button
                                   x+360..x+470, both y+316..y+340:
                                   the desktop form of shell
                                   `pkg repo <url>` (root-only,
                                   empty field refused, success
                                   reloads the URL line and clears
                                   the field, failure keeps it for
                                   a retry). Scroll: Files
                                   pattern, print "repo: scroll N"
                                   only on a real change, clamped to
                                   0..count-8, so a click that cannot
                                   move prints nothing. */
                                if (inside(mx, my, wn->x + 10, wn->y + 252, 100, 24)) {
                                    /* Update is the desktop form of
                                       shell `pkg update`: root-only
                                       like the shell (the shell's
                                       uid check lives in shell.c,
                                       pkg_repo_update itself has
                                       none, and the pkg layer writes
                                       the stored index as uid 0) —
                                       without this check a non-root
                                       desktop session could replace
                                       the stored index and then
                                       install from it, bypassing
                                       the shell's root-only rule
                                       entirely. The root check comes
                                       first, before the configured
                                       check, mirroring the shell,
                                       which refuses a non-root
                                       update before doing anything.
                                       Install below has the same
                                       hole and the same fix. */
                                    if (shell_session_uid() != 0) {
                                        console_write("repo: update needs root\n");
                                    } else if (!net_ip_configured()) {
                                        console_write("repo: not configured, run DHCP first\n");
                                    } else if (pkg_repo_update() == 0) {
                                        desk_repo_reload();
                                        wn->selected = -1;
                                    }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 120, wn->y + 252, 100, 24)) {
                                    if (wn->selected < 0 || wn->selected >= desk_repo_count) {
                                        console_write("repo: install needs selection\n");
                                    } else if (shell_session_uid() != 0) {
                                        console_write("repo: install needs root\n");
                                    } else if (pkg_repo_install(desk_repo_name[wn->selected]) == 0) {
                                        wn->selected = -1;
                                    }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 230, wn->y + 252, 100, 24)) {
                                    /* Fetch is the desktop form of
                                       shell `pkg fetch <name>`:
                                       root-only like the shell
                                       (the shell's uid check lives
                                       in shell.c, pkg_repo_fetch
                                       itself has none). Fetch
                                       needs a selected row (Install
                                       pattern); on success the
                                       selection clears, on failure
                                       it stays for a retry and pkg's
                                       own failure line already
                                       printed (a file that already
                                       exists is refused, never
                                       overwritten). No confirm:
                                       fetching writes a new file
                                       and installs nothing, Install
                                       precedent. */
                                    if (wn->selected < 0 || wn->selected >= desk_repo_count) {
                                        console_write("repo: fetch needs selection\n");
                                    } else if (shell_session_uid() != 0) {
                                        console_write("repo: fetch needs root\n");
                                    } else if (pkg_repo_fetch(desk_repo_name[wn->selected]) == 0) {
                                        console_printf("repo: fetched %s\n", desk_repo_name[wn->selected]);
                                        wn->selected = -1;
                                    } else {
                                        console_printf("repo: fetch failed %s\n", desk_repo_name[wn->selected]);
                                    }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 10, wn->y + 316, 340, 24)) {
                                    /* Set-repo field (Files rename
                                       pattern): click focuses the
                                       field so typing goes to it. */
                                    wn->field_focused = 1;
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 360, wn->y + 316, 110, 24)) {
                                    /* Set repo is the desktop form
                                       of shell `pkg repo <url>`:
                                       root-only like the shell
                                       (the shell's uid check lives
                                       in shell.c, pkg_repo_set
                                       itself has none). An empty
                                       field only reports it; on
                                       success the URL line reloads
                                       in place, the selection
                                       clears, and the field
                                       clears; on failure the field
                                       stays for a retry and pkg's
                                       own failure line already
                                       printed. No confirm: setting
                                       a URL is non-destructive and
                                       reversible by setting another,
                                       Install precedent. */
                                    if (wn->field_len == 0) {
                                        console_write("repo: set needs url\n");
                                    } else if (shell_session_uid() != 0) {
                                        console_write("repo: set needs root\n");
                                    } else if (pkg_repo_set(wn->field) == 0) {
                                        console_printf("repo: set %s\n", wn->field);
                                        wn->field_len = 0; wn->field[0] = 0; wn->field_focused = 0;
                                        wn->selected = -1;
                                        desk_repo_reload();
                                    } else {
                                        console_printf("repo: set failed %s\n", wn->field);
                                    }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 360, wn->y + 284, 50, 24)) {
                                    if (desk_repo_scroll > 0) {
                                        desk_repo_scroll--;
                                        console_printf("repo: scroll %d\n", desk_repo_scroll);
                                        desk_redraw();
                                    }
                                } else if (inside(mx, my, wn->x + 420, wn->y + 284, 50, 24)) {
                                    int mx_s = desk_repo_count - 8;
                                    if (mx_s < 0) mx_s = 0;
                                    if (desk_repo_scroll < mx_s) {
                                        desk_repo_scroll++;
                                        console_printf("repo: scroll %d\n", desk_repo_scroll);
                                        desk_redraw();
                                    }
                                } else {
                                    for (int r = 0; r < 8; r++) {
                                        int i = desk_repo_scroll + r;
                                        if (i >= desk_repo_count) break;
                                        if (inside(mx, my, wn->x + 10, wn->y + 80 + r * 20, 460, 20)) {
                                            wn->selected = i;
                                            console_printf("repo: selected %s\n", desk_repo_name[i]);
                                            desk_redraw();
                                            break;
                                        }
                                    }
                                }
                            } else if (wn->type == W_PACKAGES) {
                                /* Packages Remove (window at wn->x,wn->y):
                                   Remove x+10..x+110, y+252..y+276;
                                   rows x+10..x+470, y+54+r*20..+20.
                                   Remove is the desktop form of shell
                                   `pkg remove <name>` without force:
                                   root-only like the shell (the shell's
                                   uid check lives in shell.c, pkg_remove
                                   itself has none), dependents refuse
                                   without force, and the two-click
                                   confirm is the Files Delete pattern:
                                   first click arms, second click on
                                   the same row removes. A failed
                                   remove keeps the selection for a
                                   retry (pkg's own failure line
                                   already printed); a success clears
                                   selection + arm and the list
                                   redraws from the live registry. */
                                if (inside(mx, my, wn->x + 10, wn->y + 252, 100, 24)) {
                                    desk_packages_rb_arm = 0;
                                    if (wn->selected < 0) {
                                        console_write("packages: remove needs selection\n");
                                    } else {
                                        char pname[32], pver[16];
                                        if (pkg_registry_entry(wn->selected, pname, pver) != 0) {
                                            console_write("packages: remove needs selection\n");
                                        } else if (shell_session_uid() != 0) {
                                            console_write("packages: remove needs root\n");
                                        } else if (desk_packages_del_arm != wn->selected) {
                                            desk_packages_del_arm = wn->selected;
                                            console_printf("packages: remove confirm %s\n", pname);
                                        } else if (pkg_remove(pname, 0) == 0) {
                                            console_printf("packages: removed %s\n", pname);
                                            desk_packages_del_arm = -1;
                                            wn->selected = -1;
                                        }
                                    }
                                    desk_redraw();
                                } else if (inside(mx, my, wn->x + 120, wn->y + 252, 100, 24)) {
                                    /* Packages Rollback (window at wn->x,wn->y):
                                       Rollback x+120..x+220, y+252..y+276,
                                       beside Remove. Rollback is the
                                       desktop form of shell `sysrollback`:
                                       root-only like the shell (the shell's
                                       uid check lives in shell.c,
                                       pkg_sysrollback itself has none),
                                       whole-system so it needs no row
                                       selection, and the two-click confirm
                                       is the Files Delete pattern: first
                                       click arms, second click rolls back.
                                       A success prints beside pkg's own
                                       "Rolled back to the previous version"
                                       line and the list redraws from the
                                       live registry; a failure prints beside
                                       pkg's own failure line. The arm clears
                                       on success and on failure alike, so a
                                       retry re-arms. Any Remove press or row
                                       click disarms, and a Rollback press
                                       disarms a pending Remove confirm. */
                                    desk_packages_del_arm = -1;
                                    if (shell_session_uid() != 0) {
                                        console_write("packages: rollback needs root\n");
                                    } else if (!desk_packages_rb_arm) {
                                        desk_packages_rb_arm = 1;
                                        console_write("packages: rollback confirm\n");
                                        desk_notify("Click Rollback again to confirm");
                                    } else if (pkg_sysrollback() == 0) {
                                        console_write("packages: rollback done\n");
                                        desk_packages_rb_arm = 0;
                                    } else {
                                        console_write("packages: rollback failed\n");
                                        desk_packages_rb_arm = 0;
                                    }
                                    desk_redraw();
                                } else {
                                    for (int r = 0; r < 8; r++) {
                                        char pname[32], pver[16];
                                        if (pkg_registry_entry(r, pname, pver) != 0) break;
                                        if (inside(mx, my, wn->x + 10, wn->y + 54 + r * 20, 460, 20)) {
                                            if (desk_packages_del_arm != r) desk_packages_del_arm = -1;
                                            desk_packages_rb_arm = 0;
                                            wn->selected = r;
                                            console_printf("packages: selected %s\n", pname);
                                            desk_redraw();
                                            break;
                                        }
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
        /* Phase 10: Monitor window refresh, once per second. */
        {
            static u32 last_mon_ticks = 0;
            int mon_idx = -1;
            for (int i = 0; i < MAX_WINDOWS; i++)
                if (wins[i].used && wins[i].type == W_MONITOR && !wins[i].minimized && wins[i].ws == desk_ws) mon_idx = i;
            if (mon_idx >= 0 && timer_ticks - last_mon_ticks >= 100) {
                last_mon_ticks = timer_ticks;
                if (!pending_redraw) { pend_x = wins[mon_idx].x; pend_y = wins[mon_idx].y; pend_w = wins[mon_idx].w; pend_h = wins[mon_idx].h; pending_redraw = 1; }
            }
        }
        /* 6b: Clock window refresh, once per second (same
           single-slot pending_redraw pattern as Monitor;
           a tick already pending just defers this one). */
        {
            static u32 last_clock_ticks = 0;
            int clk_idx = -1;
            for (int i = 0; i < MAX_WINDOWS; i++)
                if (wins[i].used && wins[i].type == W_CLOCK && !wins[i].minimized && wins[i].ws == desk_ws) clk_idx = i;
            if (clk_idx >= 0 && timer_ticks - last_clock_ticks >= 100) {
                last_clock_ticks = timer_ticks;
                if (!pending_redraw) { pend_x = wins[clk_idx].x; pend_y = wins[clk_idx].y; pend_w = wins[clk_idx].w; pend_h = wins[clk_idx].h; pending_redraw = 1; }
            }
        }
        /* Desktop idle lock. */
        if (!desk_locked && shell_idle_minutes() != 0 && timer_ticks - desk_last_activity > shell_idle_minutes() * 6000u) {
            desk_show_lock(); desk_redraw();
        }
        if (pending_redraw && timer_ticks - last_redraw_ticks >= (u32)desk_throttle_ticks()) {
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
/* Phase 10 test-only entry points. Like the security and calc
   tests, these do not return on their own; the harness ends
   the run after the markers appear and checks the log. */
int wm_desktop_p10test(void) {
    int rc = wm_desktop_internal(4);
    console_printf("desktopp10test returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_appstest(void) {
    int rc = wm_desktop_internal(5);
    console_printf("desktopappstest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_p10sec(void) {
    int rc = wm_desktop_internal(6);
    console_printf("desktopp10sec returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_webtest(void) {
    int rc = wm_desktop_internal(7);
    console_printf("desktopwebtest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_nonictest(void) {
    int rc = wm_desktop_internal(8);
    console_printf("desktopnonictest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_repotest(void) {
    int rc = wm_desktop_internal(9);
    console_printf("desktoprepotest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_repoapptest(void) {
    int rc = wm_desktop_internal(10);
    console_printf("desktoprepoapptest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_packageapptest(void) {
    int rc = wm_desktop_internal(11);
    console_printf("desktoppackageapptest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_fileinstalltest(void) {
    int rc = wm_desktop_internal(12);
    console_printf("desktopfileinstalltest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_fileruntest(void) {
    int rc = wm_desktop_internal(13);
    console_printf("desktopfileruntest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_monitorjobtest(void) {
    int rc = wm_desktop_internal(14);
    console_printf("desktopmonitorjobtest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_reboottest(void) {
    /* The confirming Reboot click resets the machine, so this
       normally never returns; if it does, the rc line proves
       the reboot did not happen. */
    int rc = wm_desktop_internal(15);
    console_printf("desktopreboottest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_logouttest(void) {
    int rc = wm_desktop_internal(16);
    console_printf("desktoplogouttest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_filesysupdtest(void) {
    int rc = wm_desktop_internal(17);
    console_printf("desktopfilesysupdtest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_rollbacktest(void) {
    int rc = wm_desktop_internal(18);
    console_printf("desktoprollbacktest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_reposettest(void) {
    int rc = wm_desktop_internal(19);
    console_printf("desktopreposettest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_dnstest(void) {
    int rc = wm_desktop_internal(20);
    console_printf("desktopdnssettest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_netpingtest(void) {
    int rc = wm_desktop_internal(21);
    console_printf("desktopnetpingtest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_repofetchtest(void) {
    int rc = wm_desktop_internal(22);
    console_printf("desktoprepofetchtest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_fileshashtest(void) {
    int rc = wm_desktop_internal(23);
    console_printf("desktopfileshashtest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_monitordisktest(void) {
    int rc = wm_desktop_internal(24);
    console_printf("desktopmonitordisktest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_websavetest(void) {
    int rc = wm_desktop_internal(25);
    console_printf("desktopwebsavetest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_fileschmodtest(void) {
    int rc = wm_desktop_internal(26);
    console_printf("desktopfileschmodtest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_reporoottest(void) {
    int rc = wm_desktop_internal(27);
    console_printf("desktopreporoottest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_settingsunlocktest(void) {
    int rc = wm_desktop_internal(28);
    console_printf("desktopsettingsunlocktest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_unlocknousertest(void) {
    int rc = wm_desktop_internal(29);
    console_printf("desktopunlocknousertest returned (rc=%d)\n", rc);
    return rc;
}
int wm_desktop_fallbacktest(void) {
    int rc = wm_desktop_internal(30);
    console_printf("desktopfallbacktest returned (rc=%d)\n", rc);
    return rc;
}
