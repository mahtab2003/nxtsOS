#ifndef NXTS_WM_H
#define NXTS_WM_H
#include "common.h"
/* Window manager (Phase 7, in-kernel demo, not yet user GUI programs).
   Windows are drawn directly to the framebuffer with clipping; no
   per-window pixel buffers are allocated, so a huge window cannot
   exhaust memory — it is clamped to the screen instead.
   wm_run() is the interactive loop, entered from the shell `gui`
   command; it returns when the user clicks the taskbar "Shell"
   button or a window's "Back to shell" button, and the text console
   is redrawn on return. wm_test() runs the non-interactive
   edge-case checks (negative/huge/off-screen windows, window-count
   limit) and logs the results to serial, then restores the text
   console. Both return -1 if no framebuffer is available. */
int wm_run(void);
int wm_autotest(void);
int wm_test(void);
int wm_cursortest(void);
int wm_cliptest(void);
int wm_desktop_run(void);
int wm_desktop_autotest(void);
int wm_desktop_sectest(void);
int wm_desktop_calctest(void);
int wm_desktop_p10test(void);
int wm_desktop_appstest(void);
int wm_desktop_p10sec(void);
int wm_desktop_webtest(void);
int wm_desktop_nonictest(void);
int wm_gui_open(const char *title, s32 x, s32 y, s32 w, s32 h, u32 pid);
int wm_gui_rect(u32 pid, s32 cx, s32 cy, s32 cw, s32 ch, u32 colour);
int wm_gui_text(u32 pid, s32 cx, s32 cy, const char *text, u32 fg, u32 bg);
struct gui_event { int type; s32 x, y; int key; int button; };
int wm_gui_event(u32 pid, struct gui_event *out);
int wm_gui_close(u32 pid);
int wm_count(void);
#endif
