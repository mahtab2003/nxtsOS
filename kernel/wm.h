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
int wm_count(void);
#endif
