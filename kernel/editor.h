#ifndef NXTS_EDITOR_H
#define NXTS_EDITOR_H
#include "common.h"
/* Full-screen nano-like editor (shell `edit`, fs group).
   Runs its own keyboard loop on the kernel console (VGA text
   and framebuffer text modes); renders through the buffer-only
   console editor APIs, never console_write (which would spam
   the serial log with a full redraw per keystroke).
   Returns 0 when the user exits normally (saved or
   discarded), -1 when the file cannot be opened at all
   (no filesystem, bad name, unreadable, or over the 128 KiB
   cap). Refusals print their own "edit: ..." message.
   The caller (shell) prints nothing extra. */
int editor_open(const char *filename, u32 uid);
#endif
