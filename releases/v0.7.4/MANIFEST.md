# nxtsOS v0.7.4 — Release Manifest (bugfix on Phase 7: GUI lag)

- Version: 0.7.4 (bugfix, not a new phase)
- Kernel binary: `build/nxtsOS.bin`
- Bootable image: `build/nxtsOS.iso` (El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh`
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.7.4` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.7.4-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.7.4-dist.zip` (includes bochsrc.txt)
- Checksums: `releases/v0.7.4/SHA256SUMS`

## Fixed in v0.7.4 (user-reported 2026-10-27: "gui is working but lagging like hell")

Two real lag causes were found in the window-manager loop, not in
the emulator:

1. Mouse movement with the button up had NO branch in the loop at
   all. The cursor therefore only moved on the 0.5s periodic
   redraw — moving the mouse to click something felt like
   2 frames per second, whatever the redraw speed was.
2. Every other mouse move, drag, resize, keypress and periodic
   tick did a FULL-SCREEN redraw: 800x600 = 480,000 pixels,
   plus 4 windows, plus taskbar, plus text, on every loop
   iteration that saw movement (up to 100 Hz from mouse
   packets). In Bochs, especially on a phone, that is the lag.

Fixes (kernel/wm.c, kernel/fb.c):

- Cursor save/restore: before drawing the cursor, the 13x17
  pixels underneath are saved; moving the cursor now costs
  ~442 pixel writes (restore old + save new + draw new)
  instead of 480,000, and it moves immediately, with the
  button up or down. If the saved position does not match
  the old cursor position, it falls back to a full redraw
  instead of restoring wrong pixels.
- Dirty-rect redraw (wm_redraw_rect): background is filled
  clipped to the dirty rect only; windows that do not overlap
  the dirty rect are skipped (they cannot affect any pixel
  inside it); overlapping windows are drawn fully, in correct
  z-order, so the dirty area ends up exactly as a full
  redraw would leave it. Taskbar is only 800x24, drawn fully.
- Throttling: drag/resize/key/periodic changes merge into a
  pending dirty rect, flushed at most every 3 ticks (~30 Hz).
  Drag/resize dirty rect = union of old and new window
  rects; key dirty rect = the text-field window's rect;
  periodic (System ticks, every 50 ticks) dirty rect = the
  System window's rect only, not the full screen. If a
  pending rect grows over 200,000 pixels, it upgrades to a
  full redraw. Press/release still do an immediate full
  redraw (infrequent, and focus/minimise/maximise/close
  need it).
- Framebuffer primitives optimised: fb_fill_rect now uses a
  row pointer instead of a multiply per pixel; fb_draw_text
  clips the glyph's x range once per glyph instead of
  checking bounds per pixel; fb_draw_char uses a row pointer
  instead of a per-pixel function call. Rendering output is
  pixel-identical (see TEST_REPORT screendump counts).
- New `cursortest` shell command: proves save/restore on
  plain background (teal restored, white cursor drawn).
- Desktop bochsrc.txt: vga update_freq 5 -> 30. Bochs'
  display refresh was 5 Hz, which capped visible smoothness
  no matter how fast the kernel drew. (Android Bochs: if
  your app exposes an update-frequency setting, set it to
  20-30; if not, the kernel fixes above still apply.)

## NOT fixed by this build, stated plainly

Bochs on a phone is an interpreter and will always be slower
than QEMU on a PC (dynamic translation, ~10-50x). If the GUI
still feels slow on Android after v0.7.4, QEMU on a PC is the
faster path, and the remaining cost is Bochs emulation, not
kernel redraws. Real mouse movement in Bochs/QEMU still NOT
tested with a real pointer (same limit as before: driver via
mousetest, WM via wmautotest, cursor via cursortest).

## NOT implemented / NOT tested

Desktop shell/graphical login (Phase 8), user GUI programs,
mouse wheel, package signing, passphrase change/recovery,
authenticated encryption. Android Bochs itself NOT tested in
this sandbox (no Android device).
