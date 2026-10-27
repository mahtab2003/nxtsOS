# nxtsOS v0.7.4 — Test Report

Kernel: build/nxtsOS.bin 79K (see SHA256SUMS for archives).
All tests run 2026-10-27 on the v0.7.4 ISO, QEMU 8.2.2 and Bochs 2.7 in sandbox.

## QEMU PASS

- tests/qemu_test_v071.py: fbinfo, guitest, mousetest,
  wmautotest, idle 120/5/off/120, logout cycle, mem — PASS,
  no EXCEPTION/PANIC/page fault.
- tests/security_test_gui.py: first run FAILed only on the
  screendump step because the test harness typed "ggui"
  (a QEMU monitor sendkey duplication, shell reported
  "Unknown command: ggui", so gui never started and the
  screendump showed the text console). Rerun PASS with
  identical screendump counts to v0.7.0-0.7.3:
  teal 215200 / blue 5798 / white 9671 / cursor (400,300)
  white — proving the new clip/cursor rendering is
  pixel-identical to the old full redraw. The "ggui"
  flake did not reproduce on rerun and is not a v0.7.4
  code change (no shell/keyboard input code was touched
  except adding the cursortest command).
- tests/qemu_test.py (base, 128 MB): all markers — PASS.
- New cursortest (ad-hoc QEMU harness, /tmp/cursor_test.py):
  old_restored=0x106040 new=0xFFFFFF mid_restored=0x106040
  final=0xFFFFFF — cursortest PASS (background restored
  to teal, cursor drawn white, twice in a row).

## Bochs 2.7 desktop PASS

- Ad-hoc harness (Xvfb + SDL2 + xdotool, shipped bochsrc.txt
  with update_freq=30): prompt, kbdstat, mem, guitest PASS,
  framebuffer present, no EXCEPTION/PANIC/page fault.

## NOT tested

- Real mouse movement/clicking (same limit as before).
- Android Bochs on a real phone (no Android device).
- A measured frame-rate before/after on the user's phone:
  the sandbox cannot measure Android Bochs fps, so the
  improvement is argued from pixel counts (480,000 ->
  ~442 for cursor moves, ~70,000-140,000 for drags at
  30 Hz instead of 100 Hz) and verified by rendering
  correctness, not by a phone fps number.
