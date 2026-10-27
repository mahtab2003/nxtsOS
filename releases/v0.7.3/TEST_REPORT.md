# nxtsOS v0.7.3 — Test Report

Kernel: build/nxtsOS.bin 77,852 bytes; ISO 5,201,920 bytes.
All tests run 2026-10-27 on the v0.7.3 ISO, QEMU 8.2.2 and Bochs 2.7 in sandbox.

## QEMU PASS

- tests/qemu_test_v071.py: fbinfo, guitest, mousetest, wmautotest,
  idle 120 -> 5 -> off -> 120, logout cycle, mem — all PASS, no
  EXCEPTION/PANIC/page fault. New diagnostic line present:
  "Keyboard: startup drained 0 byte(s)".
- tests/security_test_gui.py: mousetest (450,270 / 799,0),
  guitest, wmautotest, screendump 800x600 teal 215200 / blue 5798 /
  white 9671 / cursor (400,300) white — PASS.
- tests/qemu_test.py (base, 128 MB): all markers — PASS.
- tests/qemu_test_enc.py (fresh encrypted disk, passphrase
  diskpass): unlock, permissions, package install on encrypted
  disk, 3 wrong passphrases -> halt, AES FIPS vector — PASS.
  (First run failed pkg install only because the test disk was
  built with hello.elf already on disk, which pkg correctly
  refuses to overwrite; rebuilt without it, then PASS. That was
  a test-disk setup error, not a kernel regression.)
- tests/qemu_test_pkg.py (fresh disk): SHA-256 abc vector,
  dependency order, duplicate, upgrade to 1.1 — PASS.
- GRUB-phase key test (ad-hoc, /tmp/grubkey.py): 'a' stops GRUB
  countdown, Enter boots, then mem + ticks work — PASS on both
  v0.7.2 and v0.7.3 in QEMU. QEMU does NOT reproduce the user's
  Bochs/Android deadlock (GRUB consumes the key via BIOS, buffer
  clean at kernel entry), so this test proves the new init does
  not break QEMU, not that it fixes Bochs — stated honestly.

## Bochs 2.7 desktop PASS

- Ad-hoc harness (Xvfb + SDL2 + xdotool, shipped bochsrc.txt):
  prompt, kbdstat (controller status=0x10, startup-drained=0,
  last-scancode=0x9C after Enter), mem, guitest PASS,
  framebuffer present. No EXCEPTION/PANIC/page fault.

## Regression found and fixed during v0.7.3 testing

- mousetest failed after the polling change (first packet gave
  400,300 instead of 450,270, large moves stayed 400,300):
  a stray mouse byte drained by polling had left the mouse
  packet index at 1 or 2. Fixed by resetting the packet index
  in mouse_test_set() and discarding bit-3-clear first bytes in
  mouse_feed_byte(). Mousetest now passes in all suites above.

## NOT tested

- Android Bochs on a real phone (no Android device in sandbox).
- Real mouse movement/clicking in Bochs or QEMU (same limit as
  v0.7.0–v0.7.2: driver logic via mousetest, WM via wmautotest).
- Full 120-minute idle timeout (not waited out, as before).
