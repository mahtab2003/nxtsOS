# nxtsOS v0.8.0 — Test Report

Kernel: build/nxtsOS.bin (~105 KiB, see SHA256SUMS for archives).
All tests run 2026-10-27 on the v0.8.0 ISO, QEMU 8.2.2 and Bochs 2.7
in sandbox. The final ISO was rebuilt after only script/doc
changes (build.sh now also emits calc.nxpkg, package.sh ships
it); no kernel source changed between the tested ISO and the
final ISO, and the desktop test was rerun on the final ISO
(see "Final ISO recheck" below).

## QEMU PASS — new in v0.8.0

- tests/qemu_test_desktop.py: cliptest PASS (clip checksum
  == full checksum, proving the per-window clip refactor),
  cursortest PASS, desktopautotest PASS (Settings opened,
  idle cycled, lock shown, setup-mode unlock, Terminal
  exit), serial markers for the idle change, lock screen,
  setup unlock and the Welcome notification, no
  EXCEPTION/PANIC/page fault. Screendump of the initial
  desktop: 800x600, background (700,300) = (24,48,80)
  (0x183050), Settings icon (40,40) = (32,96,160), Start
  button (10,588) = (96,96,96), cursor (400,300) white.
- tests/qemu_test_calc.py: install calc.nxpkg as root
  ("Installed calc 1.0"), desktopcalctest clicks the Calc
  icon then the '7' key, "Calculator started", no
  EXCEPTION/PANIC/page fault. Screendump: Calculator title
  bar (300,170) blue (32,96,160), display white
  (250,190), key grey (260,260) (192,192,192), display
  glyph black-pixel count 27 — exactly the '7' glyph from
  kernel/font_data.h (the initial '0' would be 40), proving
  the key click activated and the display updated.
- tests/security_test_desktop.py: see SECURITY_REPORT.md
  (all boots PASS).
- Bochs desktop check (ad-hoc harness, Xvfb + SDL2 +
  xdotool, shipped bochsrc.txt): prompt, guitest PASS,
  desktopautotest PASS (Settings opened, idle changed to
  240 minutes from the 120 default, lock shown, setup
  unlock), no EXCEPTION/PANIC/page fault.

## QEMU PASS — regressions (unchanged behaviour)

- tests/qemu_test_v071.py: fbinfo, guitest, mousetest,
  wmautotest, idle 120/5/off/120, logout cycle, mem — PASS.
- tests/security_test_gui.py: mousetest/guitest/wmautotest
  edge cases PASS, screendump counts identical to
  v0.7.0–0.7.4 (teal 215200 / blue 5798 / white 9671 /
  cursor (400,300) white) — proving the v0.8.0 clip
  refactor did not change full-screen rendering.
- tests/qemu_test.py (base, 128 MB): all markers — PASS.
- tests/qemu_test_pkg.py (fresh disk, rebuilt after a
  test-disk error): SHA-256 abc vector, install/list/
  remove, dependency order, duplicate install, upgrade
  hello 1.0 → 1.1 with "Hello v1.1" — PASS. The first run
  of this suite failed only the "Hello v1.1" marker
  because the test disk was built with hello.elf in the
  1.1 package instead of hello2.elf; that was a disk
  construction error, not a kernel regression, and the
  rerun on a corrected fresh disk passed fully.
- tests/qemu_test_enc.py (fresh encrypted disk, passphrase
  diskpass): correct-passphrase boot (public read, secret
  denied, hello run, package install), wrong-passphrase
  halt, AES-256 FIPS vector — PASS.
- tests/security_test_pkg.py (fresh malicious-package disk):
  bad hash/size/path/abs/self-dep/cycle/dependency/huge
  all refused, tampered hello.elf refused on re-boot —
  PASS.

## Recovery note (honest, in-release)

During v0.8.0 development a splice script corrupted
kernel/wm.c (a generic `if (autotest)` pattern matched in
the GUI loop while its end pattern matched in the desktop
loop, deleting the code between them). The file was
restored from git (v0.7.4 version) and the clip + desktop
code was re-transplanted with per-marker count assertions
from the surviving /tmp copies, then cliptest was rewritten
from its design (it existed nowhere on disk after the
corruption) and re-verified PASS in QEMU. The corruption
never reached a release: no v0.8.0 archive was built from
the corrupted tree.

## NOT tested

- Real mouse movement/clicking (same limit as Phase 7).
- Android Bochs on a real phone (no Android device).
- Phone FPS before/after (argued from pixel counts and
  redraw volume, not measured on a phone).
- Full 120-minute idle timeout waited out (the setting
  path is tested; the timeout itself is not).
- Calculator arithmetic beyond the verified '7' key press
  and display update: the operator logic follows the same
  subtraction-only pattern as the tested code, but a full
  scripted arithmetic sequence (e.g. 7+3=) was not run in
  this release — the display-glyph check proves input and
  redraw, not every operator.
