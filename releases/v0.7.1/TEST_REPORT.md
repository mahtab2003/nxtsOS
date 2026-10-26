# v0.7.1 test report (QEMU 8.2.2, 2026-10-27)

Build PASS: kernel 76,152 bytes; ISO 5,195,776 bytes;
Multiboot OK; GRUB menu v0.7.1 with gfxmode; kernel banner v0.7.1.

- tests/qemu_test_v071.py PASS (normal boot): fbinfo shows
  "Framebuffer: 800x600 ... (Multiboot)", guitest PASS, mousetest
  PASS, wmautotest PASS, idle default 120 minutes, idle 5 sets to
  5, idle off disables, idle 120 restores, logout -> second
  "Welcome to nxtsOS" -> mem works (terminal works after session
  close), no EXCEPTION/PANIC/page fault.
- VBE fallback PASS (proof in QEMU): test kernel with Multiboot
  VIDEO flag removed + GRUB menu with no gfxmode booted with
  "Framebuffer: 800x600, pitch 3200, phys 0xFD000000 (VBE
  fallback)" and the same v071 test PASS (guitest/mousetest/
  wmautotest/idle/logout). QEMU std VGA is Bochs-compatible.
- tests/security_test_gui.py PASS (screendump 800x600, teal
  215,200 / blue 5,798 / white 9,671, cursor at 400,300 white).
- Regressions PASS (fresh disks): tests/qemu_test_enc.py,
  tests/qemu_test_pkg.py, tests/qemu_test.py (base).
- One real regression caught and fixed during testing: an
  unconditional keyboard flush on login discarded buffered
  login/help keys on first boot (base and encryption tests
  failed). Flush now applies only on re-login, not first boot —
  the boot message promise "keys typed now are buffered" is kept.
- NOT TESTED: Bochs itself (not installed in this sandbox) and
  real mouse movement via QEMU/VNC (see v0.7.0 report). The user
  must confirm `gui` starts in Bochs on v0.7.1 and report `fbinfo`
  output if it does not.
