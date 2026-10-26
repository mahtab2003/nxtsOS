# v0.7.0 security report (adversarial test, 2026-10-27)

- tests/security_test_gui.py PASS (see TEST_REPORT.md). No
  exploitable findings in the graphics/input code.
- One real bug fixed before release: a button triggered on
  release even if the mouse had been dragged off the button.
  Release handling now checks the mouse is still inside the button
  rect before triggering.
- Four bring-up bugs fixed before release (not security findings,
  but recorded in docs/GRAPHICS.md): Multiboot header video offset
  32, Multiboot info framebuffer offset 88, Multiboot info page
  overwritten by PMM, framebuffer not shared with user PDs (first
  user print in graphics mode page-faulted).
- Known gaps, stated not hidden (see docs/GRAPHICS.md):
  real mouse movement via QEMU/VNC not tested in this sandbox
  (QEMU did not inject packets); user GUI programs do not exist
  yet, so there is no GUI syscall permission surface to attack in
  v0.7.0 — Phase 8 must add permission checks for GUI apps.
  Package signing, passphrase change/recovery, and authenticated
  encryption remain unimplemented, as in v0.6.0.
