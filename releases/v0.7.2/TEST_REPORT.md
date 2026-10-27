# v0.7.2 test report (QEMU 8.2.2 + Bochs 2.7, 2026-10-27)

Build PASS: kernel 76,396 bytes;
ISO 5,195,776 bytes; Multiboot OK; GRUB menu v0.7.2; banner v0.7.2.

BOCHS 2.7 (Xvfb + SDL2, xdotool keys, serial log as truth):
- stdvga + vbe extension (shipped bochsrc): v0.7.1 FAILED with
  "VBE fallback: no PCI display BAR found". v0.7.2 PASS:
  "Framebuffer: 800x600, pitch 3200, phys 0xE0000000 (VBE
  fallback)", `fbinfo` ready, `guitest PASS` (demo 4, neg/huge/
  off/tiny clamped, count 8, corner pixels background), keys
  typed AFTER the prompt (no early Enter presses) worked.
- cirrus + cirrus VGABIOS: kernel VBE "no Bochs VBE device (ID
  check failed)"; GRUB with and without `insmod vbe` gave
  Multiboot bpp=1 type=0 (rejected correctly); final: no
  framebuffer. PROVEN UNFIXABLE in kernel for 800x600x32.
- isavga (Bochs default): same ID failure, no framebuffer.
  PROVEN UNFIXABLE in kernel (no VBE at all).
- GRUB `insmod vbe` tested in Bochs stdvga: GRUB set a broken
  1bpp mode (bpp=1 type=0); kernel rejected it, VBE fallback
  then gave the correct 800x600x32. insmod NOT adopted.

QEMU 8.2.2 PASS: tests/qemu_test_v071.py (fbinfo, guitest,
mousetest, wmautotest, idle, logout->mem), tests/security_test_gui.py
(screendump 800x600, teal/blue/white, cursor), tests/qemu_test.py
(base). Keyboard polling: no regression in QEMU or Bochs IRQ
input; mouse data guarded by status bit 5 (mousetest PASS).

NOT TESTED: real mouse movement in Bochs (mouse detected, but
no real-pointer test in sandbox — same limit as QEMU); the
user's exact "keys only if pressed during boot" trigger could
not be reproduced in sandbox Bochs (keyboard IRQ works there)
— polling + focus guidance are the fix, and the user should
confirm keys work after the prompt in the shipped bochsrc.
