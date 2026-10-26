# v0.7.0 test report (QEMU 8.2.2, 2026-10-27)

Build PASS: kernel 71,020 bytes; ISO 5,195,776 bytes; Multiboot OK;
GRUB menu v0.7.0; kernel banner v0.7.0.

- tests/security_test_gui.py PASS: Boot 1 mousetest (packet parsing:
  (50,30) -> 450,270 left=1; release -> left=0; dx -128 -> 322;
  large moves clamped to 799,0; overflow packet movement ignored,
  buttons applied), guitest (demo 4 windows; neg/huge/off/tiny
  created and clamped: neg x=-100 y=0, huge w=800 h=600, off
  x=700 y=550, extra=0 overflow=-1 count=8 max 8, corner pixels
  0x106040 background after cleanup), wmautotest (Button OK
  clicked, window dragged to 140,90, Shell exit), no EXCEPTION/
  PANIC/page fault. Boot 2 GUI screendump 800x600, teal background
  215,200 pixels, title blue 5,798, white 9,671, cursor pixel at
  (400,300) white.
- Framebuffer text console verified by screendump: boot logs,
  test programs, and shell prompt render in graphics mode with the
  8x16 font (see docs/GRAPHICS.md, four bugs fixed during bring-up).
- Regressions PASS (fresh disks): tests/qemu_test_enc.py,
  tests/security_test_enc.py, tests/qemu_test_pkg.py,
  tests/qemu_test.py (base, 128 MB). Earlier stale-disk FAILs in
  this cycle were disk-reuse artifacts, not kernel regressions:
  enc/pkg test disks are mutated by a run (package installed), so
  they must be recreated before each run; after recreation both
  PASS.
- NOT TESTED in QEMU: real mouse movement via monitor/VNC.
  QEMU monitor mouse_move/button, mouse_set, and VNC PointerEvent
  messages delivered zero PS/2 packets to the guest in this sandbox
  (proven by controller polling and IRQ debug logging, across
  -display none, VNC, and -vga std). Driver logic is proven via
  mousetest packet injection, WM click/drag via wmautotest scripted
  mouse states. Real mouse movement needs a desktop QEMU/VirtualBox
  check by the user — see docs/GRAPHICS.md.
