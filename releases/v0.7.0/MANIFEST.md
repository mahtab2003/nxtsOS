# nxtsOS v0.7.0 — Release Manifest (Phase 7 graphics and input)

- Version: 0.7.0 (Phase 7)
- Kernel binary: `build/nxtsOS.bin` (71,020 bytes)
- Bootable image: `build/nxtsOS.iso` (5,195,776 bytes, El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh`
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.7.0` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.7.0-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.7.0-dist.zip`
- Checksums: `releases/v0.7.0/SHA256SUMS`

## Implemented (v0.7.0)

- VBE 800x600x32 framebuffer via Multiboot (kernel/fb.c, boot/boot.S),
  8x16 font (tools/genfont.py, kernel/font_data.h), framebuffer text
  console (kernel/console.c, RAM text buffer), PS/2 mouse IRQ12
  (drivers/mouse.c), window manager (kernel/wm.c: move/resize/
  minimise/maximise/close/focus/z-order/clipping/taskbar, button/
  label/text-field widgets), shell commands gui/guitest/wmautotest/
  mousetest/mouse/mousepoll, docs/GRAPHICS.md.

## NOT implemented (explicit)

Desktop shell/graphical login (Phase 8), user GUI programs,
mouse wheel, package signing, passphrase change/recovery,
authenticated encryption. Real mouse movement via QEMU/VNC is
NOT TESTED in this sandbox (see docs/GRAPHICS.md).

## Remote publishing

NOT DONE. Muse GitHub App repository selection for mahtab2003/nxtsOS
is still pending; no push has been made.
