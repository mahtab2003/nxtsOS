# nxtsOS v0.7.2 — Release Manifest (bugfix on Phase 7)

- Version: 0.7.2 (bugfix, not a new phase)
- Kernel binary: `build/nxtsOS.bin`
- Bootable image: `build/nxtsOS.iso` (El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh`
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.7.2` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.7.2-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.7.2-dist.zip` (now includes bochsrc.txt)
- Checksums: `releases/v0.7.2/SHA256SUMS`

## Fixed in v0.7.2 (user-reported, 2026-10-27, tested in Bochs 2.7)

- GUI in Bochs: VBE fallback now tries PCI BAR, then fixed LFB
  0xE0000000 (Bochs ISA VGA); shipped tested config/vm/bochsrc.txt
  (vbe + stdvga). Bochs stdvga: framebuffer 800x600, guitest PASS.
  Cirrus/isavga proven unfixable in kernel — use the shipped config.
- Keyboard after boot: shell/login/lock/WM now poll the keyboard
  controller every timer tick in addition to IRQ1 (mouse data
  guarded by status bit 5). Bochs keyboard IRQ works in sandbox
  tests; focus (click Bochs window, then type) is the remaining
  check on the user's machine.
- Boot log now prints Multiboot failure reason with bpp/type.

## NOT implemented / NOT tested

Desktop shell/graphical login (Phase 8), user GUI programs,
mouse wheel, package signing, passphrase change/recovery,
authenticated encryption. Real mouse movement in Bochs NOT
tested (mouse detected, no real-pointer test in sandbox).
