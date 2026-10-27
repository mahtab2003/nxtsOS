# nxtsOS v0.7.1 — Release Manifest (bugfix on Phase 7)

- Version: 0.7.1 (bugfix, not a new phase)
- Kernel binary: `build/nxtsOS.bin`
- Bootable image: `build/nxtsOS.iso` (El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh`
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.7.1` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.7.1-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.7.1-dist.zip`
- Checksums: `releases/v0.7.1/SHA256SUMS`

## Fixed in v0.7.1 (user-reported, 2026-10-27)

- GUI not starting in Bochs: GRUB gfxmode 800x600x32 +
  gfxpayload=keep, Bochs VBE fallback (IO ports + PCI BAR,
  verified by test pixel), `fbinfo` diagnostic.
- Session ends too quickly, no setting: idle timeout default
  30 -> 120 minutes, new `idle` command (0-480 minutes, off).
- Terminal doesn't work after session close: keyboard buffer
  flushed on re-login and lock (not first boot), console
  redrawn after idle lock, logout -> prompt -> command tested.

## NOT implemented / NOT tested

Desktop shell/graphical login (Phase 8), user GUI programs,
mouse wheel, package signing, passphrase change/recovery,
authenticated encryption. Bochs itself NOT tested here (not
installed); real mouse movement via QEMU/VNC NOT tested (see
v0.7.0 report). Confirm `gui` in Bochs on v0.7.1 and report
`fbinfo` if it still fails.
