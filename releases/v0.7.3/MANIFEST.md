# nxtsOS v0.7.3 — Release Manifest (bugfix on Phase 7)

- Version: 0.7.3 (bugfix, not a new phase)
- Kernel binary: `build/nxtsOS.bin`
- Bootable image: `build/nxtsOS.iso` (El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh`
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.7.3` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.7.3-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.7.3-dist.zip` (includes bochsrc.txt)
- Checksums: `releases/v0.7.3/SHA256SUMS`

## Fixed in v0.7.3 (user-reported, 2026-10-27, Android Bochs video)

- PS/2 controller now properly initialised at startup (drivers/keyboard.c):
  both ports disabled, output buffer flushed, configuration byte read
  and written back with IRQ1 + IRQ12 + translation on and keyboard
  clock enabled, keyboard port re-enabled, output flushed again,
  scancode set explicitly set to 2 (BIOS standard; with translation
  on the CPU sees set 1, which this driver expects). Before v0.7.3
  keyboard_init() only reset the software buffer and never touched
  the controller, so a byte left in its 1-byte output buffer by
  GRUB/BIOS (key pressed/released while GRUB loaded the kernel, a
  held key repeating) stayed there forever: the PIC reinitialisation
  forgot its IRQ, the full buffer accepted no new bytes and raised
  no new IRQ, and the keyboard looked dead from the first prompt
  on, on any emulator. Mashing Enter during loading sometimes
  cleared it — exactly the reported symptom.
- Polling now drains mouse bytes too (previously it skipped status
  bit 5 forever): a lodged mouse byte can no longer block keyboard
  bytes behind it in the 1-byte output buffer.
- Mouse packet assembly resync: mouse_test_set() resets the packet
  index, and a first byte without bit 3 is discarded immediately
  instead of starting a packet that shifts every following packet.
  This was found by the v0.7.3 tests: after the polling change,
  mousetest failed (450,270 became 400,300) until the packet index
  was reset — a stray drained mouse byte had left it at 1 or 2.
- Diagnostics that need no typing: the first shell prompt prints
  "Keyboard: startup drained N byte(s) from the PS/2 controller",
  and a new `kbdstat` command prints controller status, startup
  drained count, and last raw scancode. If drained > 0, a lodged
  byte was the failure and this build already drained it. If
  drained = 0 and keys still do nothing, no bytes are reaching the
  controller at all (emulator/app side, see VM_GUIDE).

## NOT implemented / NOT tested

Desktop shell/graphical login (Phase 8), user GUI programs,
mouse wheel, package signing, passphrase change/recovery,
authenticated encryption. Real mouse movement in Bochs NOT
tested (mouse detected, no real-pointer test in sandbox).
Android Bochs itself NOT tested in this sandbox (no Android
device): the kernel fix above addresses the provable kernel
cause, and the new diagnostic line tells the user which case
applies on their phone. If the Android app drops system-IME
input before Bochs (no bytes reach the controller), the kernel
cannot fix that — use the app's built-in virtual PC keyboard
or a physical USB/Bluetooth keyboard, or QEMU on a PC.
