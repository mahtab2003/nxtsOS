# Changelog

## 0.1.0 — first bootable kernel (Phase 2)

- Multiboot (GRUB) boot, 32-bit x86 original kernel.
- VGA text console + COM1 serial mirror.
- Multiboot memory-map parsing, bitmap physical memory manager.
- IDT, PIC remap, PIT 100 Hz timer, PS/2 keyboard.
- In-kernel shell: help, mem, ticks, clear, reboot.
- Panic path for unhandled exceptions.
- Boot test: PASS under Unicorn CPU emulation (see releases/v0.1.0/TEST_REPORT.md).
  QEMU boot test: NOT TESTED yet (QEMU package download still in progress
  in the build sandbox at packaging time).
- Not included: GUI/desktop, filesystem/persistence, networking, user
  processes/syscalls, privilege separation.
