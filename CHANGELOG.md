# Changelog

## 0.2.0 — Phase 3: paging, processes, syscalls, scheduler

- Paging: identity-mapped kernel region (0-32 MB), per-process page
  directories sharing the kernel entries, user code at 0x08048000 and
  user stack at 0x0C000000, page 0 left unmapped.
- Own GDT extended with user code/data (0x18/0x20) and a TSS (0x28);
  ring-3 -> ring-0 transitions switch to a per-process kernel stack.
- Syscalls via int 0x80: print, yield, exit, getpid, ticks. Print
  pointers are validated against the process's mapped pages first.
- Scheduler: round-robin over two ring-3 test processes, cooperative
  yield plus 100 ms timer preemption (proven: P1 iter 1 prints during
  P2's busy loop, before P2 iter 1).
- Bug fixed during testing: after a yield/exit/preempt the scheduler
  returned with IF cleared, so the shell's hlt loop never woke for
  keyboard input. run_process() now re-enables interrupts on return.
- Known limitation: exited processes' frames (page directories, tables,
  code/stack pages) are not freed yet — process teardown is later work.
  After the two test processes exit, PMM used rises from 267 to 297 frames.

# Changelog

## 0.1.1 — QEMU-verified bugfix (no new features)

- FIX: kernel installs its own GDT (code 0x08, data 0x10) before interrupts.
  This fixes the v0.1.0 QEMU reboot loop (GRUB's GDT uses 0x10/0x18, so the
  first timer IRQ triple-faulted on CS=0x08).
- QEMU boot test: PASS at 128 MB (`help`, `mem`) and 64 MB; `ticks` shows
  the PIT counting in the VM (214 ticks / 2 seconds).
- v0.1.0 is superseded — do not distribute it.

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
