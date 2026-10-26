# nxtsOS

An original, ultra-lightweight desktop operating system, built from scratch.
Not a Linux distribution, not a fork, not a re-themed desktop: nxtsOS boots
its own kernel.

## Status — v0.2.0 (Phase 3 complete, NOT a desktop yet)

What actually works in v0.2.0, verified by booting the real ISO in QEMU:

- Multiboot boot path (GRUB), 32-bit x86 kernel written from scratch
- VGA text console + serial (COM1) diagnostic log
- Multiboot memory-map parsing and a bitmap physical-memory manager
- IDT, remapped PIC, PIT timer ticks, PS/2 keyboard input
- A tiny in-kernel shell: `help`, `mem`, `ticks`, `clear`, `reboot`
- Kernel panic path for unhandled exceptions (prints registers, halts)

What is NOT in v0.1.0 — do not mistake this release for it:

- No graphical desktop, window manager, or GUI applications yet
- No filesystem / persistent storage yet
- No networking yet
- No user processes, syscalls, or privilege separation yet (kernel runs in ring 0)
- No installer

Those are Phases 3–9 in `docs/ROADMAP.md`. Each phase lands only when it
boots and is tested in QEMU the same way v0.1.1 was.

## Quick start (QEMU)

```sh
./scripts/build.sh
./scripts/run_qemu.sh          # 128 MB RAM, VGA + serial log to logs/serial.log
./scripts/run_qemu.sh 256      # 256 MB RAM
```

In the VM, type `help` at the `nxts> ` prompt. Press Ctrl-Alt-Q in the
QEMU window (or close it) to stop the VM.

Full instructions, tested configuration, and known issues:
`docs/VM_GUIDE.md`, `docs/BUILD_AND_TEST.md`, `releases/v0.1.0/TEST_REPORT.md`.

**v0.1.0 warning:** v0.1.0 rebooted in a loop in QEMU (wrong GDT selectors
— see `releases/v0.1.1/TEST_REPORT.md`). Do not use v0.1.0; use v0.2.0.
QEMU tests: `./scripts/test_boot.sh` and `tests/qemu_test_user.py` — PASS.

## Project layout

- `boot/` — Multiboot entry (GAS assembly), linker script
- `kernel/` — kernel main, console, shell, panic
- `drivers/` — VGA, serial, PIC, PIT, keyboard
- `mm/` — physical memory manager
- `fs/`, `net/`, `graphics/`, `window_manager/`, `desktop/`,
  `system_services/`, `applications/`, `sdk/` — placeholders for later phases,
  each with a `STATUS.md` stating what is (not) implemented
- `tests/` — host-side checks + QEMU boot test script
- `scripts/` — build, run, and packaging scripts
- `releases/v0.1.0/` — manifest, checksums, test report for this version
- `archives/` — versioned source and distribution archives

## Build requirements

Host: Linux x86_64, `gcc` (with `-m32` freestanding support), GNU `as`/`ld`,
`grub-mkrescue` + `xorriso` (for the ISO), `qemu-system-x86_64` (for testing),
`python3`, `git`, `tar`, `zip`, `sha256sum`.

No cross-compiler is required for v0.1.0: the kernel is built freestanding
with the host GCC (`-ffreestanding -nostdlib -m32`).

## Licence

MIT — see `LICENSE`. Third-party tools used (GRUB, QEMU, GCC) are not
nxtsOS code and are not claimed as such.
