# nxtsOS

An original, ultra-lightweight desktop operating system, built from scratch.
Not a Linux distribution, not a fork, not a re-themed desktop: nxtsOS boots
its own kernel.

## Status — v0.7.1 (Graphics + window manager, NOT a desktop shell yet)

What actually works in v0.7.1, verified by booting the real ISO in QEMU:

- Multiboot boot path (GRUB), 32-bit x86 kernel written from scratch.
  The GRUB menu version is now generated from the `VERSION` file at
  build time, so it cannot go stale again (v0.3.0's menu still said
  v0.2.0 — fixed in v0.3.1).
- VGA text console + serial (COM1) diagnostic log
- Multiboot memory-map parsing and a bitmap physical-memory manager
- IDT, remapped PIC, PIT timer ticks, PS/2 keyboard input (buffered:
  keys typed before the shell appears are not lost)
- Paging, ring-3 user processes, int 0x80 syscalls, round-robin
  scheduler with yield + 100 ms timer preemption, process teardown
  (exited processes' frames are freed)
- ATA PIO disk driver, VFS + nxtsFS filesystem (persistent files that
  survive a guest reboot), host disk tool `tools/mkdisk.py`
- A tiny in-kernel shell: `help`, `mem`, `ticks`, `clear`, `reboot`,
  `fs`, `ls`, `cat <file>`, `write <file> <text>`, `rm <file>`,
  `run <file>`, `runbg <file>`, `jobs`, `kill <pid>`, `lock`,
  `unlock <user>`, `whoami`, `logout`
- ELF loader from disk, users/permissions, text login with sessions
  and an audit log (see `docs/SECURITY.md` for the honest limits)
- Graphics + window manager: see `docs/GRAPHICS.md`. 800x600x32
  framebuffer, 8x16 font, framebuffer text console, PS/2 mouse,
  in-kernel window manager (`gui` command: move/resize/minimise/
  maximise/close/focus/taskbar, button/label/text-field widgets).
  v0.7.1 adds a Bochs VBE fallback so `gui` starts even when GRUB
  sets no graphics mode (proven in QEMU with the Multiboot video
  request removed), plus `fbinfo` to diagnose a missing
  framebuffer. Real mouse movement via QEMU/VNC was NOT testable
  in the build sandbox (QEMU did not inject mouse packets) — test
  `gui` with a real mouse on your machine; driver + WM click/drag
  logic are proven via `mousetest`/`wmautotest`. Bochs itself is
  NOT tested here (not installed) — confirm `gui` starts in Bochs.
- Session: idle timeout is now configurable with `idle`
  (`idle 240` for 4 hours, `idle off` to never lock, default 120
  minutes, per-session). Terminal after logout/lock is fixed:
  stale keys are flushed on re-login and the console is redrawn
  after a lock.
- Disk encryption (AES-256-CTR, boot passphrase): see
  `docs/ENCRYPTION.md`. Encrypted disks are created on the host with
  `tools/mkdisk_enc.py` (needs openssl) and unlock at boot with a
  passphrase (3 attempts, then halt). Unencrypted disks boot
  unchanged. No passphrase change, no recovery, no authenticated
  encryption — see the limits in `docs/ENCRYPTION.md`.
- Package management (`pkg list/install/remove`, `sha256`): see
  `docs/PACKAGES.md`. Packages are verified by SHA-256 on install
  and on load, with dependency resolution, duplicate/upgrade handling,
  and removal protection. Signing is NOT implemented — hashes do not
  authenticate the author (see `docs/SECURITY.md`).
- Earlier fixes carried over: 10000-iteration password hash
  (regenerate v0.4.0 users.txt), background jobs, persistent
  brute-force lockout, 30-minute idle lock, fast startup test.
  Disk encryption is NOT in v0.5.0 — a real AES + key-management
  implementation is a full phase, and a fake XOR one was not added.
- Kernel panic path for unhandled exceptions (prints registers, halts)

What is NOT in v0.7.0 — do not mistake this release for it:

- No graphical desktop, window manager, or GUI applications yet
- No graphics, desktop, or networking yet
- No networking yet
- No installer

Those are Phases 5–11 in `docs/ROADMAP.md`. Each phase lands only when it
boots and is tested in QEMU, with an adversarial security test, before release.

## Quick start (QEMU)

```sh
./scripts/build.sh
python3 tools/mkdisk.py build/nxtsOS-disk.img --add hello.txt:/path/to/hello.txt
./scripts/run_qemu.sh          # 128 MB RAM, VGA + serial log to logs/serial.log
./scripts/run_qemu.sh 32       # 32 MB RAM also works (tested)
```

After boot, two built-in test programs run first and print `P1 iter` /
`P2 iter` lines — those are the startup programs, not a stuck test run.
Wait a few seconds and the `nxts> ` prompt appears; type `help` there.
Press Ctrl-Alt-Q in the QEMU window (or close it) to stop the VM.

Full instructions, tested configuration, and known issues:
`docs/VM_GUIDE.md`, `docs/BUILD_AND_TEST.md`, `releases/v0.3.0/TEST_REPORT.md`.

**v0.1.0 warning:** v0.1.0 rebooted in a loop in QEMU (wrong GDT selectors
— see `releases/v0.1.1/TEST_REPORT.md`). Do not use v0.1.0; use v0.7.1.
QEMU tests: `tests/security_test_gui.py`, `tests/qemu_test_enc.py`, `tests/security_test_enc.py`, plus package, Phase 5, base, and storage regressions — all PASS.

## Project layout

- `boot/` — Multiboot entry (GAS assembly), linker script
- `kernel/` — kernel main, console, shell, panic, processes, syscalls
- `drivers/` — VGA, serial, PIC, PIT, keyboard, ATA disk
- `mm/` — physical memory manager, paging
- `fs/` — VFS + nxtsFS filesystem
- `net/`, `graphics/`, `window_manager/`, `desktop/`,
  `system_services/`, `applications/`, `sdk/` — placeholders for later phases,
  each with a `STATUS.md` stating what is (not) implemented
- `tests/` — host-side checks + QEMU boot/persistence/security test scripts
- `scripts/` — build, run, and packaging scripts
- `releases/v0.3.0/` — manifest, checksums, test + security reports
- `archives/` — versioned source and distribution archives

## Build requirements

Host: Linux x86_64, `gcc` (with `-m32` freestanding support), GNU `as`/`ld`,
`grub-mkrescue` + `xorriso` (for the ISO), `qemu-system-x86_64` (for testing),
`python3`, `git`, `tar`, `zip`, `sha256sum`.

No cross-compiler is required: the kernel is built freestanding
with the host GCC (`-ffreestanding -nostdlib -m32`).

## Licence

MIT — see `LICENSE`. Third-party tools used (GRUB, QEMU, GCC) are not
nxtsOS code and are not claimed as such.
