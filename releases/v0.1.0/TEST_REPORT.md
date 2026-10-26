# nxtsOS v0.1.0 — Test Report

## Test 1: Build — PASS

- Command: `./scripts/build.sh`
- Result: kernel links clean (one expected linker note: a single RWX LOAD
  segment, normal for a ring-0 kernel image), ISO produced by grub-mkrescue.
- Kernel: 13,552 bytes. ISO: 5,136,384 bytes.
- `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK.

## Test 2: Multiboot header placement — PASS (static check)

- Parsed the ELF LOAD segment: first 12 bytes are
  `02 b0 ad 1b 03 00 00 00 fb 4f 52 e4` — magic 0x1BADB002, flags 0x3,
  checksum valid, at load address 0x100000.
- A previous build had the header in a non-alloc section (excluded from
  the LOAD segment); that was found by this check and fixed before release.

## Test 3: Kernel boot under Unicorn CPU emulation — PASS

- Command: `python3 tests/unicorn_boot.py build/nxtsOS.bin`
- Harness: loads ELF LOAD segments at 1 MiB, supplies a fake Multiboot
  info block (mem_lower 640 KiB, mem_upper 130048 KiB, 128 MiB memory map),
  hooks COM1 OUT/IN, stops at the shell prompt.
- Serial log (full log in `logs/unicorn_serial.log`):

```
nxtsOS kernel starting
nxtsOS v0.1.0 - original kernel, Multiboot boot
Multiboot: mem_lower=640K mem_upper=130048K mmap_len=48
PMM: total=32768 frames free=32501 frames
Interrupts enabled

Welcome to nxtsOS. Type help.
nxts> 
```

- Markers found: `nxtsOS kernel starting`, `PMM:`, `Interrupts enabled`,
  `nxts> ` — all FOUND.
- PMM arithmetic checks out: 32768 frames = 128 MiB; 267 used frames
  ≈ first 1 MiB (256 frames) + kernel image (11 frames).

## Test 4: Host source check — PASS

- Command: `python3 tests/check_source.py` → PASS (all required modules
  present, no build artefacts in the source tree).

## Test 5: QEMU boot (ISO, 128 MB, monitor-typed `help` + `mem`) — NOT TESTED

- Script ready: `scripts/test_boot.sh` → `tests/qemu_test.py`
  (boots the ISO headless, types via the QEMU monitor, checks the serial
  log for boot markers, the help text, and the memory report).
- Why not run: QEMU was not installed in the build sandbox, and its
  package download through the sandbox proxy runs at tens of KB/s;
  at packaging time the download was still in progress.
- Consequence: timer ticks, keyboard input, VGA display, and GRUB→kernel
  handoff in a real VM are all UNVERIFIED for v0.1.0. The Unicorn run
  does not verify them (it injects no interrupts and emulates no PIC,
  PIT, or keyboard hardware). Do not report them as verified.

## Checklist (from the release requirements)

- [x] Image builds, kernel is nxtsOS's own, Multiboot header verified
- [x] Kernel reaches its implemented operating state (shell prompt) — under Unicorn
- [ ] Boots in QEMU — NOT TESTED (see Test 5)
- [ ] Graphical desktop — NOT IMPLEMENTED (Phase 4–5)
- [ ] Storage persistence — NOT IMPLEMENTED (Phase 6)
- [ ] Networking — NOT IMPLEMENTED (Phase 7)
- [x] Source archive, dist archive, SHA-256 checksums, manifest, test report
- [x] Local git history + tag v0.1.0
- [ ] Remote publishing — NOT DONE, no authorised account connected
