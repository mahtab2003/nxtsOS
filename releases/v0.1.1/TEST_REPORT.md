# nxtsOS v0.1.1 — Test Report

## Test 1: Build — PASS

- Command: `./scripts/build.sh`
- Result: kernel links clean (one expected linker note: a single RWX LOAD
  segment, normal for a ring-0 kernel image), ISO produced by grub-mkrescue.
- `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK.

## Test 2: QEMU boot, 128 MB — PASS (this is the test v0.1.0 failed)

- Command: `./scripts/test_boot.sh` → `tests/qemu_test.py`
  (QEMU 8.2.2, headless, monitor-typed `help` + `mem`, serial-log checks)
- Serial log:

```
nxtsOS kernel starting
nxtsOS v0.1.1 - original kernel, Multiboot boot
Multiboot: mem_lower=639K mem_upper=129920K mmap_len=168
PMM: total=32736 frames free=32469 frames
GDT installed (code 0x08, data 0x10)
Interrupts enabled

Welcome to nxtsOS. Type help.
nxts> help
Commands: help, mem, ticks, clear, reboot
nxts> mem
Memory: total 32736 frames (130944 KiB), free 32469 frames (129876 KiB), used 267 frames (1068 KiB)
nxts> 
```

- Markers found: `nxtsOS kernel starting`, `PMM:`, `GDT installed`,
  `Interrupts enabled`, `nxts> `, help text, memory report — all FOUND.
- Monitor-typed input reaching the shell proves the PS/2 keyboard IRQ
  path works in the real VM. The VM staying up for the whole run proves
  the 100 Hz timer IRQ no longer triple-faults.

## Test 3: QEMU boot, 64 MB — PASS

- Same test at `-m 64`: PASS, with
  `Memory: total 16352 frames (65408 KiB), free 16085 frames (64340 KiB)`.

## Test 4: QEMU `ticks` command — PASS

- Separate QEMU run, monitor-typed `ticks`:
  `Timer ticks: 214 (2 seconds at 100 Hz)` — the PIT counter is really
  counting timer interrupts in the VM.

## Test 5: Unicorn CPU-emulator boot — PASS

- Command: `python3 tests/unicorn_boot.py build/nxtsOS.bin` → PASS
  (boot to shell prompt, PMM counts for 128 MiB).

## Test 6: Host source check — PASS

- Command: `python3 tests/check_source.py` → PASS.

## The v0.1.0 reboot loop, for the record

- v0.1.0 in QEMU printed up to `PMM:` and then reset, repeating
  "nxtsOS kernel starting" forever. QEMU `-d int` logging showed the
  first timer interrupt (`INT=0x20`) followed by a general-protection
  fault with error code 0x0008 (the bad CS selector), then double
  fault, then reset. Cause: IDT gates and ISR stubs used selectors
  0x08/0x10, but GRUB's GDT uses 0x10/0x18. Fix in v0.1.1: the kernel
  installs its own GDT before `idt_init()`. Unicorn did not catch this
  because it injects no interrupts and uses flat default segments.

## Checklist

- [x] Image builds, kernel is nxtsOS's own, Multiboot header verified
- [x] Boots in QEMU at 128 MB and 64 MB, reaches the shell, keyboard works
- [x] Timer ticks verified in the VM
- [ ] Graphical desktop — NOT IMPLEMENTED (Phase 4–5)
- [ ] Storage persistence — NOT IMPLEMENTED (Phase 6)
- [ ] Networking — NOT IMPLEMENTED (Phase 7)
- [x] Source archive, dist archive, SHA-256 checksums, manifest, test report
- [x] Local git history + tag v0.1.1
- [ ] Remote publishing — NOT DONE, no authorised account connected
