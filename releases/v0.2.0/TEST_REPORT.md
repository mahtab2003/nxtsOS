# nxtsOS v0.2.0 — Test Report

## Test 1: Build — PASS

- Command: `./scripts/build.sh` (user program built first, then kernel,
  then ISO). Kernel 18,828 bytes, ISO 5,142,528 bytes.
- `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK.

## Test 2: QEMU user processes, 128 MB — PASS

- Command: `python3 tests/qemu_test_user.py build/nxtsOS.iso 128 logs/serial_user128.log`
- Serial log (abridged):

```
nxtsOS kernel starting
nxtsOS v0.2.0 - original kernel, Multiboot boot
PMM: total=32736 frames free=32460 frames
GDT installed (kernel 0x08/0x10, user 0x18/0x20, TSS 0x28)
Paging enabled (kernel identity-mapped 0-32 MB)
Interrupts enabled
User program blob: 484 bytes
Process 1 created: pd=0x11D000 code_pages=2
Process 2 created: pd=0x123000 code_pages=2
P1 iter 0
P2 iter 0
P1 iter 1
P1 iter 2
P2 iter 1
P1 iter 3
P1 iter 4
P2 iter 2
P2 iter 3
P2 iter 4
All user processes finished.
```

- All 10 iteration lines present. Preemption proven: P1 iter 1 and iter 2
  print during P2's first busy loop, before P2 iter 1 — without timer
  preemption, P1 iter 1 could only appear after all of P2's iterations.

## Test 3: QEMU shell after processes, 128 MB — PASS

- Command: `./scripts/test_boot.sh` (polls for the shell prompt, then
  monitor-types `help` and `mem`).
- Markers found: boot, PMM, GDT, Interrupts enabled, shell prompt,
  help text, memory report (`total 32736 frames, free 32439, used 297`
  — up from 267 at boot, because paging structures and the exited
  processes' frames are not freed yet; see known limitations).
- Bug found and fixed during this test: the first version of Phase 3
  left interrupts disabled after a process switch, so the shell prompt
  printed but keyboard input never arrived (hlt with IF=0 never wakes).
  Fix: `run_process()` re-enables interrupts on return. Both tests pass
  after the fix.

## Test 4: QEMU user processes, 64 MB — PASS

- Command: `python3 tests/qemu_test_user.py build/nxtsOS.iso 64 logs/serial_user64.log`
- Result: PASS, same checks as Test 2 (all iterations, finished marker,
  shell prompt, preemption proof).

## Test 5: Unicorn boot — PASS

- Command: `python3 tests/unicorn_boot.py build/nxtsOS.bin` → PASS
  (boot to shell prompt; note Unicorn injects no interrupts, so it does
  not exercise the scheduler — QEMU tests 2–3 are the evidence for that).

## Test 6: Host source check — PASS

- Command: `python3 tests/check_source.py` → PASS.

## Checklist

- [x] Boots in QEMU, reaches shell, keyboard works
- [x] Paging enabled, ring-3 processes run, syscalls work
- [x] Scheduler interleaves processes; timer preemption proven
- [ ] Graphical desktop — NOT IMPLEMENTED (Phase 4–5)
- [ ] Storage persistence — NOT IMPLEMENTED (Phase 6)
- [ ] Networking — NOT IMPLEMENTED (Phase 7)
- [ ] Process teardown / frame reclaim — NOT IMPLEMENTED (known limitation)
- [x] Source archive, dist archive, SHA-256 checksums, manifest, test report
- [x] Local git history + tag v0.2.0
- [ ] Remote publishing — NOT DONE, no authorised account connected
