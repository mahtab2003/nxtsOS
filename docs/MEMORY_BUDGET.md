# Memory Budget

Targets (development targets, not guarantees):

- 32–64 MB: minimal text/diagnostic configuration — investigate, not promised.
- 128 MB: basic graphical desktop (future phase).
- 256 MB: comfortable graphical desktop with additional services (future phase).

## Measured in v0.1.0

- QEMU (v0.1.1, kernel-reported PMM): 128 MB → 32736 frames total,
  32469 free, 267 used (1068 KiB); 64 MB → 16352 frames total, 16085
  free, 267 used. Unicorn (simulated 128 MB): 32768 total / 32501 free
  (difference is the real GRUB memory map, which reserves more regions).
- Kernel binary (`build/nxtsOS.bin`): see the release manifest for its
  exact size; it is a few tens of KiB.
- Kernel stack: 16 KiB, statically reserved.
- PMM bitmap: 1 bit per 4 KiB frame — 4 KiB of bitmap per 128 MB of RAM,
  allocated statically in BSS and sized for up to 512 MB in v0.1.0.
- Guest "memory used" is reported by the kernel itself as PMM frames
  allocated (kernel-reserved regions + bitmap), printed by the `mem`
  command. Host QEMU process RSS is a different number and is not
  presented as guest usage.

No idle-memory figure for a graphical desktop can honestly be reported
yet, because there is no graphical desktop in v0.1.0. That measurement
belongs to Phase 5 and will be recorded then, from the VM.
