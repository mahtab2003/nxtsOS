# Memory Budget

Targets (development targets, not guarantees):

- 32–64 MB: minimal text/diagnostic configuration — investigate, not promised.
- 128 MB: basic graphical desktop (shipped in v0.10.0 — CORRECTION:
  this line used to say "future phase"; the desktop exists now, and
  every desktop QEMU test boots at 128 MB, but no idle-memory figure
  for it has been measured yet, so 128 MB remains a target, not a
  measured result).
- 256 MB: comfortable graphical desktop with additional services
  (shipped in v0.10.0 — CORRECTION: this line used to say "future
  phase"; the desktop exists now, but no idle-memory figure for it
  has been measured yet, so "comfortable" at 256 MB remains a target,
  not a measured result).

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
yet. CORRECTION: this paragraph used to say there was no graphical
desktop (true in v0.1.0) and that the measurement belonged to Phase 5.
The desktop shipped in v0.10.0 (Phase 10, not Phase 5), and its Monitor
window does report "Memory used (KiB)" live (kernel/wm.c) — but no
reading of that figure has been taken from a booted desktop yet (it is
framebuffer text, not a serial line, so it needs a screendump read, not
a log grep), so the idle figure remains outstanding and will be
recorded from the VM when it is measured.
