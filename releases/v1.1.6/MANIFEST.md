# nxtsOS v1.1.6 — Release manifest

- Version: 1.1.6 (accumulation release over v1.1.5: Linux-
  comparability + deep-core + all five core redesigns).
- Date: 2026-11-02.
- Kernel: original 32-bit x86 monolithic kernel, Multiboot 1 via GRUB.
  No Linux code, no distro, no fork, no re-theme.
- ISO: `nxtsOS.iso`, 5,687,296 bytes,
  SHA-256 `2f53912c3985200d4ceaff4c5354c62dd87624bdabee4070868b8e285813871d`
- Kernel binary: `build/nxtsOS.bin`, 563,812 bytes (at build time)
- Distribution contents: `nxtsOS.iso`, `calc.nxpkg`,
  `term.nxpkg`, `run_qemu.sh`, `bochsrc.txt`,
  `mkdisk.py`, `VM_GUIDE.md`, `BUILD_AND_TEST.md`, this manifest,
  `TEST_REPORT.md`, `SECURITY_REPORT.md`, `README.md`, `VERSION`,
  `SHA256SUMS` (SHA-256 of the ISO inside the dist folder).
- Source archive: the full source tree minus `build/`, `archives/`,
  `logs/`, `.git`, plus this release's three documents.
  The package signing key (`build/signing.key`) never ships in any
  archive. The compiled-in vendor public key ships as generated
  source (`kernel/vendor_pubkey.h`) so vendor-signed packages verify.
- Git: branch `main`, tag `v1.1.6` (local only; no GitHub push —
  the user did not authorise a push for this release).
  The exact commit hash is recorded in the delivery notes, not inside
  this manifest, because the manifest itself is part of the commit.
- Tested on: QEMU 8.2.2 (serial + VNC suites) — see
  TEST_REPORT.md. Bochs 2.7 was NOT re-run for v1.1.6
  (last Bochs pass: v0.10.0); see TEST_REPORT.md.

## What is in v1.1.6 (over v1.1.5)

- Real VFS tree with directories (82 checks): path traversal
  with permission-gated intermediate directories, symlink hop
  budget, hard links with scan-based sector freeing, chown/
  chgrp root-only in the fs layer.
- Block-device layer (30 checks): bounded queue with merging,
  read-only fsck, inactive swap slots (no backing area).
- Socket layer + TCP server (36 checks): firewall-before-
  dispatch, privileged ports root-only at bind and listen,
  clamped backlog, bounded RX with window-aware takes.
- SMP stabilised (52 checks): AP IRQ0/preempt root cause
  fixed (LINT0 masked, readiness signalled after LAPIC/TSS
  setup), lock order documented and held, LAPIC
  publish-before-map race fixed during this gate.
- Redesign 5 (79 checks): demand paging with VMA bounds and
  fault handling, vruntime scheduling, capabilities with
  honest no-op MAC hook, shell quoting, foreground Ctrl-C,
  multi-session foundations.
- Linux-comparability + deep-core: parity family, linuxcomp
  family, deepcore family, topk — mm/kmalloc arena,
  exit-status reap table, bg-only signals, per-process fd
  tables + syscalls 14–21, FIFOs, PROC_BLOCKED retry, brk
  heap, flock.
- Gate fixes (see TEST_REPORT.md): LAPIC race panic fix;
  sysupdate snapshot stack-overflow fix (journal arrays
  moved to file-scope statics).
- Still genuinely not done (honest): swap activation, real-
  time scheduler classes, USB/GPU/sound, HTTP server/proxy,
  Wi-Fi/BT/VPN, full awk, xargs, cron/at, password ageing,
  tz, tar/gzip, multi-session `who`. See docs/CORE_CLI.md
  §14.10 and the post-v1.1.6 plan (outside this repo).
