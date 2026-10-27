# nxtsOS v1.0.0 — Release manifest

- Version: 1.0.0 (Phase 11: hardening, update, verified release)
- Date: 2026-10-27
- Kernel: original 32-bit x86 monolithic kernel, Multiboot 1 via GRUB.
  No Linux code, no distro, no fork, no re-theme.
- ISO: `nxtsOS.iso`, 5,316,608 bytes,
  SHA-256 `b396192d5f2f463e9eddd5bc434cb8412df3b2e26a80518642d5197e58a586cc`
- Kernel binary: `build/nxtsOS.bin`, 193,484 bytes (at build time)
- Distribution contents: `nxtsOS.iso`, `calc.nxpkg` (8,705 bytes),
  `term.nxpkg` (8,037 bytes), `run_qemu.sh`, `bochsrc.txt`,
  `mkdisk.py`, `VM_GUIDE.md`, `BUILD_AND_TEST.md`, this manifest,
  `TEST_REPORT.md`, `SECURITY_REPORT.md`, `README.md`, `VERSION`,
  `SHA256SUMS` (SHA-256 of the ISO inside the dist folder).
- Source archive: the full source tree minus `build/`, `archives/`,
  `logs/`, `.git`, plus this release's three documents.
  The package signing key (`build/signing.key`) never ships in any
  archive. The compiled-in vendor public key ships as generated
  source (`kernel/vendor_pubkey.h`) so vendor-signed packages verify.
- Git: branch `main`, tag `v1.0.0` (local only; no remote configured).
  The exact commit hash is recorded in the delivery notes, not inside
  this manifest, because the manifest itself is part of the commit.
- Tested on: QEMU 8.2.2 (serial + VNC suites) — see
  TEST_REPORT.md. Bochs 2.7 was NOT re-run for v1.0.0
  (last Bochs pass: v0.10.0); see TEST_REPORT.md.
- What is new in v1.0.0 (over v0.10.0):
  RSA-2048 package signatures (NXPKG002, vendor key + root keyring),
  system updates with snapshot + rollback (NXUPD001, `sysupdate` /
  `sysrollback`), and a signed remote package repository over HTTP
  (`pkg repo` / `pkg update` / `pkg fetch` / `pkg install <name>`).
- What is NOT in v1.0.0 (honest limits, see SECURITY_REPORT.md):
  graphical boot login, UEFI, installer, CA trust store, cryptographic
  RNG, user-mode socket API, package revocation list, multi-generation
  rollback, disks over 16 MiB, packages over ~132 KiB, real-pointer
  mouse testing, VirtualBox / real-hardware testing.
- Pending explicit user authorisation (NOT done in this release):
  publishing the package repository to public hosting, and pushing the
  source to GitHub (the Muse GitHub App still lacks access to
  mahtab2003/nxtsOS). Nothing was published, sent, or spent without
  that approval.
