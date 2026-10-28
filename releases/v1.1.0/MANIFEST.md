# nxtsOS v1.1.0 — Release manifest

- Version: 1.1.0 (post-v1.0.0 accumulation: kernel HTTPS, compositor,
  desktop/file polish, shell additions, documentation sweeps)
- Date: 2026-10-28
- Kernel: original 32-bit x86 monolithic kernel, Multiboot 1 via GRUB.
  No Linux code, no distro, no fork, no re-theme.
- ISO: `nxtsOS.iso`, 5,388,288 bytes,
  SHA-256 `518394a98e9641e517bd2d1388e54843b53fe4a1d4c82a26f38bc89fb50a4d79`
- Kernel binary: `build/nxtsOS.bin`, 266,168 bytes (at build time)
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
- Git: branch `main`, tag `v1.1.0` (local only; no GitHub push —
  the user did not authorise a push for this release).
  The exact commit hash is recorded in the delivery notes, not inside
  this manifest, because the manifest itself is part of the commit.
- Tested on: QEMU 8.2.2 (serial + VNC suites) — see
  TEST_REPORT.md. Bochs 2.7 was NOT re-run for v1.1.0
  (last Bochs pass: v0.10.0); see TEST_REPORT.md.
- What is new in v1.1.0 (over v1.0.0):
  TLS 1.2 client with ECDHE, ALPN, hostname matching (single-label
  leading wildcard only, never for IP literals), and pinned-anchor
  verification (`httpsa://`, plus root-owned `tlsanchors.txt`);
  repository access over HTTPS (`https://` TOFU, `httpsa://`
  anchored); a back-buffered compositor (app paints are presented
  per-rect instead of going straight to the visible framebuffer);
  window limit raised from 8 to 16 (Files no longer fails after
  all launcher apps are open); Files window actions (run, install,
  hash, chmod, sysupdate); Packages remove/rollback from the
  desktop; Monitor jobs/disk views; Network DNS/ping; desktop
  logout/reboot; lock-screen and settings unlock audits; idle
  lock and shell idle lock; audit-log cap handling; shell
  `passwd`, `cp`, `mv`, `chmod`, and large-file `cat` via
  range reads; Web save-as; and claim-by-claim documentation
  sweeps (NETWORKING, DESKTOP, VM_GUIDE, README, PACKAGES,
  SECURITY, FILESYSTEM, ENCRYPTION, BUILD_AND_TEST, CHANGELOG
  reconstruction, and others).
- What is NOT in v1.1.0 (honest limits, see SECURITY_REPORT.md):
  graphical boot login, UEFI, installer, general CA trust store,
  cryptographic RNG, user-mode socket API, package revocation list,
  multi-generation rollback, disks over 16 MiB, packages over
  ~132 KiB, real-pointer mouse testing, VirtualBox / real-hardware
  testing.
- Pending explicit user authorisation (NOT done in this release):
  pushing the source to GitHub. Nothing was published, sent, or
  spent without that approval. The Drive upload state is recorded
  in the delivery notes (archives built + tagged locally; upload
  verified or pending as stated there).
