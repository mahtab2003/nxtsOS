# nxtsOS v1.1.1 — Release manifest

- Version: 1.1.1 (patch release over v1.1.0: three fixes for bugs
  the user found testing v1.1.0 on real QEMU/KVM via Virt-Manager)
- Date: 2026-10-28
- Kernel: original 32-bit x86 monolithic kernel, Multiboot 1 via GRUB.
  No Linux code, no distro, no fork, no re-theme.
- ISO: `nxtsOS.iso`, 5,390,336 bytes,
  SHA-256 `cecbafe9685a16cc5053812d388f48a7844331ce1a4dfb79ca50f1213364e7dc`
- Kernel binary: `build/nxtsOS.bin`, 266,400 bytes (at build time)
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
- Git: branch `main`, tag `v1.1.1` (local only; no GitHub push —
  the user did not authorise a push for this release).
  The exact commit hash is recorded in the delivery notes, not inside
  this manifest, because the manifest itself is part of the commit.
- Tested on: QEMU 8.2.2 (serial + VNC suites) — see
  TEST_REPORT.md. Bochs 2.7 was NOT re-run for v1.1.1
  (last Bochs pass: v0.10.0); see TEST_REPORT.md.
- What is fixed in v1.1.1 (over v1.1.0):
  (1) TLS TOFU chain rule: `verify_chain` used to demand a
  self-signed terminal certificate, which refused every real
  website (leaf + intermediate, root never sent) with
  "certificate refused". TOFU now accepts a chain whose links
  all verify and whose terminal is self-signed with a verifying
  self-signature (single-cert case, unchanged) or a real CA
  (CA:true); anchored mode (`httpsa`, repo HTTPS) is unchanged
  and still requires a pinned anchor. (2) Desktop fallback
  green repaint: `cursor_move_only`'s fallback ran the classic
  `wm_redraw()` unconditionally from the desktop loop; with a
  real PS/2 mouse the pointer routinely moves between the
  loop's prev update and a redraw's cursor save, so the
  fallback fired and painted the classic green background over
  the desktop. It now dispatches on the active UI
  (`desk_active` -> full desktop redraw, else classic redraw).
  (3) Console cursor present: `console_putchar`'s framebuffer
  fast path drew cursor cells into the back buffer without
  presenting them (a v1.1.0 compositor regression), so typed
  input and the cursor never reached a real display; it now
  presents both cursor cells (no-op in direct mode).
  Plus a new desktop autotest mode 30 (fallback-redraw script)
  and three new QEMU suites (tls_chain, desktop_fallback,
  shell_echo), and the tls_ske raw-server suite closing the
  v1.1.0 "wrong-signature ServerKeyExchange refusal NOT
  TESTED" item. The "Calculator not installed" notification
  the user also saw is DESIGNED behaviour (calc is a package),
  not a bug; no change.
- What is NOT in v1.1.1 (honest limits, see SECURITY_REPORT.md):
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
