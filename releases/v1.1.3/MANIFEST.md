# nxtsOS v1.1.3 — Release manifest

- Version: 1.1.3 (accumulation release over v1.1.2: desktop /
  core / terminal fixes + web/SSL Phases 1–2 + shell grouping
  + 3 new desktop apps + one security fix)
- Date: 2026-10-29
- Kernel: original 32-bit x86 monolithic kernel, Multiboot 1 via GRUB.
  No Linux code, no distro, no fork, no re-theme.
- ISO: `nxtsOS.iso`, 5,439,488 bytes,
  SHA-256 `37563b592395162aff9c1a9c45901e236e4ac914e6a265968272f26bf46a44ef`
- Kernel binary: `build/nxtsOS.bin`, 316,212 bytes (at build time)
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
- Git: branch `main`, tag `v1.1.3` (local only; no GitHub push —
  the user did not authorise a push for this release).
  The exact commit hash is recorded in the delivery notes, not inside
  this manifest, because the manifest itself is part of the commit.
- Tested on: QEMU 8.2.2 (serial + VNC suites) — see
  TEST_REPORT.md. Bochs 2.7 was NOT re-run for v1.1.3
  (last Bochs pass: v0.10.0); see TEST_REPORT.md.

## What is in v1.1.3 (over v1.1.2)

- Desktop/core/terminal fixes (from the user's 2026-10-28
  QEMU/KVM report): Web-open kernel panic — user page tables
  lacked the e1000 MMIO entry and the scheduler never restored
  the kernel page directory, so post-tick kernel code faulted
  on a device read; fixed by restoring the kernel PD in
  `run_process` (plus CR3 printed on faults). Blank app
  windows — the desktop redraw erased app bodies without
  queuing EXPOSE; EXPOSE is now queued for intersecting user
  windows. Terminal-as-background — console output painted
  glyphs during desktop; framebuffer console output is now
  suppressed while the desktop is active (serial + text
  buffer unaffected, panic repaints first). Added: 100-line
  scrollback ring (PgUp/PgDn), E0 scancode delivery, list
  views for ls/jobs/pkg list, new `echo` + `ver` commands.
- Web/SSL Phase 1: ChaCha20 CSPRNG wired into every crypto
  call site; CA store (`castore.txt`, RSA-2048 + EC256:
  lines, new `httpss` trust mode); signed store updates;
  TOFU leaf pinning (`tofuprints.txt`, mismatch = hard
  refusal).
- Web/SSL Phase 2: TLS 1.3 client (HKDF, AES-128-GCM, ECDHE
  P-256, RSA + ECDSA certificates, SNI, ALPN, no 0-RTT/PSK,
  hello-retry rejected fail-closed); ECDSA for TLS 1.2;
  default offers TLS 1.3 + 1.2 only, no silent downgrade,
  both downgrade sentinel values refused.
- Shell grouping + per-command help: 10 pure groups (system,
  session, fs, proc, pkg, net, crypto, diag, gui, test),
  data-driven help table (~110 entries); bare `help` is a
  group index, `help <group>` / `help <command>` give
  dedicated entries; grouped dispatch (`net <cmd>`,
  `test <cmd>`, …) with all flat names preserved as
  declared aliases.
- Three new desktop apps: Calendar (RTC month grid, prev/next,
  today highlight, day-select), Stopwatch (start/stop, reset,
  8 laps), Notes (`notes.txt`, list/scroll, add/delete,
  reloads from disk); launcher third column (columns 1–2
  unchanged).
- Security fix found by this release's adversarial pass:
  `der_tlv` u32 wraparound in `net/tls.c` (crafted
  certificate Name length near 2^32 passed the bound check
  and handed callers a ~4 GiB length — a malicious TLS
  server could panic the kernel). Fixed with wrap-proof
  subtraction-form bounds; retested by host test
  `tests/host_der_tlv.c` (11/11; 3/11 fail on the
  vulnerable code) and QEMU test
  `tests/qemu_test_tls13_wrappedcert.py` (guest refuses
  exactly at Certificate parsing, stage 2, no panic).
  Full report: `releases/v1.1.3/SECURITY_REPORT.md`.

## What is NOT in v1.1.3

- Live Vercel guest fetch from the kernel is still NOT TESTED
  (sandbox blocks guest DNS over slirp UDP; peer-harness proof
  only — see TEST_REPORT.md). User-side Virt-Manager retests
  (repo commands, desktop fixes, Phase 2 TLS 1.3) remain the
  key live proof.
- 4096-bit RSA verification is still NOT IMPLEMENTED for links
  that must actually be verified.
- No TLS 1.3 PSK/0-RTT (out of scope by design), no graphical
  boot login, installer, UEFI, production CA bundle
  publication, package revocation list, multi-generation
  rollback, or HTML rendering.
- Legacy SSLv2/v3/TLS 1.1 (Phases 3/4) are NOT in this release
  (no run order yet); neither is the tampered-
  CertificateVerify negative test (not yet built).
