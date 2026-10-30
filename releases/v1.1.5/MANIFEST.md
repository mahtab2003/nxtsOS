# nxtsOS v1.1.5 — Release manifest

- Version: 1.1.5 (accumulation release over v1.1.4: core
  CLI completion — hardware/resources, shutdown/power
  with real ACPI poweroff, user/group management,
  nano-like editor, firewall, system date)
- Date: 2026-10-30
- Kernel: original 32-bit x86 monolithic kernel, Multiboot 1 via GRUB.
  No Linux code, no distro, no fork, no re-theme.
- ISO: `nxtsOS.iso`, 5,517,312 bytes,
  SHA-256 `b4d42ad595ae84908ea302d438fba603d783e63787869418aeb0b59124767de3`
- Kernel binary: `build/nxtsOS.bin`, 394,132 bytes (at build time)
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
- Git: branch `main`, tag `v1.1.5` (local only; no GitHub push —
  the user did not authorise a push for this release).
  The exact commit hash is recorded in the delivery notes, not inside
  this manifest, because the manifest itself is part of the commit.
- Tested on: QEMU 8.2.2 (serial + VNC suites) — see
  TEST_REPORT.md. Bochs 2.7 was NOT re-run for v1.1.5
  (last Bochs pass: v0.10.0); see TEST_REPORT.md.

## What is in v1.1.5 (over v1.1.4)

- Hardware/resources: `diag cpu/pci/disk`, `system
  uptime/sysinfo`, `proc ps/top` (live ~1 s monitor,
  `q` quits), plus `mem`/`ticks` (34 checks).
- Shutdown/power: `system shutdown` / `poweroff` /
  `halt`, root-only, `Shutdown? (y/n)` confirmation
  unless `--force`, real ACPI poweroff via parsed
  RSDP→RSDT→FADT→DSDT `_S5_` (no hardcoded SLP_TYP;
  absent/malformed tables = "ACPI poweroff
  unavailable" + halt, never a fake poweroff), plus
  permanent `diag acpi`. `reboot` deliberately
  UNCHANGED (no confirm/gate — the storage harness
  depends on it). In-run bug fixed: FADT PM1a_CNT_BLK
  is at offset 64/68, not 56 (21 checks).
- User/group management: `useradd/userdel`
  (setup-mode rule, MAX_USERS 8, CSPRNG salts,
  `fails.txt` record dropped on delete),
  `groupadd/groupdel/groupmod/groups/id`,
  `fs chown/stat` (chown root-enforced in the fs
  layer too) (82 checks).
- Nano-like editor `fs edit`: full-screen,
  arrows/Home/End/PgUp/PgDn, insert/Backspace/Del,
  ^O save/save-as (mode + ownership preserved), ^X
  with unsaved-change prompt, ^W search (wrap once),
  ^K cut (1024 B cap) / ^U paste, ^G help; 32 KiB
  cap (59/59 hardened).
- Firewall `fw`: in/out × allow/deny × proto × IP ×
  port/range, ordered first-match, default policy,
  drop counter, `fw.txt` persistence (root-owned
  0600, lazy load, malformed lines skipped), hooks
  in both net paths. One real kernel bug found and
  fixed by the malformed-file test: `fw_split`
  capped at 7 words instead of rejecting 8-word
  lines (now returns -1 on overflow) (71 checks,
  including proof denied traffic is actually dropped
  and persistence across reboot).
- Gaps closed: `system date` wired to the CMOS RTC
  (YYYY-MM-DD HH:MM:SS, hand-padded).
- FLAT-NAME DECISION (final): KEEP flat names as
  aliases. Grouped dispatch already exists, ~40
  harnesses invoke flat names, and no explicit user
  order to remove them exists.
- Tampered-CertificateVerify negative test
  (`tests/qemu_test_tls13_tamperedcv.py`, 6/6): a
  hand-rolled TLS 1.3 server sends a fully valid
  flight except a tampered server CertificateVerify;
  every variant is refused exactly at stage 3.
  Release-run harness fix (no kernel behaviour
  change): the monitor socket filename now uses a
  short tag, because the full tag exceeded the
  108-byte UNIX socket path limit for two variants
  (see TEST_REPORT.md).
- Security pass: no exploitable finding in the new
  surfaces (see SECURITY_REPORT.md for the full
  adversarial read and the carried weaknesses).

## What is NOT in v1.1.5

- Live Vercel guest fetch from the kernel is still NOT TESTED
  (peer-harness proof only). User-side Virt-Manager retests
  (repo commands, desktop fixes, Phases 2–4, core features)
  remain the key live proof.
- 4096-bit RSA verification is still NOT IMPLEMENTED for links
  that must actually be verified.
- No TLS 1.3 PSK/0-RTT (out of scope by design), no graphical
  boot login, installer, UEFI, production CA bundle
  publication, package revocation list, multi-generation
  rollback, or HTML rendering.
- Group-enforced file permissions are NOT IMPLEMENTED
  (needs an on-disk nxtsFS format change + migration;
  groups are membership + display only, by design, not
  half-implemented). Also NOT IMPLEMENTED: `date set`,
  editor undo, editor files over 32 KiB, top job control,
  HTTP proxy/server, full SSLv2 session crypto, ECDHE-CBC,
  HTTP/2, WebSocket, Expires-date cookie parsing, cookie
  persistence across reboots.
- Legacy against a real old server and Phase 4 against
  real web servers are NOT TESTED (hand-rolled peers only).
