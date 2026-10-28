# nxtsOS v1.1.1 — Test report

Release ISO: `build/nxtsOS.iso`, 5,390,336 bytes,
SHA-256 `cecbafe9685a16cc5053812d388f48a7844331ce1a4dfb79ca50f1213364e7dc`.
Kernel binary at build time: 266,400 bytes.
Tested 2026-10-28 on QEMU 8.2.2 (serial + VNC suites).
Bochs 2.7 was NOT re-run for v1.1.1: the Bochs suites
(guitest + desktopautotest) last passed on v0.10.0, and
the same GUI tests were verified under QEMU on the release
ISO (see GUI security, classic desktop, and calculator
below). Unlike v1.1.0, there is no two-ISO story here:
the version bump (banner + About literal only) was applied
before the regression, and every suite below ran on this
release ISO itself.

## The three user-reported bugs, and what proved each fix

All three were reported by the user testing v1.1.0 on real
QEMU/KVM via Virt-Manager on 2026-10-28 ~10:46–10:51 PKT.
Each was root-caused, fixed, and verified in QEMU before
this release run; this run re-verified all three on the
release ISO (the fix run's ISO differed only by the
version strings).

- Bug A — Web window `https://example.com` ->
  "certificate refused" (SSL connection error). Cause:
  `verify_chain`'s TOFU branch demanded a self-signed
  terminal certificate; real servers send leaf +
  intermediate and withhold the root, so every real site
  refused. Fix: TOFU accepts a chain whose links all
  verify and whose terminal is self-signed with a verifying
  self-signature (unchanged) or CA:true. Re-verified by
  the new `tests/qemu_test_tls_chain.py`: 5/5 PASS
  (chain-ok success; bad-CA, bad-signature, wrong-host,
  expired refusals), plus the existing TLS suites (RSA,
  ECDHE, anchor 3/3, peer wildcard, repo-HTTPS) all PASS.
- Bug B — green screen during some operation + blank Web
  window. Cause: `cursor_move_only`'s fallback ran the
  classic `wm_redraw()` unconditionally from the desktop
  loop; with a real PS/2 mouse the pointer routinely moves
  between the loop's prev update and a redraw's cursor
  save, so the fallback fired and painted the classic
  green background (0x00106040) over the desktop. The
  user's screenshot measured exactly that background plus
  the classic "Shell" taskbar. Fix: the fallback
  dispatches on `desk_active` (desktop -> full desktop
  redraw, classic -> classic redraw). Re-verified by the
  new autotest mode 30 + `tests/qemu_test_desktop_fallback.py`:
  PASS (saved=(300,432) proves the fallback path was
  taken, background Classic 0x183050, green pixel count 0,
  Web window present).
- Bug C — terminal cursor not showing, typed input not
  echoed. Cause: `console_putchar`'s framebuffer fast path
  drew into the back buffer and never presented (a v1.1.0
  compositor regression; serial always worked, which is
  why serial-only tests never caught it). Fix: present the
  old + new 8x16 cursor cells after drawing them (no-op in
  direct mode). Re-verified by the new
  `tests/qemu_test_shell_echo.py`: PASS on both boots
  (plain shell + desktop -> Terminal-exit path; echo gain
  + inverted cursor cell found in screendumps).
- Non-bug: the "Calculator not installed" notification is
  DESIGNED behaviour (calc is a package, installed via
  `pkg install calc.nxpkg`); no change was made.

## Full sweep on the release ISO (all PASS, after diagnosed re-runs)

Phase A — the v1.1.0 28 suites. One first run failed and
was diagnosed before any re-run; it was not a kernel
regression:

- base (kernel boot, test programs, shell): PASS
- storage functional (persistence across reboot): PASS
- storage security (8 corrupt-disk cases, no panic/hang): PASS
- Phase 5 functional (sessions, permissions): PASS
- Phase 5 security (malformed ELFs, syscall abuse, brute-force
  halt, malformed users.txt): PASS
- v0.4.1 functional (background jobs, kill, lock, logout): PASS
- v0.4.1 security (persistent lockout across reboot): PASS
- package functional (install/depends/upgrade): PASS on third
  run (see "The pkg re-runs" below — first run a sendkey
  doubling flake, second run a fixture-handling mistake by
  the release runner, third run clean on a fresh disk)
- package security (signature + manifest attacks, tamper boot):
  PASS
- keyring acceptance (pkgsig): PASS
- system update + rollback (topo order, atomic refusal,
  upgrade, rollback, re-refusal): PASS
- encryption functional (encrypted disk round-trip): PASS
- encryption security (no plaintext on disk, superblock tamper,
  wrong passphrase, tampered ELF): PASS
- GUI security (driver/WM edge cases; window limit 16): PASS
- classic desktop (cliptest, cursortest, desktopautotest): PASS
- desktop10 (Dark theme, workspaces, snap, restore): PASS
- desktop apps (calc + term install, Console/Editor/Viewer): PASS
- desktop10sec (invalid settings ignored, evil.txt sanitised,
  oversize BMP refused): PASS
- desktop web (DHCP, 8192-byte truncation): PASS
- desktop nonic (clean no-device report): PASS
- desktop security (non-root save denied, lock screen,
  malformed GUI syscalls): PASS
- calculator (install, '7' glyph, exact colours): PASS
- network slirp (e1000, DHCP, ping, HTTP; slirp DNS is
  BONUS-only — sandbox UDP block, a proven environment limit,
  not a kernel defect): PASS
- network peer (DHCP, ping, DNS, HTTP): PASS
- TLS (OpenSSL server, certificate verification): PASS
- network security (400-frame flood, DNS loop, wrong-host /
  tampered / expired certificates refused exactly 3 times): PASS
- repository (3 boots: signed index, anti-rollback, stored
  index survival, tampered index, wrong-key package): PASS
- v0.7.1 (legacy compatibility): PASS

Phase B — v1.1.0's 43 feature suites + the 4 new suites
(47 total, all PASS):

- NEW: tls_chain (5/5 incl. all refusal negatives): PASS
- NEW: desktop_fallback (mode 30): PASS
- NEW: shell_echo (both boots): PASS
- NEW (bonus): tls_ske raw-server ServerKeyExchange test
  (BAD case refused with no ClientKeyExchange, GOOD case
  sends ClientKeyExchange): PASS — this closes the v1.1.0
  "wrong-signature ServerKeyExchange refusal NOT TESTED"
  item.
- storm (window stress): PASS
- TLS anchor (right anchor / wrong anchor / self-signed with
  no anchor): 3/3 PASS
- TLS hostname matching, ALPN (http/1.1 selected), ECDHE,
  peer CN case handling: PASS
- repository HTTPS, anchored HTTPS, availability, bench,
  fetch, set, scroll, desktop, root, sysinfo: PASS
- Files run, install, hash, chmod, sysupd: PASS
- Packages remove, rollback: PASS
- Monitor jobs, disk: PASS
- Network DNS, ping: PASS
- Desktop logout, reboot: PASS
- Desktop unlock audit, unlock non-root audit, settings
  unlock, unlock no-user: PASS
- Idle lock, shell idle lock: PASS
- Audit cap, audit log: PASS
- cat large: PASS
- passwd: PASS on re-run (see "The passwd re-run" below)
- cp, mv, chmod, web save: PASS

## The pkg re-runs (diagnosed, not claimed away)

- Run 1 FAIL: the guest received `sha256 abbc.txt`
  (doubled `b`) instead of `sha256 abc.txt` — the known
  QEMU sendkey double-delivery flake — so the known-vector
  hash marker never printed. Every other pkg marker was
  FOUND. The abc.txt fixture itself was verified exact
  (3 bytes, `od -c`).
- Run 2 FAIL: the release runner's mistake, not the
  kernel's — the re-run reused the Phase A disk, which
  the first run had already mutated (hello 1.1 left
  installed), so greet installed first try and the
  dependency-refusal marker legitimately never fired.
  The runner was fixed to copy the pkg fixture to the
  workdir (as it already did for the storage disk).
- Run 3 PASS: all 16 markers FOUND on a freshly rebuilt
  pkg disk (freshly signed packages, same signing key).

## The passwd re-run (diagnosed, not claimed away)

First run FAIL: the self-service password change step
failed with "passwd: incorrect password" on the current
password `alice2` — the same password that had already
succeeded at login and at the earlier mismatch step, and
with no v1.1.1 code change touching password
verification (the shell.c diff is help text + the
fallback-test dispatch; console.c touches output only).
The test's own docstring names QEMU sendkey doubling as
the known flake for this test, and password typing is
not echoed, so a doubled key is invisible in serial and
surfaces exactly as one isolated "incorrect password".
Re-run on a fresh setup workdir: PASSWD TEST PASS (the
"login retry / too many failures" notes also appear in
the passing run — they are the test's expected noise for
the deliberately-failed old-password logins).

## Mid-run incident (recovered, not hidden)

A sandbox VM replacement wiped QEMU/GRUB/xorriso/Bochs/
xdotool between the toolchain check and the first Phase A
attempt, so all 28 suites died in under a second with
`FileNotFoundError: qemu-system-x86_64` (setup steps, which
need no QEMU, had all succeeded). The runtime's own
os-intent replay held the dpkg lock, so the run waited
instead of fighting it; the replay restored QEMU 8.2.2 and
the rest, the candidate ISO's SHA-256 was re-verified
unchanged, and Phase A was re-run from the start. No
result from the killed attempt was claimed.

## NOT TESTED (honest)

- User-side retest on real QEMU/KVM via Virt-Manager:
  the key remaining live proof for all three fixes in
  this release (sandbox QEMU + scripted injection stand
  in for the real pointer path).
- Live Vercel guest fetch from the kernel (sandbox blocks
  guest DNS over slirp UDP; peer-harness tests stand in).
  Published repo `nxtsos-repo.vercel.app` unchanged.
- Bochs re-run (last Bochs pass v0.10.0; GUI paths
  verified under QEMU instead).
- Real-pointer mouse movement/clicking (scripted injection
  only); Android Bochs, VirtualBox, real hardware.
  Phone FPS never measured. Full idle timeouts never
  waited out. Calculator arithmetic beyond the '7' glyph
  NOT separately verified. ELFs >64 KiB, disks >16 MiB,
  packages >131072 B unsupported. Root chmod of system
  files NOT TESTED.
- Carried limits: TLS 1.2 only, no TLS 1.3/resumption/
  client certs/revocation; no general CA store, no 4096-bit
  RSA verification (pinned anchors only); xorshift RNG NOT
  cryptographic; TCP ISN predictable; one snapshot
  generation for rollback; FS bitmap/dir commit not atomic
  (hardware-fault-only); near-max packages can fail repo
  fetch; DNS CNAME skipped, UDP-only; no DHCP renew/release,
  no static-IP command, no user-mode socket API, single TCP
  connection, IPv4 fragments dropped. NOT IMPLEMENTED:
  graphical boot login, UEFI, installer, package revocation
  list, multi-generation rollback, HTML rendering.
