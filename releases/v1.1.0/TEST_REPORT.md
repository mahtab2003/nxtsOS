# nxtsOS v1.1.0 — Test report

Release ISO: `build/nxtsOS.iso`, 5,388,288 bytes,
SHA-256 `518394a98e9641e517bd2d1388e54843b53fe4a1d4c82a26f38bc89fb50a4d79`.
Kernel binary at build time: 266,168 bytes.
Tested 2026-10-28 on QEMU 8.2.2 (serial + VNC suites).
Bochs 2.7 was NOT re-run for v1.1.0: the Bochs suites
(guitest + desktopautotest) last passed on v0.10.0, and
the post-v1.0.0 changes include a new compositor present
path — but that is not a Bochs pass, so it is not claimed
as one. The same GUI tests were verified under QEMU on
the release ISO (see GUI security, classic desktop, and
calculator below).

## Two ISOs, and what ran on each

The full regression was run on a release-candidate ISO
(5,388,288 bytes, SHA-256
`7ed10bdcac1c5e1ae17bd6a0120fcce1d677796300fbd0b0294b629368e84881`).
That sweep found exactly one real kernel defect: the
calculator window body never became visible under the new
back-buffered compositor (see "The compositor fix" below).
The fix touched only two functions (`wm_gui_rect` and
`wm_gui_text` in `kernel/wm.c`, adding a present call after
each paint). The release ISO above was rebuilt with that
fix and nothing else, and every suite that can observe the
changed path was re-run on the release ISO itself:
calculator, storm, classic desktop, desktop10, desktop
apps, GUI security, package security, Phase 5 security,
storage security, encryption security, network security,
desktop security, and desktop10 security — all PASS.
Suites that never invoke a GUI paint (base, storage,
Phase 5, v0.4.1, package, keyring, sysupdate, encryption,
network, TLS, repository, v0.7.1, and all Phase B feature
suites) passed on the candidate ISO; the compositor fix
cannot affect them, because `fb_present_rect` is a no-op
outside back-buffered mode and is only called from the two
GUI paint functions. The verdicts below are therefore
stated per ISO, honestly.

## Full sweep on the candidate ISO (all PASS, after re-runs)

Phase A — the v1.0.0 23 suites plus functional neighbours
(28 suites). Six first runs failed; each was diagnosed
before any re-run, and none was an unexplained regression:

- base (kernel boot, test programs, shell): PASS
- storage functional (persistence across reboot): PASS on
  re-run after a test-harness fix (see below)
- storage security (8 corrupt-disk cases, no panic/hang): PASS
- Phase 5 functional (sessions, permissions): PASS on re-run
  (first run: QEMU sendkey garbled the login password)
- Phase 5 security (malformed ELFs, syscall abuse, brute-force
  halt, malformed users.txt): PASS
- v0.4.1 functional (background jobs, kill, lock, logout):
  PASS on re-run (first run: test-fixture disk lacked
  `slow.elf`, which the test runs)
- v0.4.1 security (persistent lockout across reboot): PASS
- package functional (install/depends/upgrade): PASS
- package security (signature + manifest attacks, tamper boot):
  PASS
- keyring acceptance (pkgsig): PASS
- system update + rollback (topo order, atomic refusal,
  upgrade, rollback, re-refusal): PASS
- encryption functional (encrypted disk round-trip): PASS on
  re-run (first run: test-fixture disk pre-seeded a plain
  `hello.elf` that the installer correctly refuses to
  overwrite)
- encryption security (no plaintext on disk, superblock tamper,
  wrong passphrase, tampered ELF): PASS
- GUI security (driver/WM edge cases; window limit now 16,
  not 8 — see below): PASS on re-run
- classic desktop (cliptest, cursortest, desktopautotest): PASS
- desktop10 (Dark theme, workspaces, snap, restore): PASS
- desktop apps (calc + term install, Console/Editor/Viewer): PASS
- desktop10sec (invalid settings ignored, evil.txt sanitised,
  oversize BMP refused): PASS
- desktop web (DHCP, 8192-byte truncation): PASS
- desktop nonic (clean no-device report): PASS
- desktop security (non-root save denied, lock screen,
  malformed GUI syscalls): PASS
- calculator: FAIL on the candidate ISO (see "The compositor
  fix"), PASS on the release ISO
- network slirp (e1000, DHCP, ping, HTTP; slirp DNS is
  BONUS-only — sandbox UDP block, a proven environment limit,
  not a kernel defect): PASS
- network peer (DHCP, ping, DNS, HTTP): PASS
- TLS (OpenSSL server, certificate verification): PASS
- network security (400-frame flood, DNS loop, wrong-host /
  tampered / expired certificates refused exactly 3 times): PASS
- repository (3 boots: signed index, anti-rollback, stored
  index survival, tampered index, wrong-key package): 15/15 PASS
- v0.7.1 (legacy compatibility): PASS

Phase B — post-v1.0.0 feature suites (43 suites, all PASS;
the run was interrupted once by a sandbox VM replacement
that killed the runner during files_hash; the toolchain was
restored from the apt cache, the candidate ISO's SHA-256
was re-verified unchanged, and Phase B was resumed from
files_hash — whose outcome had been lost — through the end):

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
- cat large, passwd, cp, mv, chmod, web save: PASS
  (chmod needed a re-run after a test-harness fix, see below)

## Re-verification on the release ISO (all PASS)

- calculator (install, '7' glyph, exact colours — display
  white (255,255,255), key grey (192,192,192), title bar
  (32,96,160)): PASS
- storm, classic desktop, desktop10, desktop apps: PASS
- GUI security, package security, Phase 5 security, storage
  security, encryption security, network security, desktop
  security, desktop10 security: PASS
  (package security and desktop security needed re-runs after
  test-harness fixes, see below)

## The compositor fix (REAL BUG, fixed and retested)

In back-buffered mode (the post-v1.0.0 compositor),
user-app paints via the GUI_RECT / GUI_TEXT syscalls
(`wm_gui_rect` / `wm_gui_text`) wrote only to the back
buffer and set no dirty flag and no present. Every present
path goes through a redraw that first repaints the desktop
background over the rect — including over user-window
client areas, which the window manager deliberately never
repaints — and then presents the wiped result. So an app
window's body could never become visible, while its
WM-drawn frame showed fine. At v1.0.0 (direct mode) app
paints went straight to the visible framebuffer, which is
why the test passed then. Other suites missed it because
they check markers, not app client-area pixels.
Fix: both functions now call `fb_present_rect` over the
painted rect after drawing. In direct mode (no back
buffer) the present is a no-op, so behaviour there is
unchanged. Accepted side effect, same as v1.0.0 direct
mode: a present may transiently paint over a covering
window (occlusion is repaired by the next desktop redraw),
and an app paint over the cursor position may hide the
cursor until the next redraw. Verified by the calculator
re-run on the release ISO (all pixel checks PASS).

## Test-harness and fixture fixes (NOT kernel bugs)

- Storage test second-prompt wait: the test counted
  `nxts> ` occurrences >= 2, which was already true from
  boot 1, so the readback command was typed during the
  reboot window and arrived truncated ("t persist.txt").
  The wait is now position-aware (second "Welcome to
  nxtsOS" followed by the shell prompt after it).
  Persistence itself was proven working both times (`ls`
  listed `persist.txt`, 13 bytes, in the same boot).
- GUI security expectation: the test expected max 8
  windows, but MAX_WINDOWS is 16 since the post-v1.0.0
  fix for Files failing after all 8 launcher apps were
  open. The limit is still enforced (overflow=-1); only
  the number changed. Expectation updated to 16.
- chmod test: a doubled sendkey produced "cchmod" and the
  test captured only the garbled attempt's output. The
  test's command capture now extends to the retry prompt
  when "Unknown command" appears.
- Package security test: a doubled sendkey produced "pkg
  iinstall selfdep.nxpkg" (Usage line instead of the
  install), so the self-dependency refusal marker never
  appeared. The test's sender now retries once on
  "Unknown command" or a Usage line. The kernel's
  security property held throughout: no self-dependent
  package was installed.
- Desktop security test: a doubled sendkey garbled the
  boot-C1 root password ("Login incorrect"), and the test
  then sent the install action as a username at the login
  prompt. The test's login now retries once on
  "Login incorrect". Boots A and B in the same run logged
  in fine, proving the fixture and kernel verification.
- Fixture fixes (test setup, not the kernel): the v0.4.1
  disk was rebuilt with `slow.elf` added; the encryption
  plain disk was rebuilt without a pre-seeded plain
  `hello.elf` (the installer correctly refuses a
  non-upgrade install when the payload already exists).
- Environment incident (not a test result): a sandbox VM
  replacement mid-run removed QEMU/GRUB/xorriso/Bochs/
  xdotool and killed the Phase B runner during files_hash.
  The toolchain was restored from the apt cache (QEMU
  8.2.2, grub-mkrescue, xorriso, bochs, xdotool all
  re-verified), the candidate ISO's SHA-256 was confirmed
  unchanged, and Phase B resumed from files_hash.

## Not tested (honest limits)

- Live Vercel guest fetch from the kernel is still NOT
  TESTED (sandbox blocks guest DNS over slirp UDP;
  peer-harness tests stand in for it). Published repo:
  `nxtsos-repo.vercel.app` (Vercel project `nxtsos-repo`).
  Kernel repo-HTTPS was verified against peer harnesses only.
- Bochs re-run status for v1.1.0: NOT RUN in this release
  run (last Bochs pass was v0.10.0; state exactly what was
  actually run at report time).
- Real mouse movement/clicking in QEMU or with a real pointer
  in Bochs (scripted injection only); Android Bochs, VirtualBox,
  real hardware NOT TESTED. Phone FPS never measured. Full
  idle timeouts never waited out (idle-lock trigger test used
  a shortened path). Calculator arithmetic beyond the
  '7'-press glyph NOT separately verified. Larger ELFs
  (>64 KiB), disks (>16 MiB), packages with content >131072 B
  unsupported. Wrong-signature ServerKeyExchange refusal NOT
  TESTED (needs a raw-server harness). Root chmod of system
  files NOT TESTED (from earlier chunks; do not claim
  otherwise).
- Carried design limits: TLS 1.2 only, no TLS 1.3, no session
  resumption, no client certificates, no revocation; no
  general CA store and no 4096-bit RSA verification (pinned
  anchors only); xorshift RNG is NOT cryptographic; TCP ISN
  still predictable; one snapshot generation only for
  rollback; FS bitmap/dir commit not atomic
  (hardware-fault-only impact); near-max packages can fail
  repo fetch (headers count against the download buffer);
  DNS CNAME skipped, DNS UDP-only, no DHCP renew/release, no
  static-IP command, no user-mode socket API, single TCP
  connection, IPv4 fragments dropped.
