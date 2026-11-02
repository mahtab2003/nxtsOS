# Changelog

> Reconstruction note (2026-10-28): entries 0.3.0–1.0.0 below were
> reconstructed from the release commits, `docs/ROADMAP.md`, and each
> release's own `releases/<version>/TEST_REPORT.md` (and
> `SECURITY_REPORT.md` where one exists). They summarise what each
> release shipped and what its tests proved — they are not
> contemporary notes, and no test result is claimed here beyond what
> those reports record. Entries 0.1.0–0.2.0 are the original notes.

## 1.1.6 — Accumulation release: Linux-comparability + deep-core + all five core redesigns

- Real VFS tree with directories (82 checks): permission-gated
  traversal, symlink hop budget, hard links, root-only chown/chgrp
  in the fs layer.
- Block-device layer (30 checks): bounded queue with merging,
  read-only fsck, inactive swap slots.
- Socket layer + TCP server (36 checks): firewall-before-dispatch,
  privileged ports root-only at bind and listen, clamped backlog.
- SMP stabilised (52 checks): AP IRQ0/preempt root cause fixed,
  plus the LAPIC publish-before-map race panic fixed during the
  release gate (map first, then publish).
- Redesign 5 (79 checks): demand paging with VMA bounds, vruntime
  scheduling, capabilities (MAC hook honestly a no-op), quoting,
  foreground Ctrl-C, multi-session foundations.
- Linux-comparability + deep-core: parity, linuxcomp, deepcore,
  topk families — mm/kmalloc arena, reap table, bg-only signals,
  per-process fd tables + syscalls 14–21, FIFOs, PROC_BLOCKED
  retry, brk heap, flock.
- Gate fix: sysupdate snapshot stack overflow (three 8 KiB journal
  arrays on the 16 KiB kernel stack corrupted `.rodata.str1.1`,
  killing the fs/pkg/net group names) — arrays moved to
  file-scope statics; full chain re-run on the rebuilt ISO.
- Full gate: 120/120 suites PASS on the release ISO
  (5,687,296 bytes, SHA-256
  2f53912c3985200d4ceaff4c5354c62dd87624bdabee4070868b8e285813871d).
  See releases/v1.1.6/TEST_REPORT.md and SECURITY_REPORT.md.

## 1.1.5 — Accumulation release: core CLI completion (hardware/resources, shutdown, users/groups, editor, firewall)

- Hardware control + resources via the terminal: `diag cpu/pci/disk`
  (CPU identity/features, PCI device scan, disk geometry), `system
  uptime/sysinfo`, `proc ps/top` (live ~1 s monitor, `q` quits),
  plus `mem`/`ticks`. See docs/CORE_CLI.md.
- Shutdown/power: `system shutdown` / `poweroff` / `halt`,
  root-only, `Shutdown? (y/n)` confirmation unless `--force`,
  real ACPI poweroff via parsed RSDP→RSDT→FADT→DSDT `_S5_`
  (no hardcoded SLP_TYP; absent/malformed tables = "ACPI
  poweroff unavailable" + halt, never a fake poweroff), plus
  permanent `diag acpi`. `reboot` deliberately unchanged
  (no confirm/gate — the storage harness depends on it).
- User/group management, completed: `useradd/userdel`
  (MAX_USERS 8, CSPRNG salts, `fails.txt` record dropped on
  delete), `groupadd/groupdel/groupmod/groups/id`,
  `fs chown/stat` (chown root-enforced in the fs layer too).
  Passwords echo-off, prompted twice, buffers cleared, never
  logged, salted-hash only.
- Nano-like editor: `fs edit` — full-screen, arrows/Home/End/
  PgUp/PgDn, insert/Backspace/Del, ^O save/save-as (mode +
  ownership preserved), ^X with unsaved-change prompt, ^W
  search (wrap once), ^K cut (1024 B cap) / ^U paste, ^G help;
  32 KiB cap.
- Firewall: `fw` family — in/out × allow/deny × proto × IP ×
  port/range, ordered first-match, default policy, drop
  counter, `fw.txt` persistence (root-owned 0600, lazy load,
  malformed lines skipped), hooks in both net paths, with
  proof denied traffic is actually dropped and rules
  surviving a reboot. One real kernel bug found and fixed
  by the malformed-file test: `fw_split` capped at 7 words
  instead of rejecting 8-word lines (now returns -1 on
  overflow).
- Gaps closed: `system date` wired to the CMOS RTC
  (YYYY-MM-DD HH:MM:SS). FLAT-NAME DECISION (final):
  flat shell names are KEPT as aliases — grouped dispatch
  already exists, ~40 harnesses invoke flat names, and no
  explicit user order to remove them exists.
- Security pass: adversarial coverage of the new surfaces
  (editor input handling, firewall parsing/persistence,
  user/group privilege escalation attempts, ACPI table
  parsing) — see `releases/v1.1.5/SECURITY_REPORT.md`.
  Full regression on the release ISO — see
  `releases/v1.1.5/TEST_REPORT.md`.
- Remains (not in this release): group-enforced file
  permissions (needs an on-disk nxtsFS format change +
  migration); `date set`; editor undo; editor files over
  32 KiB; top job control; HTTP proxy/server.

## 1.1.4 — Accumulation release: web/SSL Phases 3–4 (legacy protocols + HTTP layer)

- Web/SSL Phase 3: TLS 1.1 + SSLv3 client (single suite
  TLS_RSA_WITH_AES_128_CBC_SHA), new CBC record layer
  (explicit CSPRNG IVs per record, full pad-byte checks;
  SSLv3 MAC pad1/pad2, not HMAC), TLS 1.1 MD5+SHA1 PRF and
  SSLv3's own MD5/SHA1 construction; new crypto
  `kernel/md5.c`, `kernel/sha1.c`, AES decrypt; SHA-1
  certificates gated to legacy handshakes only (modern
  mode still refuses them); SSLv2-Hello probe command
  `sslprobe` (net group, dedicated help entry). Opt-in
  per connection only: `--legacy` flag + Web Legacy toggle
  (every legacy fetch labelled INSECURE LEGACY),
  single-use flag consumed at handshake, never carried
  across requests; default still offers TLS 1.3 + 1.2
  only; no silent downgrade either way; the package repo
  stays modern-only anchored. Full SSLv2 session crypto
  and ECDHE-CBC deliberately out. See docs/WEB_SSL.md.
- Web/SSL Phase 4: HTTP layer in `net/http.c` (shared
  response parser: 4096-byte header cap, case-insensitive
  names, Content-Length/Transfer-Encoding rules; chunked
  decoding with extensions and trailers; 16-entry
  memory-only cookie jar; redirect resolver for
  301/302/303/307/308, max 5 hops, loop refusal, relative
  resolution). Shell `http`/`https`/`httpsa`/`httpss` gain
  `--legacy`/`--no-redirect`/`--no-cookies`; new `cookies
  list|clear`. The raw single-request getters keep their
  exact contract (repo + `castore update` untouched).
  Security: https→http downgrade refused before fetching;
  the legacy flag is never re-armed across redirects;
  Secure cookies are TLS-only; the hostname check applies
  on every hop. Deliberately out: HTTP/2, WebSocket, HTML
  rendering, Expires parsing, cookie persistence, proxy,
  HTTP server. See docs/WEB_SSL.md.
- Security pass (adversarial, this release): no exploitable
  finding in the new surfaces — new host harness
  `tests/host_http_sec.c` 83/83 PASS and new QEMU
  hostile-peer suite `tests/qemu_test_http_sec.py` 9/9
  PASS on the release ISO; full read of `net/http.c`
  found no exploitable bug. Carried weaknesses
  unchanged: predictable TCP ISNs, non-atomic
  filesystem commit, `dhcp`/`dnsset` uid gate missing,
  early-boot CSPRNG limits, no constant-time crypto.
  See `releases/v1.1.4/SECURITY_REPORT.md`.
- Full regression on the release ISO: 98/98 PASS
  (Phase A 28/28, Phase B 48/48, Phase C 11/11,
  Phase D 11/11 incl. legacy 19/19, http 23/23,
  host_http 43/43, host_http_sec 83/83, http_sec 9/9).
  Six FAIL lines appeared during the run; all were
  proven test/harness bugs or sendkey flakes and all
  re-ran green (see `releases/v1.1.4/TEST_REPORT.md`).
- NOT TESTED: live Vercel guest fetch from the kernel
  (peer-harness proof only); user-side Virt-Manager
  retests (repo commands, desktop fixes, Phases 2–4);
  Bochs re-run for v1.1.x trees; real-pointer mouse
  movement/clicking (scripted injection only); real
  hardware; tampered-CertificateVerify negative (not
  yet built); legacy vs a real old server and Phase 4
  vs real web servers (hand-rolled peers only); Web
  Legacy toggle click itself.

## 1.1.3 — Accumulation release: desktop/core/terminal fixes + web/SSL Phases 1–2 + shell grouping + 3 new apps

- Desktop/core/terminal fixes (from the user's 2026-10-28 QEMU/KVM
  report): Web-open kernel panic — user page tables lacked the
  e1000 MMIO entry and the scheduler never restored the kernel
  page directory, so post-tick kernel code faulted on a device
  read; fixed by restoring the kernel PD in `run_process` (plus
  CR3 printed on faults). Blank app windows — the desktop redraw
  erased app bodies without queuing EXPOSE; EXPOSE is now queued
  for intersecting user windows. Terminal-as-background — console
  output painted glyphs during desktop; framebuffer console output
  is now suppressed while the desktop is active (serial + text
  buffer unaffected, panic repaints first). Added: 100-line
  scrollback ring (PgUp/PgDn), E0 scancode delivery, list views
  for ls/jobs/pkg list (row formats pinned, header + footer-count
  lines added), new `echo` + `ver` commands.
- Web/SSL Phase 1: ChaCha20 CSPRNG (RFC 8439 vector cross-checked;
  seeded from RTC + input timing + MAC uniqueness, no RDRAND
  assumption) wired into every crypto call site; CA store
  (`castore.txt`, root-owned; RSA-2048 + EC256: lines; new trust
  mode `httpss` ending the path at the first store member);
  store update (`castore add` / `castore update` over anchored
  HTTPS with vendor-signature verification); TOFU prints
  (`tofuprints.txt`: first accepted leaf per host pinned, a
  different leaf later is a hard refusal). See docs/WEB_SSL.md.
- Web/SSL Phase 2: TLS 1.3 client (HKDF, AES-128-GCM, ECDHE
  P-256, RSA + ECDSA certificates, SNI, ALPN http/1.1, no
  0-RTT/PSK, HRR fails closed); ECDSA for TLS 1.2 (suite
  0xC02B) and EC256: store/anchor lines. Default offers TLS
  1.3 + 1.2 only, no silent downgrade, both DOWNGRD sentinel
  values refused. See docs/WEB_SSL.md.
- Shell grouping + per-command help (user's 2026-10-28 rule):
  10 pure groups (system, session, fs, proc, pkg, net, crypto,
  diag, gui, test), data-driven help table (~110 entries); bare
  `help` = group index, `help <group>` = listing,
  `help <command>` = dedicated entry; grouped dispatch
  (`net <cmd>`, `test <cmd>`, ...; `pkg` keeps its own
  dispatch + gains `pkg help`, `pkg sysupdate`,
  `pkg sysrollback`). Every flat name still works (declared
  aliases); removing flat names needs a user order + harness
  updates.
- Three new built-in desktop apps (launcher third column):
  Calendar (RTC month grid, prev/next, today highlight,
  day-select), Stopwatch (start/stop, reset, 8 laps,
  MM:SS.t), Notes (`notes.txt`, list/scroll, add/delete,
  reloads from disk).
- Release security pass found + fixed one exploitable bug
  before shipping: a u32 wraparound in the DER parser
  (`der_tlv` bound check) let a crafted certificate Name
  length near 2^32 pass and hand callers a ~4 GiB length —
  a malicious server certificate could panic the kernel.
  Fixed with wrap-proof subtraction-form bounds; retested
  by host test `tests/host_der_tlv.c` (11/11; 3/11 fail on
  the vulnerable code) and QEMU test
  `tests/qemu_test_tls13_wrappedcert.py` (guest refuses
  exactly at Certificate parsing, stage 2, no panic).
  Full report: `releases/v1.1.3/SECURITY_REPORT.md`.
- Full regression on the release ISO: 87/87 PASS (Phase A
  28/28, Phase B 48/48, Phase C 11/11). The
  `desktop_fallback` suite passed on a hardened re-run (the
  test now waits for the full fb30 line before terminating
  QEMU — a stricter check; see
  `releases/v1.1.3/TEST_REPORT.md`). Full report:
  `releases/v1.1.3/TEST_REPORT.md`.
- NOT TESTED (honest): live Vercel guest fetch from the kernel
  (peer-harness proof only); user-side Virt-Manager retests
  (repo commands, desktop fixes, Phase 2 TLS 1.3); Bochs
  re-run for v1.1.x trees; real hardware; tampered-
  CertificateVerify negative (not yet built); legacy
  SSLv2/v3/TLS 1.1 (Phases 3/4, no run order yet).

## 1.1.2 — Patch release: TLS chain fix for the live repo host

- The user reported on v1.1.1 that `pkg repo
  https://nxtsos-repo.vercel.app/` + `pkg update` still answered
  "repository certificate refused". The v1.1.1 TOFU fix did not
  cover the path the way the brief assumed (`https://` = TOFU
  mode, `httpsa://` = anchored mode) — and the anchored path
  would have refused the same chain too.
- Root cause (verified from the live server): Vercel sends three
  certificates — leaf (RSA-2048) + WR1 intermediate (RSA-2048, the
  pinned anchor) + GTS Root R1 (RSA-4096). The kernel's 2048-bit
  bignum refused to parse the 4096-bit root before verification
  ever ran, in both modes.
- Fix (`net/tls.c` only): the validated path is now a prefix of
  the presented chain — anchored mode stops at the first pinned
  anchor (later certificates ignored, per RFC 5280); TOFU mode
  stops just before the first oversize-key certificate (equal to
  the server withholding that tail, which TOFU already allowed).
  Every rule inside the path still holds (dates, hostname, every
  link's issuer/subject + CA flag + signature); oversize keys
  that must actually be verified still refuse.
- New peer-harness suite `tls_anchor_stop` (8/8) proves the fix
  with the exact live chain; full regression 28 + 48 suites ALL
  PASS on the release ISO. `docs/NETWORKING.md` TLS section
  corrected to the new rules.
- NOT TESTED (honest): live Vercel guest fetch from the kernel
  (sandbox slirp DNS block); user-side Virt-Manager retest is the
  key remaining live proof. 4096-bit RSA verification for links
  that must actually be verified is still NOT IMPLEMENTED.

## 1.1.1 — Patch release: three fixes for user-reported v1.1.0 bugs

- TLS TOFU chain rule: a self-signed terminal was demanded, which
  refused every real website (leaf + intermediate, root withheld).
  TOFU now accepts a chain whose links all verify and whose terminal
  is self-signed with a verifying self-signature or CA:true;
  anchored mode (`httpsa`, repo HTTPS) unchanged.
- Desktop fallback green repaint: `cursor_move_only`'s fallback ran
  the classic redraw unconditionally from the desktop loop; with a
  real PS/2 mouse it fired routinely and painted the classic green
  background over the desktop. It now dispatches on the active UI.
- Console cursor present: the framebuffer fast path drew cursor
  cells into the back buffer without presenting (a v1.1.0 compositor
  regression), so typed input and the cursor never reached a real
  display. Both cursor cells are now presented (no-op in direct mode).
- New suites: tls_chain (5/5), desktop_fallback (mode 30), shell_echo
  (both boots), tls_ske (closes the v1.1.0 wrong-SKE-signature
  NOT TESTED item). The "Calculator not installed" notification is
  designed behaviour (calc is a package), not a bug.
- Full sweep: Phase A (28 suites) + Phase B (43 + 4 new suites) all
  PASS on the release ISO (5,390,336 bytes, kernel 266,400 bytes).
  Bochs NOT re-run for v1.1.1 (last Bochs pass v0.10.0).
- Still NOT tested at v1.1.1: user-side retest on real QEMU/KVM
  (the key remaining live proof for all three fixes), live Vercel
  guest fetch, Bochs re-run, real-pointer mouse, real hardware.

## 1.1.0 — Post-v1.0.0 accumulation: HTTPS, compositor, desktop/file polish, shell additions

- TLS 1.2 client with ECDHE, ALPN, hostname matching, and pinned-anchor
  verification (`httpsa://` + root-owned `tlsanchors.txt`); repository
  access over HTTPS (`https://` TOFU, `httpsa://` anchored).
- Back-buffered compositor; window limit raised 8 -> 16; Files window
  actions (run/install/hash/chmod/sysupd); Packages remove/rollback;
  Monitor jobs/disk; Network DNS/ping; desktop logout/reboot; unlock
  audits; idle lock; shell `passwd`, `cp`, `mv`, `chmod`, large-file
  `cat`; Web save-as; claim-by-claim documentation sweeps.
- One real bug found by the release regression and fixed: app window
  bodies never became visible under the back-buffered compositor
  (paints were never presented); fixed by presenting the painted rect
  after each GUI paint, verified by calculator pixel checks.
- Full sweep: Phase A (28 suites) + Phase B (43 feature suites) all
  PASS on the candidate ISO; calculator + all GUI/security neighbours
  re-verified PASS on the release ISO (5,388,288 bytes, kernel
  266,168 bytes). Bochs NOT re-run for v1.1.0 (last Bochs pass v0.10.0).
- Still NOT implemented at v1.1.0: graphical boot login, general CA
  trust store, cryptographic RNG, user-mode socket API, package
  revocation list, multi-generation rollback, HTML rendering.

## 1.0.0 — Phase 11: hardening, update and verified release

- RSA-2048 package signatures (NXPKG002): a package installs only if
  signed by the vendor key or a key in the root-owned `pubkeys.txt`
  keyring; legacy unsigned, wrong-key, and tampered packages refused.
- System updates with snapshot + rollback (NXUPD001): `sysupdate`
  applies a signed bundle, `sysrollback` restores the snapshot.
- Signed remote package repository (NXREPO1): `pkg repo/update/fetch/
  install` over HTTP, signed index re-verified on load, anti-rollback
  on index version.
- 11.2 review: every earlier security suite re-run, plus a fresh
  syscall/driver/parser pass. Two real bugs found and fixed: TCP
  stale-segment acceptance truncating downloads, and repository
  version/port integer wraparounds now refused.
- Final full sweep: 23 suites ALL PASS on the release ISO
  (5,316,608 bytes, kernel 193,484 bytes). Bochs was NOT re-run for
  v1.0.0 (last Bochs pass v0.10.0); the same GUI tests were verified
  under QEMU instead — stated, not claimed as a Bochs pass.
- Still NOT implemented at v1.0.0: graphical boot login, package
  revocation list, memory-hard KDF, user-mode socket API, HTML
  rendering.

## 0.10.0 — Phase 10: modern desktop and applications

- Desktop polish: themes (Classic/Dark/Light/High-contrast), accents,
  wallpapers, low-resource mode, large text, shortcut presets,
  2 workspaces, snap halves/maximise — all persistent in
  `settings.txt`, invalid values ignored.
- Applications: Editor (8192-byte cap, sanitises non-text bytes),
  Monitor, Network manager, text-only Web browser, BMP Viewer
  (24-bit, ≤128×128, ≤128 KiB), Files Open integration, Console
  package (`term.nxpkg`, local echo console, cannot run programs).
- Bug found by the web test and fixed: HTTP/HTTPS clients failed on
  bodies over the buffer instead of truncating — now
  truncate-and-drain (`web: truncated at 8192`).
- Adversarial application tests pass (invalid settings ignored, evil
  file sanitised, oversize BMP refused); base, desktop, calc, pkg,
  enc, net, TLS and security suites re-run green.

## 0.9.0 — Phase 9: networking

- e1000 network driver, DHCP (one-shot), DNS over UDP, TCP (one
  connection at a time), HTTP client.
- TLS 1.2 client (AES-128-GCM-SHA256, RSA-2048 certificates):
  verified against a local TLS server and `openssl s_server`;
  wrong-host, tampered-signature, and expired certificates all
  refused.
- Adversarial network tests pass (400-frame flood survived, DNS
  pointer abuse refused, shell stays alive).
- Honest limit: DNS via QEMU slirp is bonus-only in the sandbox
  (outbound UDP blocked, proven by packet capture); DNS itself is
  proven by the deterministic peer harness.

## 0.8.0 — Phase 8: first desktop release

- Desktop shell: Start menu, Settings window, Terminal window,
  notifications, lock screen, setup-mode unlock; idle setting with
  lock.
- GUI syscalls for user programs: SYS_GUI_OPEN/RECT/TEXT/EVENT/
  CLOSE; windows scoped to the calling process.
- Calculator as a signed-style package (`calc.nxpkg`): install,
  click the '7' key, display glyph proven pixel-exact.
- Window clip refactor proven by cliptest (clip checksum equals
  full-redraw checksum); desktopautotest passes in QEMU and Bochs.
- Adversarial desktop security tests pass.

## 0.7.4 — GUI lag fix

- Cursor save/restore, dirty-rect redraw, 30 Hz redraw throttle,
  framebuffer optimisations; new `cursortest` command.
- Rendering proven pixel-identical to the old full redraw
  (screendump counts teal 215200 / blue 5798 / white 9671,
  cursor white at 400,300, unchanged).
- Measured argument, not a phone measurement: cursor moves redraw
  ~442 pixels instead of 480,000; no Android frame-rate claimed.

## 0.7.3 — PS/2 controller fixes

- PS/2 controller initialisation fixes a keyboard deadlock; mouse
  resync; new `kbdstat` diagnostic (controller status, startup
  drained bytes, last scancode).
- Regression found and fixed during testing: a stray mouse byte
  drained by polling left the packet index mid-packet — packet
  index now reset in the mouse test path, bit-3-clear first bytes
  discarded.
- QEMU and Bochs desktop suites pass; the user's Bochs/Android
  deadlock itself was NOT reproduced in sandbox QEMU (GRUB
  consumes the key via BIOS there), so this release proves the
  new init does not break QEMU, not that it fixes Bochs.

## 0.7.2 — Bochs VBE fix

- Bochs VBE fixed linear framebuffer + shipped `bochsrc`:
  stdvga + VBE extension now boots to 800x600x32 with
  `guitest PASS` in Bochs 2.7 (v0.7.1 failed there with
  "no PCI display BAR found").
- Keyboard polling; mouse data guarded by controller status bit.
- Proven unfixable in-kernel for 800x600x32: cirrus and isavga
  Bochs adapters (no usable VBE device) — documented, not hidden.
- GRUB `insmod vbe` NOT adopted: it sets a broken 1bpp mode that
  the kernel must reject before falling back.

## 0.7.1 — VBE fallback, idle setting, terminal after session close

- Bochs VBE fallback + GRUB `gfxmode`: a kernel built without the
  Multiboot video flag still reaches 800x600x32 via VBE.
- Idle setting: default 120 minutes (was 30), `idle 5` / `idle off` /
  `idle 120` all work; terminal works after a session closes
  (logout then `mem` works).
- Regression caught and fixed: an unconditional keyboard flush on
  login discarded buffered first-boot keys — flush now applies
  only on re-login.
- NOT tested in this release: Bochs itself (not installed in the
  sandbox at the time) and real mouse movement via QEMU/VNC.

## 0.7.0 — Phase 7: graphics and input

- VBE framebuffer (800x600x32), 8x16 font, framebuffer text
  console (boot logs, test programs, shell prompt all render in
  graphics mode), PS/2 mouse driver, window manager + widgets.
- Driver/WM tests pass: mousetest (packet parsing, clamping,
  overflow ignored), guitest (window edge cases clamped, 8-window
  cap), wmautotest (button click, window drag).
- Adversarial graphics/input security tests pass.
- NOT tested: real mouse movement via monitor/VNC — QEMU
  monitor/VNC pointer delivery produced zero PS/2 packets in the
  sandbox, so driver logic is proven by packet injection only.

## 0.6.0 — Disk encryption

- AES-256-CTR sector encryption, transparent to the filesystem;
  boot passphrase, 10000-round SHA-256 key derivation by default
  (header field, kernel accepts 1000–100000), key-check block.
- Three wrong passphrases halt the system; no plaintext of file
  contents on the raw disk; superblock/header tamper fails cleanly
  or halts without unlocking.
- AES FIPS 197 vector passes (`aes-test`).
- Package install works on an encrypted disk.
- Known limits: no passphrase-change command; KDF is not
  memory-hard (Argon2/bcrypt remain outstanding, see 1.0.0).

## 0.5.0 — Phase 6: package management

- NXPKG package format with manifest and SHA-256 verification;
  installer, dependency resolution, removal guards, upgrade.
- Proven end-to-end: install refused while a dependency is
  missing, duplicate install refused, removal refused while
  another package depends on it, upgrade 1.0 → 1.1 works and runs.
- Load-time tamper check on installed programs.
- Package install is root-only (`pkg install` as a user prints
  "root only").
- Adversarial package security tests pass.

## 0.4.1 — v0.4.0 limits fixed

- Stronger password hash (10000-round salted hash).
- Background jobs: `runbg`, `jobs`, `kill`.
- Persistent lockout across reboot; idle lock after 30 minutes
  (default later changed to 120 in v0.7.1).
- Fast startup test: P1/P2 now time-based (~1.5 s on any host),
  preserving the timer-preemption proof that the old
  iteration-count test proved only on some hosts.
- Honest limit: the 30-minute idle trigger itself was not waited
  out in a test; the lock/unlock code path is tested via `lock`.

## 0.4.0 — Phase 5: loader, security and sessions

- ELF loader: ELF32 headers validated (magic, class, machine,
  entry, program-header bounds, section sizes), PT_LOAD segments
  loaded into a fresh ring-3 address space, BSS zeroed;
  malformed ELFs rejected without crashing the kernel.
- Users and permissions: UID/GID, per-process owner, file
  owner/mode enforced on every VFS operation, syscall permission
  checks (no reading another user's files, no killing another
  user's processes, no forged UID via syscall arguments).
- Login and sessions: text login against a stored password hash
  (never plaintext) on disk, per-login session, logout kills the
  session's processes and frees their frames, append-only audit
  log of logins and failures on disk.
- Without a users file the system boots as root in setup mode
  with a warning.
- Adversarial loader/security/session tests pass.

## 0.3.1 — Bootloader version fix

- Bootloader version now generated from `VERSION` (fixes v0.3.0
  shipping a GRUB menu that still said 0.2.0); boot progress
  messages added; README updated.
- Persistence verified at 32 MB (the configuration in the user's
  screenshot at the time), plus base regression at 128 MB.
- No security report for this bugfix release (no security-relevant
  change); test report records build, persistence, and base
  regression passes.

## 0.3.0 — Phase 4: persistent storage

- ATA disk driver (PIO, QEMU IDE, LBA28, polling with timeout,
  cache flush, clean "no disk" detection — never an infinite wait).
- VFS + nxtsFS filesystem: superblock, sector bitmap, fixed root
  directory (32 entries); mount and every operation validate
  magic, version, sizes, and block ranges, so a file can never
  claim the superblock/bitmap/directory or blocks outside the disk.
- Shell `ls`, `cat`, `write`, `rm`; file content survives a VM
  reboot (proven byte-for-byte at 128 MB and 64 MB); host tool
  `tools/mkdisk.py` creates and seeds disk images.
- Process teardown: exiting processes free their page directories,
  tables, and code/stack frames — fixing the v0.2.0 frame leak
  (PMM used after processes back to 288 frames, no leak).
- Adversarial storage security tests pass (8/8 corrupt-disk cases);
  one real finding fixed during testing (huge total_sectors
  free-space scan denial of service).

## 0.2.0 — Phase 3: paging, processes, syscalls, scheduler

- Paging: identity-mapped kernel region (0-32 MB), per-process page
  directories sharing the kernel entries, user code at 0x08048000 and
  user stack at 0x0C000000, page 0 left unmapped.
- Own GDT extended with user code/data (0x18/0x20) and a TSS (0x28);
  ring-3 -> ring-0 transitions switch to a per-process kernel stack.
- Syscalls via int 0x80: print, yield, exit, getpid, ticks. Print
  pointers are validated against the process's mapped pages first.
- Scheduler: round-robin over two ring-3 test processes, cooperative
  yield plus 100 ms timer preemption (proven: P1 iter 1 prints during
  P2's busy loop, before P2 iter 1).
- Bug fixed during testing: after a yield/exit/preempt the scheduler
  returned with IF cleared, so the shell's hlt loop never woke for
  keyboard input. run_process() now re-enables interrupts on return.
- Known limitation: exited processes' frames (page directories, tables,
  code/stack pages) are not freed yet — process teardown is later work.
  After the two test processes exit, PMM used rises from 267 to 297 frames.

# Changelog

## 0.1.1 — QEMU-verified bugfix (no new features)

- FIX: kernel installs its own GDT (code 0x08, data 0x10) before interrupts.
  This fixes the v0.1.0 QEMU reboot loop (GRUB's GDT uses 0x10/0x18, so the
  first timer IRQ triple-faulted on CS=0x08).
- QEMU boot test: PASS at 128 MB (`help`, `mem`) and 64 MB; `ticks` shows
  the PIT counting in the VM (214 ticks / 2 seconds).
- v0.1.0 is superseded — do not distribute it.

# Changelog

## 0.1.0 — first bootable kernel (Phase 2)

- Multiboot (GRUB) boot, 32-bit x86 original kernel.
- VGA text console + COM1 serial mirror.
- Multiboot memory-map parsing, bitmap physical memory manager.
- IDT, PIC remap, PIT 100 Hz timer, PS/2 keyboard.
- In-kernel shell: help, mem, ticks, clear, reboot.
- Panic path for unhandled exceptions.
- Boot test: PASS under Unicorn CPU emulation (see releases/v0.1.0/TEST_REPORT.md).
  QEMU boot test: NOT TESTED yet (QEMU package download still in progress
  in the build sandbox at packaging time).
- Not included: GUI/desktop, filesystem/persistence, networking, user
  processes/syscalls, privilege separation.
