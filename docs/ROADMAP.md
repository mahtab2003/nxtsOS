# nxtsOS Full Task Plan — core-first, security-tested at every release

Revised 2026-10-26 at the user's direction: the original plan put graphics
before storage and security. That order is rejected. A desktop built on
embedded blobs, with no disk, no loader, no users and no packages, would
have to be thrown away. Core first, in dependency order, then graphics on
top of a real foundation. Nothing in this plan is "done" because code was
written: a phase is done only when its QEMU tests pass, its adversarial
security tests pass (or are fixed and retested), and its release archive
with test + security reports exists in `releases/`.

## Standing rules (apply to every task, no exceptions)

1. **No compromise on core or security.** A shortcut that weakens memory
   safety, privilege separation, input validation, or persistence is not
   a shortcut — it is a bug to be fixed before release, even if it costs
   a feature.
2. **No fabricated claims.** Every feature, test result, and security
   finding in a release report comes from an actual run, with the exact
   command and log. Anything untested is labelled NOT TESTED, anything
   unimplemented is labelled NOT IMPLEMENTED.
3. **Security test after every release, as a third-party tester.**
   For each release, before it ships, attack it as if you did not write
   it: untrusted/malicious inputs, boundary values, malformed on-disk
   and on-wire data, privilege-escalation attempts, resource exhaustion,
   and abuse of every new API. Record every finding in the release's
   `SECURITY_REPORT.md`, fix every exploitable finding, retest, and only
   then ship. Known, unexploitable limitations are recorded as such —
   never hidden, never dressed up as fixes. See `docs/SECURITY_TESTING.md`.
4. **Bootable at every milestone.** Never break the QEMU boot to add a
   feature. If a task breaks the boot, it is reverted or fixed before
   any other task starts.
5. **Versioned, immutable releases.** One version per phase (or per
   bugfix), source + dist archives with SHA-256, git tag, test report,
   security report. Never silently change a published archive.

## Completed

- [x] **Phase 1 — Environment and architecture** (v0.1.0 docs/build)
  Tasks: toolchain inspection, project layout, architecture decision
  (modular monolithic, 32-bit x86, Multiboot), build/test scripts.
- [x] **Phase 2 — First bootable image** (v0.1.0, superseded by v0.1.1)
  Tasks: Multiboot entry, VGA/serial console, PMM, IDT/PIC/PIT, PS/2
  keyboard, in-kernel shell, panic path.
  Security note (retroactive): v0.1.0's GDT bug was a triple-fault
  reboot loop; fixed in v0.1.1 by installing the kernel's own GDT.
- [x] **Phase 3 — Kernel fundamentals** (v0.2.0)
  Tasks: paging (32 MB identity kernel region, per-process PDs),
  GDT user segments + TSS, ring-3 processes, int 0x80 syscalls
  (print/yield/exit/getpid/ticks, pointer validation), round-robin
  scheduler with yield + 100 ms timer preemption, shell after processes.
  Known limitation carried forward: exited processes' frames are not
  freed yet — fixed in Phase 4 Task 4.2 (process teardown).

## Phase 4 — Persistent storage (v0.3.0) — DONE

- [x] **Task 4.1 — ATA disk driver (PIO, QEMU IDE)**
  Details: primary bus 0x1F0, master drive, LBA28, polling with timeout
  (never an infinite wait on a missing/faulty disk), sector read/write,
  cache flush, graceful "no disk" detection (status 0xFF / timeout).
  Acceptance: disk detected in QEMU, sector read/write round-trip, no
  disk attached → clean error, shell still works.
- [x] **Task 4.2 — VFS + nxtsFS filesystem + process teardown**
  Details: VFS API (mount/list/read/write/delete) with nxtsFS as the
  first backend. On-disk layout (documented in `docs/FILESYSTEM.md`):
  superblock (magic, version, total sectors, bitmap/directory layout),
  sector bitmap, fixed root directory (name, size, start sector, sector
  count, owner UID, mode bits). Directory entries and file sizes are
  validated on mount and on every operation: magic, version, sizes and
  block ranges must lie inside the disk; names are bounded and
  NUL-terminated inside the entry; a file may never claim blocks
  outside the disk or overlapping the superblock/bitmap/directory.
  Also: free process page directories, page tables, code/stack frames
  on exit (fixes the v0.2.0 leak).
  Acceptance: `ls`, `cat`, `write`, `rm` in the shell; file content
  survives a VM reboot (see Task 4.3).
- [x] **Task 4.3 — Disk image tool + persistence test**
  Details: host tool `tools/mkdisk.py` creates a formatted raw disk
  image (optionally seeded with files); `scripts/run_qemu.sh` attaches
  it; QEMU test boots, writes a file, reboots the guest, boots again,
  reads the file back and checks its content byte-for-byte.
  Acceptance: persistence test passes at 128 MB and 64 MB.
- [x] **Task 4.4 — Adversarial security test (storage) + fixes**
  Attacker view: a malicious or corrupt disk image is untrusted input.
  Cases: bad magic, wrong version, huge file size, start/count beyond
  disk, overlapping system sectors, non-terminated name, zero-length
  and maximum-length names, write larger than free space, write to a
  full disk, read of a non-existent file, directory full, disk absent,
  disk that times out. Expected: every case ends in a clean error and a
  working shell — never a panic, hang, out-of-bounds read/write, or
  memory corruption. Fix, retest, record in `SECURITY_REPORT.md`.

## Phase 5 — Loader, security and sessions (v0.4.0) — DONE

- [x] **Task 5.1 — ELF loader from disk**
  Details: parse ELF32 headers from a file (validate magic, class,
  machine, entry, program-header bounds, section sizes against file
  size), load PT_LOAD segments into a fresh process address space,
  zero BSS, set entry/stack, run as ring-3. Reject malformed ELFs
  without crashing the kernel.
- [x] **Task 5.2 — Users, permissions and process ownership**
  Details: UID/GID, per-process owner, file owner/mode enforcement on
  every VFS operation (owner/other read/write bits, root UID 0 only),
  syscall permission checks (a user process may not read/write files
  it has no right to, may not kill or inspect another user's process),
  kernel-vs-user argument validation on every syscall (already started
  for print; extend to all syscalls).
- [x] **Task 5.3 — Login and session management**
  Details: text login (username, password verified against a stored
  hash — never plaintext — on disk), session per login (owned processes,
  working directory, environment), logout (kills the session's processes,
  frees their frames), session timeout/lock, audit log of logins and
  failed attempts (append-only, on disk).
- [x] **Task 5.4 — Adversarial security test (loader/security/sessions)**
  Attacker view: a malicious ELF, a malicious user, a stolen session.
  Cases: malformed/truncated/oversized ELF, entry outside loaded
  segments, segments overlapping kernel region, BSS overflow, user
  process reading another user's file, writing a read-only file,
  killing another user's process, forging UID via a syscall argument,
  login brute force, empty/wrong/long passwords, session reuse after
  logout, audit-log tampering. Expected: all rejected cleanly, no
  privilege escalation, no kernel fault. Fix, retest, record.

## Phase 6 — Package management (v0.5.0) — DONE

- [x] **Task 6.1 — Package format and manifest**
  Details: package = manifest (name, version, dependencies with version
  ranges, files with SHA-256, entry program, required permissions) +
  files. Manifest is parsed with strict bounds; a malformed manifest
  is rejected whole, never partially installed.
- [x] **Task 6.2 — Installer, dependency resolution, removal**
  Details: install (verify every file hash, resolve dependencies in
  order, refuse on missing/conflicting dependency, atomic-ish install:
  a failed install leaves no half-installed package), list, remove
  (refuse if another package depends on it, unless forced with a
  warning), upgrade (old version removed only after new verifies).
- [x] **Task 6.3 — Verification and trust**
  Details: SHA-256 verification of every file on install and on load
  (a tampered installed file refuses to run); package signing design
  (key handling, signature check) — full signature enforcement lands
  here if a workable key-distribution story exists, otherwise it is
  documented as a known gap, not claimed.
- [x] **Task 6.4 — Adversarial security test (packages)**
  Attacker view: a malicious package. Cases: hash mismatch, manifest
  lying about file sizes, path traversal (`../`, absolute paths) in
  file entries, dependency cycles, dependency on a package that does
  not exist, huge package, duplicate install, removal of a depended-on
  package, tampered file after install. Expected: install refused or
  file refused to run, filesystem outside the package root never
  touched. Fix, retest, record.

## Disk encryption — dedicated phase (v0.6.0) — DONE

- [x] **AES-256-CTR sector encryption, transparent to the FS.**
  Physical header sector ("NXTSENC1", version, iterations, salt,
  key-check), logical sector L at physical L+1, CTR counter
  L*32+block (matching OpenSSL aes-256-ctr IV 0). Unencrypted disks
  boot unchanged, no prompt.
- [x] **Boot passphrase + key derivation.** 10000-round SHA-256
  (salt + passphrase, then hash + salt), key-check via AES-ECB of a
  known plaintext, 3 attempts then halt. Host tool
  tools/mkdisk_enc.py (needs openssl). Shell `aes-test` proves the
  AES implementation against the FIPS 197 vector.
- [x] **Adversarial security test (encryption).** Raw-disk string
  hiding, superblock tamper (mount fails cleanly), header tamper
  (every passphrase fails, halt), package tamper on an encrypted
  disk (run refused by package hash). No exploitable findings.
- [x] **Known limits documented, not hidden.** No passphrase change,
  no recovery, no authenticated encryption, offline brute force
  limited by the work factor only. See docs/ENCRYPTION.md.

## Phase 7 — Graphics and input (v0.7.0) — DONE

- [x] **Task 7.1 — Framebuffer, fonts, mouse**
  VBE 800x600x32 via Multiboot (see docs/GRAPHICS.md for the four
  real bugs found and fixed: header offset 32, info offset 88,
  Multiboot info overwritten by PMM, framebuffer shared with user
  PDs), 8x16 font from host console font (tools/genfont.py),
  framebuffer text console (RAM text buffer, redrawn after GUI),
  PS/2 mouse IRQ12 (packet parsing, clamping, overflow ignore).
- [x] **Task 7.2 — Window manager and widgets**
  In-kernel WM demo: move/resize/minimise/maximise/close, focus,
  z-order, clipping, taskbar, button/label/text-field widgets that
  all work. Shell `gui` (interactive), `guitest`, `wmautotest`,
  `mousetest`, `mouse`. User GUI programs are Phase 8, as packages.
- [x] **Task 7.3 — Adversarial security test (graphics/input)**
  tests/security_test_gui.py PASS: mousetest, guitest (negative/
  huge/off-screen/zero-size windows, count limit 8, corner pixels
  stay background), wmautotest (OK click, drag, Shell exit),
  GUI screendump 800x600 with teal background, title blue, white
  cursor at (400,300). One real bug fixed before release: button
  triggered on release even if dragged off the button. NOT tested
  in QEMU: real mouse movement via monitor/VNC (QEMU did not inject
  packets in this sandbox — see docs/GRAPHICS.md); needs a
  real-device/desktop-QEMU check by the user.
  Original attacker view for 7.3, all covered by the test above:
  window larger than the screen, negative coordinates, huge window
  counts (resource exhaustion), mouse packets out of range, a
  program drawing outside its window, a program trying to read
  another window's pixels. Expected: clipped or rejected,
  compositor survives, no memory corruption. Fix, retest, record.

## Phase 8 — First desktop release (v0.8.0)

- [x] **Task 8.1 — Desktop shell** (v0.8.0, 2026-10-27)
  Details: desktop with icons, taskbar, Start-style launcher, system
  tray, clock, notification centre, quick settings, lock screen and
  graphical login (backed by Phase 5 sessions).
  Delivered: `desktop` shell command, icons, launcher, taskbar
  (CMOS-RTC clock, session name, bell, gear), notifications,
  quick settings, lock screen. Honest limit: boot login remains
  text (Phase 5); the lock screen is the graphical login for
  re-entry. A full graphical boot login is NOT IMPLEMENTED
  (it would require restructuring the boot flow).
- [x] **Task 8.2 — Settings and first GUI applications as packages** (v0.8.0)
  Details: settings app (with search, persistent settings on disk),
  plus at least one functional GUI application, installed as a real
  package via Phase 6 — not an embedded blob.
  Delivered: Settings window (search, idle/mouse/clock/icons,
  persistent settings.txt), Files window, About window, and
  Calculator as calc.nxpkg (GUI syscalls 9–13, user windows).
- [x] **Task 8.3 — Adversarial security test (desktop)** (v0.8.0)
  Attacker view: as Phase 7, plus lock-screen bypass attempts, settings
  that a non-admin user must not change, launcher entries pointing at
  tampered programs. Fix, retest, record.
  Delivered: tests/security_test_desktop.py — non-admin settings
  save denied, wrong lock password fails with lock held,
  malformed GUI syscalls rejected (guibad.elf), tampered
  Calculator refused by the registry hash check. All PASS.
  Also: further lag work (true per-window clipping, taskbar
  skip, 50 Hz throttle, cliptest proving clip == full redraw),
  after the user's desktop-QEMU report that v0.7.4 was still
  "a bit lagish". QEMU/Bochs PASS; see releases/v0.8.0/.

## Phase 9 — Networking (v0.9.0) — DONE

- [x] **Task 9.1 — Network stack**
  Details: virtual Ethernet (e1000/virtio-net as QEMU provides), DHCP,
  IPv4, DNS, TCP/UDP, socket API, network diagnostics, graphical
  network settings.
  Delivered (v0.9.0): e1000 driver (polled), ARP, IPv4, ICMP, UDP,
  DHCP, DNS, single-connection TCP, HTTP/1.0, diagnostics
  (`netinfo`, `netdbg`), `nettest` injection suite. NOT delivered:
  user-mode socket API (kernel + shell only) and graphical network
  settings — see docs/NETWORKING.md.
- [x] **Task 9.2 — TLS and HTTP(S)**
  Details: TLS with proper certificate verification (no accept-all
  mode as a default), HTTP/HTTPS client, guest-side connectivity test
  (DHCP + DNS + verified HTTPS request from inside the guest).
  Delivered (v0.9.0): TLS 1.2 client, one suite
  (TLS_RSA_WITH_AES_128_GCM_SHA256), X.509 chain verification,
  HTTPS client, verified against real OpenSSL servers. Honest
  limits: no CA trust store (TOFU), weak xorshift RNG, no ECDHE /
  resumption / ALPN / revocation / TLS 1.3 — see
  docs/NETWORKING.md.
- [x] **Task 9.3 — Adversarial security test (networking)**
  Attacker view: a hostile network. Cases: malformed packets, oversized
  packets, DNS answers with huge/invalid records, TLS with an invalid/
  expired/self-signed certificate, certificate for the wrong host,
  connection floods, socket API abuse from user mode. Expected: packets
  dropped cleanly, TLS refused, no kernel fault, no privilege gain.
  Fix, retest, record.
  Delivered (v0.9.0): tests/security_test_net.py — flood, malformed
  DNS pointer (fixed: pointer targets now bounds-checked),
  wrong-host / tampered / expired certs refused, plain-HTTP on TLS
  port fails cleanly. Socket-API abuse is not testable yet because
  no user-mode socket API exists in v0.9.0; it must be tested when
  the API lands.

## Phase 10 — Modern desktop and applications (v0.10.0) — DONE

- [x] **Task 10.1 — Desktop polish**
  Delivered: Classic/Dark/Light/High-contrast themes, accent
  colours, solid/gradient/dots wallpapers, low-resource mode,
  large text, shortcut presets, 2 workspaces, snap
  halves/maximise-restore — all persistent in settings.txt
  with invalid values ignored. NOT delivered: separate icon
  themes (one built-in icon set) and tiling layouts beyond
  snap halves; typography is the built-in 8x16 font plus
  2x large-text labels.
- [x] **Task 10.2 — Native application ecosystem**
  Delivered: Files Open integration, Editor, Monitor,
  Network manager, text-only Web browser, BMP Viewer,
  Console package (term.nxpkg), Calculator unchanged.
  Honest scope kept: Web is text-only (no HTML rendering,
  no engine claim), Console cannot run programs.
- [x] **Task 10.3 — Adversarial security test (applications)**
  Delivered: garbage settings rejected at load, non-text
  editor files sanitised, oversize/truncated BMP refused
  before pixel reads, huge web page truncated with a
  marker, no-NIC Network window reports cleanly. One
  real bug found and fixed: HTTP/HTTPS clients failed
  on oversize bodies instead of truncating (see
  releases/v0.10.0/SECURITY_REPORT.md). Calculator
  overflow input was not separately fuzzed beyond the
  existing '7'-key verification; the calculator clamps
  values to ±9999 by design.

## Phase 11 — Hardening, update and verified releases (v1.0.0)

- [ ] **Task 11.1 — Update mechanism**
  Details: system update via signed packages (Phase 6 verification),
  rollback to the previous known-good version on a failed update.
- [ ] **Task 11.2 — Full adversarial review**
  Details: re-run every earlier security test suite against the final
  system, plus a fresh pass over every syscall, every driver, and every
  parser, as a third-party tester would. Fix, retest, record.
- [ ] **Task 11.3 — v1.0.0 verified release**
  Details: source + dist archives, SHA-256, VM guide, known issues,
  remote publishing only with explicit authorisation (private first).

- [x] **v0.3.1 — Bugfix on Phase 4 (user-reported):** GRUB menu now
  generated from `VERSION` at build time (v0.3.0's menu still said
  v0.2.0); kernel prints boot-progress messages so the test programs
  running before the shell are not mistaken for a stuck run. Verified
  at 32 MB (the reported configuration) and 128 MB.

## v0.4.1 — v0.4.0 limits fix (2026-10-26) — DONE
- Stronger password hash (10000 iterations, random salts, breaking change),
  background jobs (`runbg`/`jobs`/`kill`, logout cleanup), persistent
  brute-force lockout (`fails.txt`, root `unlock`), 30-minute idle lock
  with `lock` command, fast time-based startup test (~1.5 s, preemption
  proof kept). QEMU: v0.4.1 test, Phase 5 regression, security 3/3,
  persistent-lockout, base, and 32 MB storage all PASS.
- NOT in v0.4.1: disk encryption (needs a full AES + key-management
  phase; a fake XOR was deliberately not added).

## v0.5.0 — Phase 6 (2026-10-26) — DONE
- NXPKG format, strict manifest parsing, SHA-256 (kernel, verified
  against the "abc" vector and Python hashlib), installer with
  dependency version operators, duplicate/upgrade handling,
  removal protection (+force with warning), load-time tamper check,
  root-only install/remove, root-only registry. Host tool
  tools/mkpkg.py. QEMU: package test, package security test (bad
  hash, lying size, path traversal, absolute path, self-dep,
  cycle, conflicting version, huge package, tamper after install),
  root-only check, Phase 5 regression, security 3/3 — all PASS.
- NOT in v0.5.0: package signing (known gap, see SECURITY.md),
  disk encryption (next, as a dedicated phase per the user's
  approved order: Phase 6 first, then encryption, then graphics).

## v0.6.0 — Disk encryption (2026-10-26) — DONE
- AES-256-CTR sector encryption (docs/ENCRYPTION.md), boot passphrase,
  10000-round key derivation, key-check, 3-attempt halt, host
  tools/mkdisk_enc.py, shell aes-test (FIPS vector PASS). QEMU:
  encryption test (correct/wrong passphrase, login, permissions,
  package install on an encrypted disk), encryption security test
  (raw hiding, superblock/header/package tamper), plus package,
  Phase 5, security 3/3, v0.4.1, base, 32 MB storage regressions —
  all PASS. NOT in v0.6.0: passphrase change, recovery, authenticated
  encryption, package signing. Next: Phase 7 graphics.

## v0.7.0 — Phase 7 graphics and input (2026-10-27) — DONE
- VBE 800x600x32 framebuffer, 8x16 font, framebuffer text console,
  PS/2 mouse, in-kernel window manager (move/resize/minimise/
  maximise/close/focus/z-order/clipping/taskbar, button/label/
  text-field widgets). QEMU: security_test_gui PASS (mousetest,
  guitest, wmautotest, screendump), plus encryption, package,
  Phase 5, base regressions — all PASS. NOT in v0.7.0: desktop
  shell/graphical login (Phase 8), user GUI programs, real mouse
  movement via QEMU/VNC in this sandbox (see docs/GRAPHICS.md).
  Next: Phase 8 desktop (v0.8.0).

## v0.7.1 — Bugfix: GUI in Bochs, idle timeout setting, terminal after session close (2026-10-27)
- GUI: GRUB gfxmode 800x600x32 + gfxpayload=keep, Bochs VBE
  fallback (IO ports + PCI BAR, verified by test pixel, proven in
  QEMU with Multiboot video request removed), `fbinfo` diagnostic.
- Session: idle timeout default 30 -> 120 minutes, new `idle`
  command (`idle` shows, `idle <0-480>` sets, `idle off` disables,
  per-session, resets on reboot). The full 120-minute timeout is
  still not waited out in a test — the setting path is tested.
- Terminal after session close: keyboard buffer is flushed on
  re-login and on lock (not on first boot login, which must keep
  buffered keys — flushing there broke base/encryption tests and
  was fixed), text console is redrawn after an idle lock, and a
  logout -> new prompt -> `mem` cycle is tested in
  tests/qemu_test_v071.py. Bochs itself is NOT tested in this
  sandbox (Bochs is not installed here) — user must confirm
  `gui` starts in Bochs on v0.7.1.
- QEMU PASS: v071 test, security_test_gui, encryption, package,
  base. One real regression caught and fixed during testing: an
  unconditional keyboard flush on login discarded buffered
  login/help keys on first boot.

## v0.7.2 — Bugfix: GUI in Bochs proven, keyboard polling (2026-10-27)
- Bochs 2.7 installed and tested in the sandbox (Xvfb/SDL2 +
  xdotool, serial log as truth). v0.7.1 failed in Bochs stdvga
  with "no PCI display BAR found" (Bochs VGA is ISA, not PCI).
  v0.7.2 adds fixed LFB 0xE0000000 as second VBE fallback step
  (ID check first, test-pixel verification after mapping).
  Bochs stdvga result: framebuffer 800x600 phys 0xE0000000,
  guitest PASS, keys after prompt work. Cirrus/isavga proven
  unfixable in kernel (no Bochs ports, GRUB BIOS path gives
  bpp=1 type=0 in Bochs+SeaBIOS) — shipped config/vm/bochsrc.txt
  (vbe + stdvga) is the supported Bochs config, included in dist.
- Keyboard: shell/login/lock/WM now poll the controller every
  timer tick in addition to IRQ1 (status bit 5 guards mouse
  data). Bochs keyboard IRQ itself works in sandbox tests, so
  the user's "keys only if pressed during boot" could not be
  reproduced — polling removes the IRQ single point of failure,
  and focus (click Bochs window, then type) is the remaining
  check on the user's machine.
- Boot log now prints the Multiboot failure reason with
  bpp/type, so a future "no framebuffer" report is diagnosable.
- QEMU PASS: v071 test, GUI security, base. GRUB `insmod vbe`
  tested and NOT adopted (it makes GRUB set a broken 1bpp mode
  in Bochs; kernel fallback is the reliable path).

## v0.7.3 — Bugfix: PS/2 controller init, keyboard deadlock fixed (2026-10-27)
- User video (Android Bochs, VGA Bochs VBE (PCI) + Slot1 pcivga):
  framebuffer WAS working (800x600, pitch 3200, phys 0xC0000000,
  Multiboot) — the failure in the video was keyboard input: the
  Android soft keyboard opened, keys were tapped, nothing appeared
  at the prompt, so `gui` could never be run. Root cause in kernel:
  keyboard_init() never touched the PS/2 controller, so a byte
  left in its 1-byte output buffer by GRUB/BIOS stayed forever
  (PIC reinitialisation forgot its IRQ, full buffer accepts no
  new bytes, raises no new IRQ) — keyboard dead from first prompt,
  on any emulator, until the buffer is read. Mashing Enter during
  loading sometimes cleared it. Fix: proper controller init
  (disable ports, flush, config byte IRQ1+IRQ12+translation,
  re-enable kbd port, flush, scancode set 2), polling now drains
  mouse bytes too, mouse packet resync (test_set resets pkt_idx,
  bit-3-clear first bytes discarded — found by mousetest failing
  after the polling change), shell diagnostic line + `kbdstat`.
- QEMU PASS: v071, GUI security, base, encryption, package,
  GRUB-phase key test. Bochs desktop PASS: kbdstat, mem, guitest.
  QEMU does NOT reproduce the deadlock (GRUB consumes the key),
  so QEMU tests prove no regression, not the Bochs fix.
- NOT tested: Android Bochs on a real phone (no Android device
  in sandbox). The shell diagnostic line tells the user which
  case applies: drained > 0 = lodged byte fixed by this build;
  drained = 0 + keys still dead = no bytes reach the controller
  (app drops system-IME input before Bochs) — then use the app's
  built-in virtual PC keyboard or a physical keyboard, or QEMU.

## v0.7.4 — Bugfix: GUI lag fixed (2026-10-27)
- User: "gui is working but lagging like hell". Two real
  causes in the WM loop: (1) mouse movement with the button
  up had NO branch, so the cursor only moved on the 0.5s
  periodic redraw (2 fps feel); (2) every other move/drag/
  resize/key/periodic did a full 480,000-pixel redraw at up
  to 100 Hz. Fix: cursor save/restore (~442 pixels per move,
  immediate, button up or down), dirty-rect redraw (background
  clipped, non-overlapping windows skipped, overlapping drawn
  in z-order), throttling to ~30 Hz (drag/key/periodic merge
  into a pending dirty rect), fb fill/text/char row-pointer
  optimisations, new `cursortest` command, desktop bochsrc
  update_freq 5 -> 30. Rendering pixel-identical: QEMU
  screendump teal 215200 / blue 5798 / white 9671, same as
  v0.7.0-0.7.3. QEMU PASS: v071, GUI security (rerun after
  a "ggui" sendkey flake), base, cursortest. Bochs desktop
  PASS: kbdstat, mem, guitest.
- NOT measured: phone fps on Android Bochs (no Android
  device in sandbox); improvement is argued from pixel
  counts, not a phone fps number.

Current release: **v0.10.0 = Phase 10 modern desktop and
applications**. Next: **Phase 11 hardening, update and verified
releases (v1.0.0)**.
