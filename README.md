# nxtsOS

An original, ultra-lightweight desktop operating system, built from scratch.
Not a Linux distribution, not a fork, not a re-themed desktop: nxtsOS boots
its own kernel.

## Status — v1.0.0 (Phase 11: hardening, update, verified release)

What actually works in v1.0.0, verified by booting the real ISO in QEMU and in Bochs 2.7:

- Everything from v0.10.0, plus RSA-2048 package signatures:
  every install now requires a valid signature over the
  manifest (vendor key compiled into the kernel, or a
  root-owned keyring in `pubkeys.txt`); legacy unsigned
  packages and wrong-key or tampered packages are
  refused, with the tamper case proven by a byte-flip
  test (see docs/PACKAGES.md). The signing key itself
  never ships in any archive; if it is lost, old
  signed packages become uninstallable and everything
  must be re-signed.
- System updates with rollback: `sysupdate <bundle>`
  verifies every package, dependency, reverse
  dependency, file conflict, and dependency cycle
  BEFORE writing anything, snapshots the files and
  registry it will touch, then commits in dependency
  order; any failure restores the snapshot, and
  `sysrollback` returns to the previous version
  (one generation only).
- A remote package repository over plain HTTP, by
  design: the kernel TLS client has no public CA
  trust store, so signatures — not transport — carry
  authenticity, like apt's signed Release files.
  `pkg repo`, `pkg update` (signed index, anti-
  rollback against the stored version, stored index
  re-verified on every use), `pkg fetch`, and
  `pkg install <name>` from the repository. The
  public hosting publish is still pending the user's
  explicit approval; the mechanism itself is verified
  against a local repository.
- A full adversarial review (Phase 11.2): every
  earlier security suite re-run green, plus a fresh
  pass over syscalls, drivers, and parsers. Two real
  bugs found and fixed on the way: the TCP stack
  accepted stale segments from previous connections
  (no destination-port check, any bare FIN counted
  as a close), which intermittently truncated a
  download; and two integer wraparounds (repository
  index version, repository URL port) that now refuse
  instead of wrapping. See
  releases/v1.0.0/SECURITY_REPORT.md.
- Honest limits, unchanged from before and still
  stated plainly: no graphical boot login, no UEFI,
  no installer, no CA trust store (TOFU roots only),
  no cryptographic RNG (timer-seeded xorshift),
  no user-mode socket API, no package revocation
  list, one rollback generation, 32-file / 16 MiB
  disk caps, and real mouse movement still
  untested in QEMU (scripted injection only).
  VirtualBox and real hardware are NOT TESTED.

## Status — v0.10.0 (Phase 10: modern desktop and applications)

What actually works in v0.10.0, verified by booting the real ISO in QEMU and in Bochs 2.7:

- Everything from v0.9.0, plus a polished desktop: four
  themes (Classic/Dark/Light/High-contrast), accent
  colours, three wallpapers, low-resource mode, large
  text, configurable shortcut presets, two workspaces,
  and window snapping (`[` left half, `]` right half,
  `\` maximise/restore) — all persistent in
  `settings.txt`, with out-of-range values ignored, not
  fatal (see docs/DESKTOP.md).
- Built-in applications in the Start launcher's second
  column: a text Editor (8192-byte cap, sanitises
  non-text bytes on load), a system Monitor, a Network
  manager (DHCP/ping buttons, clean no-device report),
  a text-only Web browser (HTTP/HTTPS, 8192-byte body
  buffer with reported truncation), and a BMP Viewer
  (24-bit uncompressed, max 128×128, 128 KiB) — plus
  Files → Open integration (.txt → Editor, .bmp →
  Viewer). Calculator is unchanged; a new Console
  package (`term.nxpkg`) provides a local echo console
  that plainly cannot run programs.
- A real bug fixed on the way: the HTTP/HTTPS clients
  used to fail outright on any body bigger than the
  buffer. They now truncate-and-drain and report it
  (`web: truncated at 8192`, shell `http: N bytes
  (truncated)`). Verified against a host server with a
  20000-byte page.
- Adversarial application testing passed: garbage
  settings (theme=99, wallpaper=5, non-numeric values)
  ignored at load, control/high bytes sanitised in the
  editor, an oversize BMP refused before any pixel
  read, empty files opening as 0 bytes.

## Status — v0.9.0 (Phase 9: networking + TLS 1.2 client)

What actually works in v0.9.0, verified by booting the real ISO in QEMU and in Bochs 2.7:

- Everything from v0.8.0, plus a real network stack: e1000
  driver (polled), ARP, IPv4, ICMP, UDP, DHCP, DNS, a
  single-connection TCP client, and an HTTP/1.0 client.
  Shell commands: `netinfo`, `netdbg`, `dhcp`,
  `ping <ip>`, `dns <name>`, `dnsset <ip>`, `http`,
  `https`, `nettest`. Try it under QEMU slirp:
  `dhcp`, then `ping 10.0.2.2`, then `http`/`https`
  against a host server (see docs/NETWORKING.md).
- A TLS 1.2 client with real X.509 verification (one
  suite: TLS_RSA_WITH_AES_128_GCM_SHA256, RSA key
  exchange, AES-128-GCM records, SAN hostname matching,
  RSA signature verification via a from-scratch bignum).
  Verified against real OpenSSL servers. Honest limits,
  stated plainly: NO CA trust store ships (chains must
  end in a self-signed root — TOFU, not CA
  authentication), and randomness is a timer-seeded
  xorshift, not a cryptographic RNG. Do not use it for
  real secrets yet; see docs/NETWORKING.md.
- Adversarial network testing passed: a 400-frame
  flood does not wedge the stack, malformed DNS
  pointers are rejected, and wrong-host, tampered, and
  expired TLS certificates are all refused (while plain
  HTTP on a TLS port fails as a handshake error, not
  misreported as a certificate refusal).

What actually works in v0.8.0, verified by booting the real ISO in QEMU and in Bochs 2.7:

- Everything from v0.7.4, plus a real desktop shell: run `desktop`
  at the shell prompt for icons (Settings, Files, Calculator,
  About, Terminal, Lock), a Start-style launcher, a taskbar with
  a CMOS-RTC clock, session name, notification bell and quick
  settings, a notification centre, and a lock screen backed by
  Phase 5 sessions (wrong passwords fail and the lock stays up;
  in setup mode with no users file, Enter unlocks).
- Settings window with search, and persistent `settings.txt` on
  disk (idle timeout, mouse speed, clock format, desktop icons);
  a non-root user cannot save over a root-owned settings file —
  the save is refused with "Save failed: permission denied".
- GUI syscalls (9–13: open/rect/text/event/close) for user
  windows, and the first GUI application as a real package:
  Calculator (`calc.nxpkg`, install with `pkg install
  calc.nxpkg`, then open it from the desktop Calc icon or the
  launcher). Calculator has a fixed keypad layout, + − × ÷ with
  division by repeated subtraction, and click confirmation on
  mouse release over the same key.
- Further lag work on top of v0.7.4: true per-window clipping
  (a dirty redraw now draws only the dirty rect of each
  window, and skips the taskbar when the dirty rect does not
  reach it), pending-redraw throttle 30 Hz → 50 Hz, and a
  `cliptest` command proving a clipped redraw produces exactly
  the same pixels as a full redraw. `gui` remains the Phase 7
  demo, unchanged; `desktop` is the new shell.

- Multiboot boot path (GRUB), 32-bit x86 kernel written from scratch.
  The GRUB menu version is now generated from the `VERSION` file at
  build time, so it cannot go stale again (v0.3.0's menu still said
  v0.2.0 — fixed in v0.3.1).
- VGA text console + serial (COM1) diagnostic log
- Multiboot memory-map parsing and a bitmap physical-memory manager
- IDT, remapped PIC, PIT timer ticks, PS/2 keyboard input (buffered:
  keys typed before the shell appears are not lost)
- Paging, ring-3 user processes, int 0x80 syscalls, round-robin
  scheduler with yield + 100 ms timer preemption, process teardown
  (exited processes' frames are freed)
- ATA PIO disk driver, VFS + nxtsFS filesystem (persistent files that
  survive a guest reboot), host disk tool `tools/mkdisk.py`
- A tiny in-kernel shell: `help`, `mem`, `ticks`, `clear`, `reboot`,
  `fs`, `ls`, `cat <file>`, `write <file> <text>`, `rm <file>`,
  `run <file>`, `runbg <file>`, `jobs`, `kill <pid>`, `lock`,
  `unlock <user>`, `whoami`, `logout`
- ELF loader from disk, users/permissions, text login with sessions
  and an audit log (see `docs/SECURITY.md` for the honest limits)
- Graphics + window manager: see `docs/GRAPHICS.md`. 800x600x32
  framebuffer, 8x16 font, framebuffer text console, PS/2 mouse,
  in-kernel window manager (`gui` command: move/resize/minimise/
  maximise/close/focus/taskbar, button/label/text-field widgets).
  v0.7.2 adds a Bochs VBE fallback so `gui` starts even when GRUB
  sets no graphics mode (proven in QEMU with the Multiboot video
  request removed, and in Bochs 2.7 itself: framebuffer 800x600
  at 0xE0000000, `guitest PASS`), plus `fbinfo` to diagnose a
  missing framebuffer. For Bochs, use the shipped `bochsrc.txt`
  (`vga: extension=vbe`, stdvga VGABIOS) — Bochs' default isavga
  and cirrus configs cannot run the GUI (proven, see
  docs/GRAPHICS.md). Real mouse movement via QEMU/VNC was NOT
  testable in the build sandbox (QEMU did not inject mouse
  packets) — test `gui` with a real mouse on your machine;
  driver + WM click/drag logic are proven via
  `mousetest`/`wmautotest`.
- Session: idle timeout is now configurable with `idle`
  (`idle 240` for 4 hours, `idle off` to never lock, default 120
  minutes, per-session). Terminal after logout/lock is fixed:
  stale keys are flushed on re-login and the console is redrawn
  after a lock.
- Disk encryption (AES-256-CTR, boot passphrase): see
  `docs/ENCRYPTION.md`. Encrypted disks are created on the host with
  `tools/mkdisk_enc.py` (needs openssl) and unlock at boot with a
  passphrase (3 attempts, then halt). Unencrypted disks boot
  unchanged. No passphrase change, no recovery, no authenticated
  encryption — see the limits in `docs/ENCRYPTION.md`.
- Package management (`pkg list/install/remove`, `sha256`): see
  `docs/PACKAGES.md`. Packages are verified by SHA-256 on install
  and on load, with dependency resolution, duplicate/upgrade handling,
  and removal protection. Signing is NOT implemented — hashes do not
  authenticate the author (see `docs/SECURITY.md`).
- Earlier fixes carried over: 10000-iteration password hash
  (regenerate v0.4.0 users.txt), background jobs, persistent
  brute-force lockout, 30-minute idle lock, fast startup test.
  Disk encryption is NOT in v0.5.0 — a real AES + key-management
  implementation is a full phase, and a fake XOR one was not added.
- Kernel panic path for unhandled exceptions (prints registers, halts)

What is NOT in v0.7.0 — do not mistake this release for it:

- No graphical desktop, window manager, or GUI applications yet
- No graphics, desktop, or networking yet
- No networking yet
- No installer

Those are Phases 5–11 in `docs/ROADMAP.md`. Each phase lands only when it
boots and is tested in QEMU, with an adversarial security test, before release.

## Quick start (QEMU)

```sh
./scripts/build.sh
python3 tools/mkdisk.py build/nxtsOS-disk.img --add hello.txt:/path/to/hello.txt
./scripts/run_qemu.sh          # 128 MB RAM, VGA + serial log to logs/serial.log
./scripts/run_qemu.sh 32       # 32 MB RAM also works (tested)
```

After boot, two built-in test programs run first and print `P1 iter` /
`P2 iter` lines — those are the startup programs, not a stuck test run.
Wait a few seconds and the `nxts> ` prompt appears; type `help` there.
Press Ctrl-Alt-Q in the QEMU window (or close it) to stop the VM.

Full instructions, tested configuration, and known issues:
`docs/VM_GUIDE.md`, `docs/BUILD_AND_TEST.md`, `releases/v0.3.0/TEST_REPORT.md`.

**v0.1.0 warning:** v0.1.0 rebooted in a loop in QEMU (wrong GDT selectors
— see `releases/v0.1.1/TEST_REPORT.md`). Do not use v0.1.0; use v0.8.0.
QEMU tests: `tests/security_test_gui.py`, `tests/qemu_test_enc.py`, `tests/security_test_enc.py`, plus package, Phase 5, base, and storage regressions — all PASS.

## Project layout

- `boot/` — Multiboot entry (GAS assembly), linker script
- `kernel/` — kernel main, console, shell, panic, processes, syscalls
- `drivers/` — VGA, serial, PIC, PIT, keyboard, ATA disk
- `mm/` — physical memory manager, paging
- `fs/` — VFS + nxtsFS filesystem
- `net/`, `graphics/`, `window_manager/`, `desktop/`,
  `system_services/`, `applications/`, `sdk/` — placeholders for later phases,
  each with a `STATUS.md` stating what is (not) implemented
- `tests/` — host-side checks + QEMU boot/persistence/security test scripts
- `scripts/` — build, run, and packaging scripts
- `releases/v0.3.0/` — manifest, checksums, test + security reports
- `archives/` — versioned source and distribution archives

## Build requirements

Host: Linux x86_64, `gcc` (with `-m32` freestanding support), GNU `as`/`ld`,
`grub-mkrescue` + `xorriso` (for the ISO), `qemu-system-x86_64` (for testing),
`python3`, `git`, `tar`, `zip`, `sha256sum`.

No cross-compiler is required: the kernel is built freestanding
with the host GCC (`-ffreestanding -nostdlib -m32`).

## Licence

MIT — see `LICENSE`. Third-party tools used (GRUB, QEMU, GCC) are not
nxtsOS code and are not claimed as such.
