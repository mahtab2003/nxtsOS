# nxtsOS v0.8.0 — Release Manifest (Phase 8: first desktop shell)

- Version: 0.8.0 (Phase 8, whole phase in one release, per the user's choice)
- Kernel binary: `build/nxtsOS.bin`
- Bootable image: `build/nxtsOS.iso` (El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh` (also builds `build/calc.nxpkg`)
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.8.0` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.8.0-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.8.0-dist.zip`
  (includes the ISO, `calc.nxpkg`, `bochsrc.txt`, `mkdisk.py`,
  VM_GUIDE, BUILD_AND_TEST, MANIFEST, TEST_REPORT,
  SECURITY_REPORT, README, VERSION)
- Checksums: `releases/v0.8.0/SHA256SUMS`

## What is new in v0.8.0

User request (2026-10-27, desktop QEMU): v0.7.4's GUI was "good
still a bit lagish — fix it and immediately start next phase
then provide me a new file". This is that single release: a
further lag fix plus Phase 8, not two separate releases.

### Lag fix (on top of v0.7.4)

- True per-window clipping (`kernel/wm.c`): `draw_window_clip`
  draws each window clipped to the dirty rect (fills via
  `fb_fill_rect_clip`, text via `draw_text2`, which intersects
  the window clip with the dirty rect). User windows (W_USER)
  draw title/border only and return before the client-area
  fill — the client area belongs to the app, and the WM must
  never fill it, or every desktop redraw would erase the app.
- Taskbar skip: `wm_redraw_rect` no longer draws the taskbar
  when the dirty rect does not overlap the taskbar strip
  (v0.7.4 drew it always).
- Throttle 3 ticks → 2 ticks (~30 Hz → ~50 Hz) for the
  pending dirty-redraw flush (drag/resize/key). The clip
  drawing cuts drag cost roughly 3x, so the higher rate is
  affordable; periodic System-ticks redraw stays at 50 ticks.
- New `cliptest` command: minimises the System window first
  (its ticks text changes every 10 ms and would make any two
  checksums differ — a false FAIL), parks the cursor at
  (10,10), moves Welcome (40,40)→(140,90), redraws only the
  union rect, checksums, then full-redraws and checksums
  again. Equality proves the clip refactor is correct.
- Honest residual limit: QEMU's PS/2 mouse is relative, so
  the host pointer and guest cursor are both visible unless
  the user grabs the mouse in QEMU (Ctrl+Alt+G), and QEMU's
  display refresh means the guest cursor trails the host
  pointer by roughly 30–50 ms regardless. The kernel cannot
  fix host-side latency; a USB tablet (absolute mouse) is
  impossible without a USB driver, which nxtsOS does not
  have yet. See docs/VM_GUIDE.md.

### Phase 8.1 — Desktop shell (`desktop` command)

- Desktop background, icons down the left (48x48 boxes, 84 px
  spacing): Settings, Files, Calculator, About, Terminal,
  Lock. Single click opens (documented choice).
- Taskbar: Start button (60 px), window buttons, tray from
  the right: session name, CMOS-RTC clock (24h/12h, read
  from ports 0x70/0x71 with BCD and 12h conversion), bell
  `B:<count>`, gear `G`. Clock minute changes redraw only
  the taskbar strip.
- Start launcher menu (200x180 above the taskbar): Settings,
  Files, Calculator, About, Terminal, Lock, Exit desktop.
- Quick settings panel (260x140): Idle / Mouse / Clock /
  Icons value buttons + Save.
- Notification centre (300x200, list + Clear): max 8
  notifications, 64 chars each, also logged to serial as
  `Desktop notification: <msg>`.
- Lock screen: full-screen dark panel with clock, user name,
  password field (`*` per char), Unlock button at
  (210,350,100,24). Unlock uses Phase 5 `users_check` for
  the session user; in setup mode (no users file) any Enter
  unlocks. Three failed attempts halt the system, same as
  text login lockout. Desktop idle: the loop tracks last
  mouse/key activity and shows the lock when the session
  idle timeout (shell `idle` setting, default 120 min)
  expires.
- Background GUI apps: the desktop loop calls
  `proc_bg_tick()` every iteration, so background jobs run
  while the desktop waits, and user windows whose program
  exited are closed.
- `gui` is unchanged (Phase 7 demo). Run `desktop` for the
  new shell; existing `gui` tests are untouched.

### Phase 8.2 — Settings, Files, About, Calculator

- Settings window (480x320 at 160,80): search field at the
  top (click to focus, typing filters rows by
  case-insensitive substring), rows for Idle timeout (cycle
  0/30/60/120/240), Mouse speed (Slow/Normal/Fast, applied
  in the mouse driver as a 0/1/2 scale), Clock format
  (24h/12h), Desktop icons (On/Off). Values apply
  immediately on click; Save persists `settings.txt`
  (lines `idle=N`, `mouse=N`, `clock=N`, `icons=N`) via
  `fs_write_as` with the session uid and mode 0600, loaded
  at desktop start (bad/missing lines ignored).
- Files window (480x320): list via the new `fs_enum_as`
  API (names/sizes for valid, readable entries, directory
  order, max 16 shown); click a row to select and preview
  files up to 255 bytes, larger files show a message to use
  `cat` in the shell. The list is loaded once at open and
  is stale until reopened (documented).
- About window (360x240): `nxtsOS v0.8.0`, "Original kernel,
  Multiboot, 32-bit x86.", "Not a Linux distribution or
  fork.", memory total, desktop features. The version
  literal is guarded by a grep check in `scripts/build.sh`,
  same anti-stale pattern as the kernel banner.
- GUI syscalls 9–13 (SYS_GUI_OPEN/RECT/TEXT/EVENT/CLOSE):
  user-pointer validation reuses the Phase 5 rules, with a
  separate `valid_user_text` (printable ASCII, `/` allowed
  because GUI text is never a file path). GUI_OPEN rejects
  w/h <0 or >4096 and fails cleanly when the desktop is not
  running; one window per pid; event queue 16 per window,
  events dropped when full (documented); EXPOSE queued on
  open, on drag/resize/maximise, and on close (CLOSE).
  User-window drag ghosting limit: the WM never fills a
  user client area, so on a move the overlapping region
  shows shifted old content for ~1 frame until the app
  redraws on EXPOSE (documented, accepted).
- Calculator (`userland/calc.c`, package `calc.nxpkg`,
  built by `scripts/build.sh`): no libc, int 0x80 only, no
  division/modulo (repeated subtraction, 4-digit clamp so
  the subtraction-based itoa stays exact). Fixed 4x4
  keypad (+ − × ÷, =, C), display, click confirmation on
  mouse release over the same key (mirroring the desktop
  button rule), keyboard input, redraw on EXPOSE. Fixed
  layout: resizing larger leaves extra space. Install with
  `pkg install calc.nxpkg` (as root), then open from the
  desktop Calc icon or Start → Calculator. The launcher
  starts it via `proc_bg_start`; if the package is not
  installed, it notifies instead of silently doing nothing.

### Phase 8.3 — Adversarial security test

See SECURITY_REPORT.md. Summary: non-admin settings save
denied, wrong lock password fails with the lock held,
malformed GUI syscalls rejected, tampered Calculator
refused by the registry hash check. All PASS, no
exploitable finding left open in this release.

## NOT IMPLEMENTED in v0.8.0

- Graphical boot login (boot login remains text, Phase 5;
  the lock screen is the graphical login for re-entry).
- GUI applications beyond Calculator; networking; installer;
  UEFI; package signing; production memory-hard password
  KDF; disk passphrase change; recovery key; authenticated
  encryption; mouse wheel.
- Files list refresh without reopening; event queue larger
  than 16; Calculator resize-adaptive layout.
- Real mouse movement/clicking (same limit as Phase 7:
  verified via scripted mouse_test_set injection, not a
  real pointer, in QEMU and Bochs).
- Scripted keyboard-into-text-field typing (Settings search
  typing is implemented but only exercised via the search
  filter logic, not a scripted typing test).
- Android Bochs on a real phone (no Android device in
  sandbox); phone FPS never measured.
