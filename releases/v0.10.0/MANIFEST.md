# nxtsOS v0.10.0 — Release Manifest (Phase 10: modern desktop and applications)

- Version: 0.10.0 (Phase 10, whole phase in one release, per the user's choice)
- Kernel binary: `build/nxtsOS.bin` (173,264 bytes)
- Bootable image: `build/nxtsOS.iso` (5,296,128 bytes, El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh` (also builds `build/calc.nxpkg` and `build/term.nxpkg`)
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.10.0` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.10.0-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.10.0-dist.zip`
  (includes the ISO, `calc.nxpkg`, `term.nxpkg`, `bochsrc.txt`, `mkdisk.py`,
  VM_GUIDE, BUILD_AND_TEST, MANIFEST, TEST_REPORT,
  SECURITY_REPORT, README, VERSION)
- Checksums: `releases/v0.10.0/SHA256SUMS`

## What is new in v0.10.0

User request (2026-10-27, after v0.9.0 delivered): "continue" —
interpreted as proceeding with Phase 10, the next phase in the
core-first roadmap. This release is all three Phase 10 tasks
(10.1 polish, 10.2 apps, 10.3 adversarial test). Full detail in
docs/DESKTOP.md.

### 10.1 — Desktop polish (kernel/wm.c)

- Themes: Classic (pixel-identical to v0.8.0/v0.9.0), Dark,
  Light, High-contrast. Theme recolours desktop background,
  taskbar, panels and panel text; window client areas stay
  light grey with black text in every theme (deliberate:
  keeps all content readable without refactoring every
  content painter).
- Accent colours: Blue (default, the old focused-title
  colour), Gold, Green, Red — applied to the focused
  window's title bar.
- Wallpapers: Solid, Gradient (theme background lerped
  toward black in 4-pixel bands, u32 math only), Dots
  (accent dots every 48 pixels).
- Low-resource mode: forces solid wallpaper, raises the
  pending-redraw throttle from 2 ticks to 5.
- Large text: desktop icon labels drawn 2× via a new
  2× text painter (font8x16, foreground pixels only).
- Shortcut presets: {Lock L, Workspace W}, {Lock K,
  Workspace J}, {Lock X, Workspace Z}, matched
  case-insensitively, firing only when no text input has
  focus (lock screen, Settings search, Editor, Web field,
  focused user windows take priority, in that order).
- Workspaces: 2; the taskbar WS button toggles. Windows
  belong to their opening workspace and are hidden from
  redraw, taskbar buttons, on-window detection and click
  loops on the other workspace.
- Window snapping: `[` left half, `]` right half, `\`
  maximise/restore toggle on the topmost non-minimised
  window of the current workspace; first snap saves the
  geometry for restore.
- Settings Appearance page: page 1 is the original four
  rows at unchanged positions (autotest safety); page 2
  rows cycle Theme/Accent/Wallpaper/Low-resource/Large
  text/Shortcuts with serial markers. Save buffer grown
  128 → 256 bytes; new keys theme/accent/wallpaper/
  lowres/bigtext/shortcuts. Load validation: out-of-range
  values ignored with a marker, non-numeric skipped.

### 10.2 — Native application ecosystem (kernel/wm.c, userland/term.c)

- New window types: W_NETWORK, W_WEB, W_EDITOR,
  W_MONITOR, W_VIEWER. Launcher column 2 (panel widened
  200 → 400 pixels, column 1 entries/coords unchanged):
  Editor, Monitor, Network, Web, Viewer, Console.
- Network window: MAC, DHCP state, IP/mask/gateway/DNS,
  RX/TX counters, [Run DHCP] and [Ping gateway] buttons;
  with no NIC it prints `network: no device` on open.
- Web window: one address field, `host[:port][/path]`
  with optional http(s):// prefix, Fetch button, body
  scrolled by Up/Down. Text-only; body buffer 8192
  bytes with truncation reported (see 10.3 fix).
- Editor window: filename field, cursor, scroll, `[`/`]`
  cursor movement, insert/backspace via memmove, Save
  (mode 0644) and Open buttons. Load cap 8192 bytes:
  missing/oversize refused with a marker; bytes <32
  (except newline) and >=127 sanitised to `?` with a
  marker.
- Monitor window: uptime, memory total/free, window
  count, net RX/TX/drops/IP, refreshed every 100 ticks.
- Viewer window: BMP only — 24-bit uncompressed,
  max 128×128, file max 128 KiB. Every header/data
  bound checked before any pixel read; refusals carry a
  specific reason. Pixels drawn 1:1, BGR → RGB.
- Files Open: .txt → Editor load+open, .bmp → Viewer
  load+open, anything else → notification + marker
  (`files: no viewer for <name>`).
- Terminal console package: `userland/term.c` (GUI
  console, 480×320, 15-line scrollback, help/echo/
  clear/about/exit) built as `build/term.nxpkg` by
  build.sh and copied into the dist by package.sh.
  It states plainly that it cannot run programs.
  Package rule applies: never pre-seed a plain
  term.elf on a disk that also carries term.nxpkg.

### 10.3 — Adversarial application test (tests/, kernel/wm.c)

- New scripted desktop modes (30 ticks/step):
  mode 4 desktop10test (polish), mode 5 desktopappstest
  (apps), mode 6 desktop10sec (security), mode 7
  desktopwebtest (slirp web), mode 8 desktopnonic
  (no-NIC).
- New python harnesses: tests/qemu_test_desktop10.py,
  tests/qemu_test_desktop_apps.py (+setup),
  tests/security_test_desktop10.py (+setup),
  tests/qemu_test_desktop_web.py,
  tests/qemu_test_desktop_nonic.py.
- One real bug found by the web test and fixed (see
  SECURITY_REPORT.md): HTTP/HTTPS clients failed on
  oversize bodies instead of truncating.
- The web fetch handler previously printed a marker
  only on truncation; it now also prints
  `web: fetched N bytes`, `web: fetch failed`, and
  `web: certificate refused` so failures are diagnosable
  instead of silent.

## NOT implemented in v0.10.0

Graphical boot login (unchanged), package signing
(unchanged), user-mode socket API (unchanged),
separate icon themes (one built-in set), tiling
layouts beyond snap halves/maximise, HTML rendering
or any browser engine in the Web window, Console
running programs, editor files over 8192 bytes,
viewer images over 128×128 / 24-bit BMP / 128 KiB.

## NOT tested

Android Bochs (no Android device in sandbox),
VirtualBox / real hardware, real mouse movement with
a real pointer (scripted injection only), phone FPS,
Calculator arithmetic beyond the '7' key, slirp DNS
in this sandbox (environment UDP block, proven —
unchanged from v0.9.0), DNS-name (non-IP) HTTPS
end-to-end (unchanged from v0.9.0).
